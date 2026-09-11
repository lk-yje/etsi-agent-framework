"""Transport 错误分类 + 暂停/继续/停止行为测试。"""

import asyncio
import json
from pathlib import Path

import pytest

from framework.agent_runner import AgentConfig, AgentRunner
from framework.retry import RetryConfig, RetryPolicy
from framework.transport_errors import (
    TransportErrorCategory,
    classify_exception,
    is_pausable,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ═══════════════════════════ 错误分类 ═══════════════════════════

class _FakeAPIError(Exception):
    def __init__(self, status_code=None):
        self.status_code = status_code


class _NamedError(Exception):
    pass


@pytest.mark.parametrize("exc,expected", [
    (_FakeAPIError(429), TransportErrorCategory.RATE_LIMITED),
    (_FakeAPIError(529), TransportErrorCategory.OVERLOADED),
    (_FakeAPIError(500), TransportErrorCategory.SERVER_ERROR),
    (_FakeAPIError(503), TransportErrorCategory.SERVER_ERROR),
    (_FakeAPIError(401), TransportErrorCategory.AUTH),
    (_FakeAPIError(403), TransportErrorCategory.AUTH),
    (_FakeAPIError(400), TransportErrorCategory.INVALID_REQUEST),
    (_FakeAPIError(404), TransportErrorCategory.NOT_FOUND),
    (TimeoutError("boom"), TransportErrorCategory.TIMEOUT),
    (ConnectionResetError("reset"), TransportErrorCategory.CONNECTION),
    (OSError("dns fail"), TransportErrorCategory.CONNECTION),
    (RuntimeError("???"), TransportErrorCategory.UNKNOWN),
])
def test_classify_exception(exc, expected):
    assert classify_exception(exc) is expected


def test_classify_by_sdk_class_name():
    """不 import SDK 也能按 anthropic 异常类名分类。"""
    for name, expected in [
        ("RateLimitError", TransportErrorCategory.RATE_LIMITED),
        ("APITimeoutError", TransportErrorCategory.TIMEOUT),
        ("APIConnectionError", TransportErrorCategory.CONNECTION),
        ("AuthenticationError", TransportErrorCategory.AUTH),
        ("BadRequestError", TransportErrorCategory.INVALID_REQUEST),
        ("InternalServerError", TransportErrorCategory.SERVER_ERROR),
    ]:
        exc = type(name, (Exception,), {})("x")
        assert classify_exception(exc) is expected, name


def test_pausable_categories_exclude_request_errors():
    """运输层可暂停；请求层（401/400/404）重试无意义，不暂停。"""
    assert is_pausable(_FakeAPIError(429))
    assert is_pausable(_FakeAPIError(529))
    assert is_pausable(ConnectionResetError())
    assert is_pausable(TimeoutError())
    assert not is_pausable(_FakeAPIError(401))
    assert not is_pausable(_FakeAPIError(400))
    assert not is_pausable(_FakeAPIError(404))
    assert not is_pausable(RuntimeError("logic bug"))


# ═══════════════════════════ 暂停/继续/停止 ═══════════════════════════

class _FlakyAPI:
    """messages.create 前 N 次抛运输错误，之后成功。"""

    def __init__(self, fail_times, error_factory):
        self.fail_times = fail_times
        self.error_factory = error_factory
        self.calls = 0

        outer = self

        class _Messages:
            async def create(cls_self, **kwargs):
                outer.calls += 1
                if outer.calls <= outer.fail_times:
                    raise outer.error_factory()
                from tests.mock_api import MockMessage
                return MockMessage('{"ok": true}')

        class _Client:
            messages = _Messages()

        self._client = _Client()

    @property
    def messages(self):
        return self._client.messages


class _NullTelemetry:
    def start_trace(self, agent_id, agent_type):
        return "trace-test"

    def end_trace(self, trace_id, result):
        pass

    def log_stage_event(self, *args, **kwargs):
        pass


def _config():
    return AgentConfig(
        agent_id="work_test_v1",
        agent_type="work",
        persona_path=FIXTURES / "test_persona.md",
    )


def _fast_retry_runner(api):
    return AgentRunner(
        api,
        _NullTelemetry(),
        retry_policy=RetryPolicy(
            RetryConfig(max_retries=0, base_delay_seconds=0.01, max_delay_seconds=0.01,
                        jitter=False, circuit_breaker=False),
        ),
    )


def test_transport_pause_then_continue(tmp_path):
    """重试耗尽 → 写 pause_state → 继续 token → 重置重试 → 成功。"""
    api = _FlakyAPI(fail_times=1, error_factory=lambda: ConnectionResetError("net down"))
    runner = _fast_retry_runner(api)
    task_ctx = {"task": "demo", "workspace": str(tmp_path)}

    async def scenario():
        # 首次调用进入暂停后，异步投递继续 token
        async def deliver_continue():
            pause_file = tmp_path / "pause_state.json"
            for _ in range(200):  # 最多等 2s
                if pause_file.exists():
                    break
                await asyncio.sleep(0.01)
            assert pause_file.exists(), "pause_state.json 未写入"
            state = json.loads(pause_file.read_text(encoding="utf-8"))
            assert state["paused"] is True
            assert state["category"] == "connection"
            (tmp_path / "tokens" / ".pause_continue").touch()

        deliver = asyncio.create_task(deliver_continue())
        result = await runner.run(_config(), task_ctx)
        await deliver
        return result

    result = asyncio.run(scenario())
    assert result.raw_text == '{"ok": true}'
    # 暂停已被清除
    state = json.loads((tmp_path / "pause_state.json").read_text(encoding="utf-8"))
    assert state["paused"] is False
    assert state["outcome"] == "resumed"
    # 继续 token 已被消费，不会造成下一次误继续
    assert not (tmp_path / "tokens" / ".pause_continue").exists()


def test_transport_pause_then_stop(tmp_path):
    """暂停后收到取消 token → 抛 RetryExhausted，pause_state 记录 stopped。"""
    from framework.retry import RetryExhausted

    api = _FlakyAPI(fail_times=99, error_factory=lambda: TimeoutError("upstream timeout"))
    runner = _fast_retry_runner(api)
    task_ctx = {"task": "demo", "workspace": str(tmp_path)}

    async def scenario():
        async def deliver_cancel():
            pause_file = tmp_path / "pause_state.json"
            for _ in range(200):
                if pause_file.exists():
                    break
                await asyncio.sleep(0.01)
            (tmp_path / "tokens" / ".cancel_requested").touch()

        deliver = asyncio.create_task(deliver_cancel())
        with pytest.raises(RetryExhausted):
            await runner.run(_config(), task_ctx)
        await deliver

    asyncio.run(scenario())
    state = json.loads((tmp_path / "pause_state.json").read_text(encoding="utf-8"))
    assert state["paused"] is False
    assert state["outcome"] == "stopped"


def test_request_error_does_not_pause(tmp_path):
    """401 类请求错误不进入暂停，直接抛出。"""
    from framework.retry import RetryExhausted

    api = _FlakyAPI(fail_times=99, error_factory=lambda: _FakeAPIError(401))
    runner = _fast_retry_runner(api)
    task_ctx = {"task": "demo", "workspace": str(tmp_path)}

    async def scenario():
        with pytest.raises(RetryExhausted):
            await runner.run(_config(), task_ctx)

    asyncio.run(scenario())
    assert not (tmp_path / "pause_state.json").exists()


# ═══════════════════════════ Web 端点 ═══════════════════════════

def test_web_pause_continue_endpoint(tmp_path, monkeypatch):
    """暂停中的 run 可以通过端点投递继续信号；未暂停时拒绝。"""
    from fastapi.testclient import TestClient
    from framework.runtime_config import RuntimeSettings
    from web import server

    root = tmp_path / "runs"
    root.mkdir()
    mapping = tmp_path / "mapping.json"
    mapping.write_text('{"paths": {}}', encoding="utf-8")
    monkeypatch.setattr(
        server, "RUNTIME_SETTINGS",
        RuntimeSettings(tmp_path, root, mapping),
    )
    monkeypatch.setattr(server, "RUNS_FILE", tmp_path / "runs-registry.json")

    ws = root / "case-pause"
    (ws / "tokens").mkdir(parents=True)
    (ws / "pause_state.json").write_text(
        json.dumps({"paused": True, "category": "connection", "agent_id": "work_M1_v1"}),
        encoding="utf-8",
    )
    server._runs["run-pause"] = {
        "workspace": str(ws), "status": "running",
        "started_at": "2026-08-21T00:00:00",
    }
    try:
        client = TestClient(server.app)

        # run 状态里能看到 pause 派生字段
        status = client.get("/api/runs/run-pause").json()
        assert status["pause"]["paused"] is True
        assert status["pause"]["category"] == "connection"

        response = client.post("/api/runs/run-pause/pause/continue")
        assert response.status_code == 200
        assert (ws / "tokens" / ".pause_continue").exists()

        # 未暂停时重复请求 → 409
        (ws / "pause_state.json").write_text('{"paused": false}', encoding="utf-8")
        (ws / "tokens" / ".pause_continue").unlink()
        assert client.post("/api/runs/run-pause/pause/continue").status_code == 409
    finally:
        server._runs.pop("run-pause", None)
