import asyncio
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from framework.runtime_config import RuntimeSettings
from framework.file_bus import FileBus
from framework.traffic_state import TrafficStateStore
from pipelines.etsi.pipeline import TrafficCollectStage
from pipelines.etsi.traffic_checklist import load_traffic_checklist
from web import server


async def _true_async():
    return True


def _initialized_store(tmp_path):
    version, checklist = load_traffic_checklist()
    store = TrafficStateStore(tmp_path)
    store.initialize(
        checklist_version=version,
        checklist=checklist,
        dut_ip="10.0.0.8",
        capture_pcap=tmp_path / "capture.pcap",
        control_mode="web",
    )
    return store


def test_traffic_state_persists_checklist_and_reentry_is_explicit(tmp_path):
    store = _initialized_store(tmp_path)
    store.transition("WAITING_START", "waiting_for_user_start")
    store.update_check_item("firmware_upload_old", "done", note="device rejected", evidence=["capture.pcap"])

    persisted = json.loads((tmp_path / "traffic_state.json").read_text(encoding="utf-8"))
    item = next(x for x in persisted["checklist"] if x["id"] == "firmware_upload_old")
    assert item["status"] == "done"
    assert item["note"] == "device rejected"
    assert item["evidence"] == ["capture.pcap"]

    # 进程重入不能假装重新接管旧进程；旧 attempt 必须明确留下 interrupted 记录。
    version, checklist = load_traffic_checklist()
    renewed = store.initialize(
        checklist_version=version,
        checklist=checklist,
        dut_ip="10.0.0.8",
        capture_pcap=tmp_path / "capture.pcap",
        control_mode="web",
    )
    assert renewed["status"] == "PREPARING"
    assert renewed["prior_attempts"][-1]["status"] == "WAITING_START"


def test_web_wait_requires_start_before_done(tmp_path):
    store = _initialized_store(tmp_path)
    store.transition("WAITING_START", "waiting_for_user_start")

    async def scenario():
        task = asyncio.create_task(
            TrafficCollectStage._wait_for_user_confirmation(tmp_path, "web", store)
        )
        await asyncio.sleep(0.05)
        tokens = tmp_path / "tokens"
        (tokens / "traffic_user_done").touch()
        await asyncio.sleep(0.05)
        assert not task.done()
        (tokens / "traffic_user_start").touch()
        # Pipeline 控制文件轮询间隔为 1 秒；等待其消费 start 而非假定即时处理。
        await asyncio.sleep(1.1)
        assert store.read()["status"] == "WAITING_FINISH"
        assert task.done() is False
        (tokens / "traffic_user_done").touch()
        return await asyncio.wait_for(task, timeout=2)

    assert asyncio.run(scenario()) is True


def test_web_wait_observes_cancellation_token(tmp_path):
    store = _initialized_store(tmp_path)
    store.transition("WAITING_START", "waiting_for_user_start")

    async def scenario():
        task = asyncio.create_task(
            TrafficCollectStage._wait_for_user_confirmation(tmp_path, "web", store)
        )
        await asyncio.sleep(0.05)
        (tmp_path / "tokens" / ".cancel_requested").touch()
        return await asyncio.wait_for(task, timeout=2)

    assert asyncio.run(scenario()) is None


def _configure_runtime(tmp_path, monkeypatch):
    root = tmp_path / "runs"
    root.mkdir()
    mapping = tmp_path / "mapping.json"
    mapping.write_text('{"paths": {}}', encoding="utf-8")
    monkeypatch.setattr(server, "RUNTIME_SETTINGS", RuntimeSettings(tmp_path, root, mapping))
    monkeypatch.setattr(server, "RUNS_FILE", tmp_path / "runs-registry.json")
    return root


def test_traffic_api_enforces_start_checklist_and_skip_reason(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-traffic"
    workspace.mkdir()
    (workspace / "pipeline_state.json").write_text(
        json.dumps({"current_state": "traffic"}), encoding="utf-8"
    )
    store = _initialized_store(workspace)
    store.transition("WAITING_START", "waiting_for_user_start")
    run_id = "traffic-api-test"
    server._runs[run_id] = {"workspace": str(workspace)}
    client = TestClient(server.app)

    done_before_start = client.post(f"/api/runs/{run_id}/traffic/confirm", json={"action": "done"})
    assert done_before_start.status_code == 409
    assert client.post(f"/api/runs/{run_id}/traffic/confirm", json={"action": "skip"}).status_code == 400

    started = client.post(f"/api/runs/{run_id}/traffic/confirm", json={"action": "start"})
    assert started.status_code == 200
    assert (workspace / "tokens/traffic_user_start").exists()

    # Pipeline 收到 start 后才会打开正式的 checklist 记录窗口。
    store.transition("WAITING_FINISH", "waiting_for_user_finish")
    not_ready = client.post(f"/api/runs/{run_id}/traffic/confirm", json={"action": "done"})
    assert not_ready.status_code == 409

    for item in store.read()["checklist"]:
        if item["required"]:
            response = client.put(
                f"/api/runs/{run_id}/traffic/checklist/{item['id']}",
                json={"status": "done", "note": "recorded"},
            )
            assert response.status_code == 200

    finished = client.post(f"/api/runs/{run_id}/traffic/confirm", json={"action": "done"})
    assert finished.status_code == 200
    assert (workspace / "tokens/traffic_user_done").exists()

    server._runs.pop(run_id, None)


def test_traffic_api_requests_cooperative_stop(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-cancel"
    workspace.mkdir()
    (workspace / "pipeline_state.json").write_text(
        json.dumps({"current_state": "traffic"}), encoding="utf-8"
    )
    run_id = "traffic-cancel-test"
    server._runs[run_id] = {"run_id": run_id, "workspace": str(workspace), "status": "running"}

    response = TestClient(server.app).post(f"/api/runs/{run_id}/stop")

    assert response.status_code == 200
    assert response.json()["status"] == "cancellation_requested"
    assert (workspace / "tokens/.cancel_requested").exists()
    server._runs.pop(run_id, None)


def test_traffic_stage_fake_channels_clean_up_and_complete(tmp_path, monkeypatch):
    """fake 只验证阶段控制流与清理顺序，不代表真实 DUT 条款通过。"""
    stopped = []
    events = []

    class FakeTelemetry:
        def log_stage_event(self, *args, **kwargs):
            events.append((args, kwargs))

    class FakeResolver:
        def check_tool(self, _name):
            return True

        def get_tool_path(self, name):
            return {
                "tshark": r"C:\temporary-mapping\tshark.exe",
                "xray": r"C:\temporary-mapping\xray.exe",
            }.get(name)

    class FakePipeline:
        def __init__(self):
            self.bus = FileBus(tmp_path)
            self.telemetry = FakeTelemetry()
            self.path_resolver = FakeResolver()
            self.control_mode = "web"
            self.non_interactive = False
            self.mcp_manager = SimpleNamespace(burp_connected=True, playwright_connected=True)
            self._state = SimpleNamespace(
                pipeline_id="traffic-fake", review_required=False, review_reasons=[],
            )

        def _save_state(self):
            pass

    class FakeProcess:
        returncode = None  # 启动后核验要求：进程仍在运行

    started_paths = []

    async def start_tshark(capture_pcap, _dut_ip, _iface, _receipt_context=None, **kwargs):
        started_paths.append(kwargs["tshark_path"])
        capture_pcap.write_bytes(b"x" * 2048)
        return FakeProcess()

    async def start_xray(_workspace, _receipt_context=None, **kwargs):
        started_paths.append(kwargs["xray_path"])
        return FakeProcess()

    async def stop_process(_proc, name, _receipt_context=None):
        stopped.append(name)

    async def configured(*_args, **_kwargs):
        return True

    async def confirmed(_workspace, _mode, state):
        state.transition("COLLECTING", "fake_started")
        state.transition("WAITING_FINISH", "fake_finished")
        for item in state.read()["checklist"]:
            if item["required"]:
                state.update_check_item(item["id"], "done")
        return True

    async def analyzed(*_args, **_kwargs):
        return True

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(TrafficCollectStage, "_detect_interface", staticmethod(lambda *_args: None))
    monkeypatch.setattr(TrafficCollectStage, "_start_tshark", staticmethod(start_tshark))
    monkeypatch.setattr(TrafficCollectStage, "_start_xray", staticmethod(start_xray))
    monkeypatch.setattr(TrafficCollectStage, "_wait_for_tcp_listener", staticmethod(lambda *_args, **_kwargs: _true_async()))
    monkeypatch.setattr(TrafficCollectStage, "_stop_process", staticmethod(stop_process))
    monkeypatch.setattr(TrafficCollectStage, "_configure_burp_upstream", staticmethod(configured))
    monkeypatch.setattr(TrafficCollectStage, "_remove_burp_upstream", staticmethod(configured))
    monkeypatch.setattr(TrafficCollectStage, "_wait_for_user_confirmation", staticmethod(confirmed))
    monkeypatch.setattr(TrafficCollectStage, "_run_pcap_analyzer", staticmethod(analyzed))
    monkeypatch.setattr("pipelines.etsi.pipeline.asyncio.sleep", no_sleep)

    pipeline = FakePipeline()
    asyncio.run(TrafficCollectStage().execute(tmp_path, registry=None, pipeline=pipeline))

    final = TrafficStateStore(tmp_path).read()
    assert final["status"] == "COMPLETE"
    assert stopped == ["xray", "tshark"]
    assert started_paths == [
        r"C:\temporary-mapping\tshark.exe",
        r"C:\temporary-mapping\xray.exe",
    ]
    assert pipeline._state.review_required is False
    assert any(args[2] == "pcap_analyzer_done" for args, _ in events)


# ═══════════════════════════ 网卡自动检测 ═══════════════════════════

def test_capture_host_strips_url_scheme_port_and_path():
    """DUT 控制台 URL 必须转换为 tshark 可接受的 BPF host。"""
    assert TrafficCollectStage._capture_host("http://192.168.22.129:8080/") == "192.168.22.129"
    assert TrafficCollectStage._capture_host("https://dut.example.test/ui") == "dut.example.test"
    assert TrafficCollectStage._capture_host("192.168.22.129") == "192.168.22.129"


def test_traffic_stage_routes_interface_detection_with_dut_host(tmp_path, monkeypatch):
    """Web 填入 URL 时，网卡检测不得把 scheme/path 传给路由查询。"""
    observed = []

    class FakeTelemetry:
        def log_stage_event(self, *_args, **_kwargs):
            pass

    class FakePipeline:
        def __init__(self):
            self.bus = FileBus(tmp_path)
            self.bus.write_json("run_config.json", {"dut_ip": "http://192.168.22.129:8080/"})
            self.telemetry = FakeTelemetry()
            self.path_resolver = SimpleNamespace(
                check_tool=lambda _name: True,
                get_tool_path=lambda name: rf"C:\temporary\{name}.exe",
            )
            self.control_mode = "web"
            self.non_interactive = False
            self.mcp_manager = SimpleNamespace(burp_connected=True, playwright_connected=True)
            self._state = SimpleNamespace(pipeline_id="traffic-url", review_required=False, review_reasons=[])

        def _save_state(self):
            pass

    class FakeProcess:
        returncode = None

    async def start_tshark(capture_pcap, *_args, **_kwargs):
        capture_pcap.write_bytes(b"x" * 2048)
        return FakeProcess()

    async def fake_process(*_args, **_kwargs):
        return FakeProcess()

    async def configured(*_args, **_kwargs):
        return True

    async def finished(*_args, **_kwargs):
        return False

    async def no_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(TrafficCollectStage, "_detect_interface", staticmethod(lambda host, *_args: observed.append(host) or None))
    monkeypatch.setattr(TrafficCollectStage, "_start_tshark", staticmethod(start_tshark))
    monkeypatch.setattr(TrafficCollectStage, "_start_xray", staticmethod(fake_process))
    monkeypatch.setattr(TrafficCollectStage, "_wait_for_tcp_listener", staticmethod(lambda *_args, **_kwargs: _true_async()))
    monkeypatch.setattr(TrafficCollectStage, "_stop_process", staticmethod(configured))
    monkeypatch.setattr(TrafficCollectStage, "_configure_burp_upstream", staticmethod(configured))
    monkeypatch.setattr(TrafficCollectStage, "_remove_burp_upstream", staticmethod(configured))
    monkeypatch.setattr(TrafficCollectStage, "_wait_for_user_confirmation", staticmethod(finished))
    monkeypatch.setattr("pipelines.etsi.pipeline.asyncio.sleep", no_sleep)

    asyncio.run(TrafficCollectStage().execute(tmp_path, registry=None, pipeline=FakePipeline()))
    assert observed == ["192.168.22.129"]

def test_detect_interface_env_override_skips_detection(monkeypatch):
    """TSHARK_IFACE 手动指定时直接采用，不启动任何子进程。"""
    import pipelines.etsi.pipeline as pl

    monkeypatch.setenv("TSHARK_IFACE", "5")

    def boom(*args, **kwargs):
        raise AssertionError("不应调用任何子进程")

    monkeypatch.setattr(pl.subprocess, "run", boom)
    assert TrafficCollectStage._detect_interface("10.0.0.8") == "5"


def test_detect_interface_windows_maps_wlan_alias_to_npf(monkeypatch):
    """出口 IP → InterfaceAlias(WLAN) → tshark -D 中的 NPF 设备名。"""
    import pipelines.etsi.pipeline as pl

    monkeypatch.setattr(pl.os, "name", "nt")
    monkeypatch.setattr(
        TrafficCollectStage, "_local_route_ip",
        staticmethod(lambda _ip: "192.168.1.64"),
    )
    monkeypatch.setattr(TrafficCollectStage, "_tshark_binary", staticmethod(lambda: "tshark.exe"))

    def fake_run(cmd, **kwargs):
        if cmd[0] == "powershell":
            return SimpleNamespace(stdout="WLAN\n", stderr="")
        assert cmd[:2] == ["tshark.exe", "-D"], cmd
        return SimpleNamespace(
            stdout=(
                "1. \\Device\\NPF_{1ADA5E8B} (本地连接* 10)\n"
                "5. \\Device\\NPF_{DEEFF2E2-EDB3-4B8D-92BD-FD81F889F7C5} (WLAN)\n"
                "9. \\Device\\NPF_{9C634CC2} (以太网)\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(pl.subprocess, "run", fake_run)
    assert TrafficCollectStage._detect_interface("10.19.199.26") == (
        "\\Device\\NPF_{DEEFF2E2-EDB3-4B8D-92BD-FD81F889F7C5}"
    )


def test_detect_interface_linux_dev_name(monkeypatch):
    """非 Windows 分支：ip route get 的 dev 名可直接用于 tshark -i。"""
    import pipelines.etsi.pipeline as pl

    monkeypatch.setattr(pl.os, "name", "posix")

    def fake_run(cmd, **kwargs):
        assert cmd[:3] == ["ip", "route", "get"]
        return SimpleNamespace(stdout="10.0.0.8 dev wlan0 src 192.168.1.64\n", stderr="")

    monkeypatch.setattr(pl.subprocess, "run", fake_run)
    assert TrafficCollectStage._detect_interface("10.0.0.8") == "wlan0"


def test_detect_interface_returns_none_when_alias_lookup_fails(monkeypatch):
    """Get-NetIPAddress 查不到别名时安静返回 None，不抛异常。"""
    import pipelines.etsi.pipeline as pl

    monkeypatch.setattr(pl.os, "name", "nt")
    monkeypatch.setattr(
        TrafficCollectStage, "_local_route_ip",
        staticmethod(lambda _ip: "192.168.1.64"),
    )
    monkeypatch.setattr(pl.subprocess, "run", lambda cmd, **kw: SimpleNamespace(stdout="", stderr=""))

    assert TrafficCollectStage._detect_interface("10.0.0.8") is None


def test_traffic_stage_requires_pcap_only_after_user_finishes(tmp_path, monkeypatch):
    """pcap 可在用户操作后才生成；缺失时应在完成采集后 BLOCKED。"""
    events = []

    class FakeTelemetry:
        def log_stage_event(self, *args, **kwargs):
            events.append((args, kwargs))

    class FakePipeline:
        def __init__(self):
            self.bus = FileBus(tmp_path)
            self.telemetry = FakeTelemetry()
            self.path_resolver = SimpleNamespace(check_tool=lambda _n: True)
            self.control_mode = "web"
            self.non_interactive = False
            self.mcp_manager = SimpleNamespace(burp_connected=True, playwright_connected=True)
            self._state = SimpleNamespace(
                pipeline_id="traffic-verify", review_required=False, review_reasons=[],
            )

        def _save_state(self):
            pass

        def request_needs_review(self, current, reason):
            self.review_request = (current, reason)

    class FakeProcess:
        returncode = None

    async def start_tshark(capture_pcap, _dut_ip, _iface, _receipt_context=None, **_kwargs):
        return FakeProcess()  # 不预先写 pcap；它应在用户实际操作后才产生。

    async def start_xray(_workspace, _receipt_context=None, **_kwargs):
        return FakeProcess()

    async def stop_process(_proc, _name, _receipt_context=None):
        return None

    async def configured(*_args, **_kwargs):
        return True

    opened_window = []

    async def confirmed(*_args, **_kwargs):
        opened_window.append(True)
        return True

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(TrafficCollectStage, "_detect_interface", staticmethod(lambda *_args: None))
    monkeypatch.setattr(TrafficCollectStage, "_start_tshark", staticmethod(start_tshark))
    monkeypatch.setattr(TrafficCollectStage, "_start_xray", staticmethod(start_xray))
    monkeypatch.setattr(TrafficCollectStage, "_wait_for_tcp_listener", staticmethod(lambda *_args, **_kwargs: _true_async()))
    monkeypatch.setattr(TrafficCollectStage, "_stop_process", staticmethod(stop_process))
    monkeypatch.setattr(TrafficCollectStage, "_configure_burp_upstream", staticmethod(configured))
    monkeypatch.setattr(TrafficCollectStage, "_remove_burp_upstream", staticmethod(configured))
    monkeypatch.setattr(TrafficCollectStage, "_wait_for_user_confirmation", staticmethod(confirmed))
    monkeypatch.setattr(TrafficCollectStage, "_run_pcap_analyzer", staticmethod(configured))
    monkeypatch.setattr("pipelines.etsi.pipeline.asyncio.sleep", no_sleep)

    pipeline = FakePipeline()
    asyncio.run(TrafficCollectStage().execute(tmp_path, registry=None, pipeline=pipeline))

    final = TrafficStateStore(tmp_path).read()
    assert final["status"] == "BLOCKED"
    assert opened_window == [True]
    assert not any(args[2] == "tshark_start_verify_failed" for args, _ in events)
    assert pipeline.review_request[0].value == "traffic"
    assert "BLOCKED" in pipeline.review_request[1]
