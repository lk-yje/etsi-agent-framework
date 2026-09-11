"""Transport 错误分类 — 判定 LLM API 调用失败是"运输层可恢复"还是"请求本身有病"。

设计立场：保护结果，不保护运输。
- 运输层错误（断网、超时、限流、上游过载）不改变请求语义 → 值得暂停等待人工
  恢复网络后原样重试，而不是烧完重试次数把整个 run 判死。
- 请求层错误（401 凭证、400 参数、404 模型不存在）重试一万次也是同样的结果
  → 立即失败，不进入暂停。
"""

from enum import Enum
from typing import Optional


class TransportErrorCategory(str, Enum):
    RATE_LIMITED = "rate_limited"          # 429 — 配额/限流，等待后可重试
    OVERLOADED = "overloaded"              # 529 — provider 过载
    TIMEOUT = "timeout"                    # 请求超时
    CONNECTION = "connection"              # 断网 / DNS / 连接重置
    SERVER_ERROR = "server_error"          # 5xx — 上游内部错误
    AUTH = "auth"                          # 401/403 — 凭证问题，重试无意义
    INVALID_REQUEST = "invalid_request"    # 400 — 请求本身错误，重试无意义
    NOT_FOUND = "not_found"                # 404 — 模型/端点不存在
    UNKNOWN = "unknown"


# 可暂停（pausable）类别：只包含运输层/上游临时性错误。
# AUTH / INVALID_REQUEST / NOT_FOUND / UNKNOWN 不在其中 — 这些重试不会自愈。
PAUSABLE_CATEGORIES = frozenset({
    TransportErrorCategory.RATE_LIMITED,
    TransportErrorCategory.OVERLOADED,
    TransportErrorCategory.TIMEOUT,
    TransportErrorCategory.CONNECTION,
    TransportErrorCategory.SERVER_ERROR,
})


# anthropic SDK 异常类名 → 类别（按类名匹配，不 import SDK，保持 provider 中立；
# 私有 Anthropic 兼容网关通常也抛同名异常或带 status_code 的通用 HTTPError）。
_NAME_MATCHES = (
    ("ratelimiterror", TransportErrorCategory.RATE_LIMITED),
    ("overloadederror", TransportErrorCategory.OVERLOADED),
    ("apitimeouterror", TransportErrorCategory.TIMEOUT),
    ("timeouterror", TransportErrorCategory.TIMEOUT),
    ("apiconnectionerror", TransportErrorCategory.CONNECTION),
    ("connectionerror", TransportErrorCategory.CONNECTION),
    ("authenticationerror", TransportErrorCategory.AUTH),
    ("permissiondeniederror", TransportErrorCategory.AUTH),
    ("badrequesterror", TransportErrorCategory.INVALID_REQUEST),
    ("notfounderror", TransportErrorCategory.NOT_FOUND),
    ("internalservererror", TransportErrorCategory.SERVER_ERROR),
    ("apistatuserror", TransportErrorCategory.UNKNOWN),  # 兜底：父类，再看 status_code
)

_STATUS_MATCHES = (
    (429, TransportErrorCategory.RATE_LIMITED),
    (529, TransportErrorCategory.OVERLOADED),
    (401, TransportErrorCategory.AUTH),
    (403, TransportErrorCategory.AUTH),
    (400, TransportErrorCategory.INVALID_REQUEST),
    (404, TransportErrorCategory.NOT_FOUND),
)


def classify_exception(exc: Optional[BaseException]) -> TransportErrorCategory:
    """把任意异常归类到 TransportErrorCategory。"""
    if exc is None:
        return TransportErrorCategory.UNKNOWN

    name = type(exc).__name__.lower()
    matched = TransportErrorCategory.UNKNOWN
    for fragment, category in _NAME_MATCHES:
        if fragment in name:
            matched = category
            break

    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        if any(status_code == code for code, _ in _STATUS_MATCHES):
            return next(
                category for code, category in _STATUS_MATCHES if code == status_code
            )
        if 500 <= status_code < 600:
            return TransportErrorCategory.SERVER_ERROR
        # 有 status_code 但没命中已知档位：类名匹配结果优于 UNKNOWN
        if matched is not TransportErrorCategory.UNKNOWN:
            return matched
        return TransportErrorCategory.UNKNOWN

    if matched is not TransportErrorCategory.UNKNOWN:
        return matched
    if isinstance(exc, TimeoutError):
        return TransportErrorCategory.TIMEOUT
    if isinstance(exc, OSError):
        # ConnectionResetError / ConnectionAbortedError / DNS gaierror 等都是 OSError 子类
        return TransportErrorCategory.CONNECTION
    return TransportErrorCategory.UNKNOWN


def is_pausable(exc: Optional[BaseException]) -> bool:
    """该异常是否属于运输层可暂停错误（等待人工恢复后可原样重试）。"""
    return classify_exception(exc) in PAUSABLE_CATEGORIES
