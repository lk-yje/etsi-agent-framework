"""从归一化 IXIT 中保守提取可追溯的流量声明。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from contracts.traffic_intelligence import (
    FlowDirection,
    TrafficDeclaration,
    TrafficDeclarationSource,
)


_APPLICATION_PROTOCOL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bWEBSOCKETS?\b", "WEBSOCKET"),
    (r"\bWS[- ]?DISCOVERY\b", "WS-DISCOVERY"),
    (r"\bOPC\s*UA\b", "OPC UA"),
    (r"\bHTTPS\b", "HTTPS"),
    (r"\bHTTP\b", "HTTP"),
    (r"\bRTSPS\b", "RTSPS"),
    (r"\bRTSP\b", "RTSP"),
    (r"\bMQTTS\b", "MQTTS"),
    (r"\bMQTT\b", "MQTT"),
    (r"\bCOAPS\b", "COAPS"),
    (r"\bCOAP\b", "COAP"),
    (r"\bSFTP\b", "SFTP"),
    (r"\bFTPS\b", "FTPS"),
    (r"\bFTP\b", "FTP"),
    (r"\bSMTPS\b", "SMTPS"),
    (r"\bSMTP\b", "SMTP"),
    (r"\bIMAPS\b", "IMAPS"),
    (r"\bIMAP\b", "IMAP"),
    (r"\bPOP3S\b", "POP3S"),
    (r"\bPOP3\b", "POP3"),
    (r"\bSYSLOG\b", "SYSLOG"),
    (r"\bSNMP\b", "SNMP"),
    (r"\bONVIF\b", "ONVIF"),
    (r"\bMODBUS\b", "MODBUS"),
    (r"\bBACNET\b", "BACNET"),
    (r"\bTELNET\b", "TELNET"),
    (r"\bSSH\b", "SSH"),
    (r"\bDNS\b", "DNS"),
    (r"\bDHCP\b", "DHCP"),
    (r"\bNTP\b", "NTP"),
    (r"\bAMQP\b", "AMQP"),
    (r"\bSOAP\b", "SOAP"),
    (r"\bRTP\b", "RTP"),
    (r"\bSIP\b", "SIP"),
    (r"\bISUP\b", "ISUP"),
    (r"\bSADP\b", "SADP"),
    (r"\bOTAP\b", "OTAP"),
    (r"\bSDK\b", "SDK"),
)

_ENCRYPTION_PROTOCOL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bDTLS\b", "DTLS"),
    (r"\bTLS\b", "TLS"),
    (r"\bSSL\b", "SSL"),
    (r"\bIPSEC\b", "IPSEC"),
    (r"\bSSH(?:V?2)?\b", "SSH"),
)

_CIPHER_RE = re.compile(
    r"\b(?:TLS_[A-Z0-9_]+|(?:ECDHE|DHE|ECDH|DH|RSA|PSK|AES|ARIA|CAMELLIA)"
    r"(?:[-_][A-Z0-9]+){1,8}|CHACHA20(?:[-_]POLY1305)?|HMAC[-_]SHA(?:1|224|256|384|512)|"
    r"AES[-_]?(?:128|192|256)|SHA[-_]?(?:1|224|256|384|512)|MD5|3DES|DES)\b",
    re.IGNORECASE,
)

_TLS_VERSION_RE = re.compile(r"\b(?:TLS|DTLS)\s*(?:V(?:ERSION)?\s*)?([0-9]+(?:\.[0-9]+){1,2})\b", re.I)
_PORT_PATTERNS = (
    re.compile(r"(?i)\bport\s*[:=#]?\s*(\d{1,5})\b"),
    re.compile(r"(?i)\bIP\s*:\s*(\d{1,5})\b"),
    re.compile(r"(?i)\b[A-Z][A-Z0-9+.-]*\s*\(\s*(\d{1,5})\s*\)"),
)
_URL_HOST_RE = re.compile(r"(?i)\b(?:https?|rtsp|mqtt|ftp|ssh)://([^/:\s]+)")
_DNS_NAME_RE = re.compile(r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class DeclarationExtractionResult:
    declarations: list[TrafficDeclaration]
    warnings: list[str]
    communication_table_present: bool


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).casefold())


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value).strip()
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return "\n".join(_string(item) for item in value if _string(item))
    return ""


def _lookup(row: Mapping[str, Any], *names: str) -> str:
    normalized = {_key(name): value for name, value in row.items()}
    for name in names:
        value = _string(normalized.get(_key(name)))
        if value:
            return value
    return ""


def _table_rows(table: Any) -> list[dict[str, Any]] | None:
    if isinstance(table, Mapping):
        rows = table.get("rows")
    else:
        rows = table
    if not isinstance(rows, list):
        return None
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _logical_rows(rows: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    """把 flat parser 的 Field/Value 行还原为逻辑记录。"""
    if not rows or not all("Field" in row and "Value" in row for row in rows):
        return list(enumerate(rows, start=1))

    logical: list[tuple[int, dict[str, Any]]] = []
    current: dict[str, Any] = {}
    start_row = 1
    for row_number, row in enumerate(rows, start=1):
        field = _string(row.get("Field"))
        if not field:
            continue
        if _key(field) in {"id", "identifier", "protocol", "mechanism"} and current:
            logical.append((start_row, current))
            current = {}
            start_row = row_number
        current[field] = row.get("Value")
    if current:
        logical.append((start_row, current))
    return logical


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _extract_protocols(text: str) -> list[str]:
    return _unique([
        canonical
        for pattern, canonical in _APPLICATION_PROTOCOL_PATTERNS
        if re.search(pattern, text, re.IGNORECASE)
    ])


def _extract_transport(text: str) -> list[str]:
    return [name for name in ("TCP", "UDP", "SCTP") if re.search(rf"\b{name}\b", text, re.I)]


def _extract_encryption_protocols(text: str, applications: Sequence[str]) -> list[str]:
    found = [
        canonical
        for pattern, canonical in _ENCRYPTION_PROTOCOL_PATTERNS
        if re.search(pattern, text, re.IGNORECASE)
    ]
    if any(protocol in {"HTTPS", "MQTTS", "COAPS", "FTPS", "SMTPS", "IMAPS", "POP3S", "RTSPS"}
           for protocol in applications):
        found.append("TLS")
    return _unique(found)


def _extract_ports(text: str) -> list[int]:
    ports: list[int] = []
    for pattern in _PORT_PATTERNS:
        for match in pattern.finditer(text):
            port = int(match.group(1))
            if 0 <= port <= 65535:
                ports.append(port)
    return sorted(set(ports))


def _ports_from_columns(row: Mapping[str, Any], *, prefix: str | None = None) -> list[int]:
    values: list[int] = []
    for name, raw in row.items():
        normalized = _key(name)
        if "port" not in normalized:
            continue
        if prefix and prefix not in normalized:
            continue
        if isinstance(raw, int) and 0 <= raw <= 65535:
            values.append(raw)
            continue
        for match in re.finditer(r"\b\d{1,5}\b", _string(raw)):
            port = int(match.group())
            if 0 <= port <= 65535:
                values.append(port)
    return sorted(set(values))


def _direction(text: str) -> FlowDirection | None:
    server = bool(re.search(r"(?i)(?:\(\s*server\s*\)|acts? as (?:an? )?server|服务端|服务器)", text))
    client = bool(re.search(r"(?i)(?:\(\s*client\s*\)|acts? as (?:a )?client|客户端)", text))
    if server == client:
        return None
    return FlowDirection.INBOUND if server else FlowDirection.OUTBOUND


def _encryption_expectation(
    text: str,
    applications: Sequence[str],
    encryption_protocols: Sequence[str],
) -> tuple[bool | None, str | None]:
    lower = text.casefold()
    explicit_plaintext = bool(re.search(
        r"(?i)\b(?:plaintext|cleartext|unencrypted|does not (?:perform|provide) encryption|no encryption)\b|明文|不加密",
        text,
    )) or bool(re.search(r"(?im)^\s*(?:none|n/a\s*\(\s*plaintext\s*\))\s*$", text))
    explicit_encrypted = bool(encryption_protocols) or bool(re.search(
        r"(?i)\b(?:link|transport|channel)\s+(?:is\s+)?encrypted\b|链路加密|传输加密",
        text,
    ))
    secure_application = any(item in {
        "HTTPS", "MQTTS", "COAPS", "FTPS", "SMTPS", "IMAPS", "POP3S", "RTSPS", "SSH", "SFTP",
    } for item in applications)
    mixed_mode = (
        explicit_plaintext and (explicit_encrypted or secure_application)
    ) or any(pair in lower for pair in ("http or https", "http/https"))
    if mixed_mode:
        return None, "同一声明同时包含加密和非加密模式，无法归一为单一加密期望"
    if explicit_plaintext:
        return False, None
    if explicit_encrypted or secure_application:
        return True, None
    return None, None


def _minimum_version(text: str) -> str | None:
    versions = _unique([match.group(1) for match in _TLS_VERSION_RE.finditer(text)])
    if not versions:
        return None
    return min(versions, key=lambda value: tuple(int(part) for part in value.split(".")))


def _algorithm_claims(row: Mapping[str, Any], text: str) -> list[str]:
    explicit = _lookup(row, "Cipher Suites", "Cipher Suite", "Algorithms", "Algorithm")
    claims: list[str] = []
    for source in (explicit, text):
        claims.extend(match.group(0).upper().replace("_", "-") for match in _CIPHER_RE.finditer(source))
    return _unique(claims)[:256]


def _remote_hosts(row: Mapping[str, Any]) -> list[str]:
    raw = _lookup(
        row,
        "Remote Host",
        "Remote Hosts",
        "Destination",
        "Destination Host",
        "Server Address",
        "Endpoint",
        "Host",
    )
    if not raw:
        return []
    candidates = [match.group(1) for match in _URL_HOST_RE.finditer(raw)]
    candidates.extend(re.split(r"[,;\s]+", raw))
    normalized: list[str] = []
    for candidate in candidates:
        value = candidate.strip().strip("[]().,").casefold()
        if not value:
            continue
        try:
            normalized.append(str(ipaddress.ip_address(value)))
        except ValueError:
            if _DNS_NAME_RE.fullmatch(value):
                normalized.append(value.rstrip("."))
    return _unique(normalized)


def _interface_matches(
    interface_rows: list[tuple[int, dict[str, Any]]],
    applications: Sequence[str],
) -> list[tuple[int, dict[str, Any]]]:
    if not applications:
        return []
    matches: list[tuple[int, dict[str, Any]]] = []
    for row_number, row in interface_rows:
        identity = _lookup(row, "ID", "Name", "Interface", "Protocol")
        if not identity:
            identity = _lookup(row, "Purpose")
        identified = set(_extract_protocols(identity))
        if identified.intersection(applications):
            matches.append((row_number, row))
    return matches


def _canonical_hash(primary_row: Mapping[str, Any], interfaces: Sequence[Mapping[str, Any]]) -> str:
    payload = json.dumps(
        {"communication_mechanism": primary_row, "interfaces": list(interfaces)},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def extract_traffic_declarations(
    ixit: Mapping[str, Any],
    *,
    artifact: str = "ixit.json",
) -> DeclarationExtractionResult:
    """提取 11-ComMech，并只用可明确关联的 15-Intf 行补端口/用途。"""
    warnings: list[str] = []
    tables = ixit.get("ixit_tables")
    if not isinstance(tables, Mapping):
        return DeclarationExtractionResult([], ["IXIT 缺少有效的 ixit_tables"], False)

    communication_present = "11-ComMech" in tables
    communication_rows = _table_rows(tables.get("11-ComMech")) if communication_present else None
    if not communication_present:
        return DeclarationExtractionResult([], ["IXIT 缺少 11-ComMech，无法判断未声明通信"], False)
    if communication_rows is None:
        return DeclarationExtractionResult([], ["IXIT 11-ComMech rows 不是对象数组"], False)

    raw_interfaces = _table_rows(tables.get("15-Intf")) if "15-Intf" in tables else []
    if raw_interfaces is None:
        warnings.append("IXIT 15-Intf rows 不是对象数组，未用于补充端口和用途")
        raw_interfaces = []
    interface_rows = _logical_rows(raw_interfaces)

    declarations: list[TrafficDeclaration] = []
    for row_number, row in _logical_rows(communication_rows):
        identifier = _lookup(row, "ID", "Identifier", "Mechanism", "Protocol", "Name")
        description = _lookup(row, "Description", "Purpose", "Use", "Use Case")
        security = _lookup(row, "Security Guarantees", "Security Guarantee")
        crypto = _lookup(
            row,
            "Cryptographic Details",
            "Cryptography",
            "Cipher Suites",
            "Cipher Suite",
            "Encryption",
        )
        version = _lookup(row, "Version", "Protocol Version", "Minimum Version")
        transport_text = _lookup(row, "Transport", "Transport Protocol")
        text = "\n".join(
            value
            for value in (identifier, description, security, crypto, version, transport_text)
            if value
        )
        if not text:
            warnings.append(f"11-ComMech 第 {row_number} 行为空，已跳过")
            continue

        applications = _extract_protocols("\n".join((identifier, _lookup(row, "Protocol"), description)))
        transports = _extract_transport(text)
        direction = _direction("\n".join((identifier, description)))
        encryption_protocols = _extract_encryption_protocols(text, applications)
        encryption_expected, encryption_warning = _encryption_expectation(
            text,
            applications,
            encryption_protocols,
        )

        local_ports = _ports_from_columns(row, prefix="local")
        remote_ports = _ports_from_columns(row, prefix="remote")
        generic_ports = _ports_from_columns(row)
        generic_ports.extend(_extract_ports("\n".join((identifier, description))))
        generic_ports = sorted(set(generic_ports) - set(local_ports) - set(remote_ports))
        if direction == FlowDirection.INBOUND:
            local_ports.extend(generic_ports)
        elif direction == FlowDirection.OUTBOUND:
            remote_ports.extend(generic_ports)

        matched_interfaces = _interface_matches(interface_rows, applications)
        interface_sources: list[dict[str, Any]] = []
        interface_purposes: list[str] = []
        for interface_row_number, interface in matched_interfaces:
            interface_ports = _ports_from_columns(interface)
            interface_ports.extend(_extract_ports("\n".join(
                _string(value) for value in interface.values()
            )))
            local_ports.extend(interface_ports)
            purpose = _lookup(interface, "Purpose", "Description")
            if purpose:
                interface_purposes.append(purpose)
            interface_sources.append(interface)
            if interface_ports:
                warnings.append(
                    f"11-ComMech 第 {row_number} 行从 15-Intf 第 {interface_row_number} 行补充本地端口"
                )

        row_warnings: list[str] = []
        if not identifier:
            row_warnings.append("缺少通信机制 ID/Protocol")
        if direction is None:
            row_warnings.append("未声明 DUT 作为 client/server，方向无法确定")
        if not transports:
            row_warnings.append("未明确声明 TCP/UDP/SCTP")
        if not applications:
            row_warnings.append("未识别到可保守归一化的应用协议名称")
        if not local_ports and not remote_ports:
            row_warnings.append("11-ComMech/15-Intf 未提供可关联端口")
        if encryption_expected is None:
            row_warnings.append("无法归一为单一的链路加密期望")
        if encryption_warning:
            row_warnings.append(encryption_warning)

        raw_hash = _canonical_hash(row, interface_sources)
        declaration_id = f"decl-{raw_hash[:20]}"
        declarations.append(TrafficDeclaration(
            declaration_id=declaration_id,
            source=TrafficDeclarationSource(
                artifact=artifact,
                table="11-ComMech",
                row=row_number,
            ),
            raw_text_sha256=raw_hash,
            purpose=description or ("; ".join(_unique(interface_purposes)) or None),
            direction=direction,
            transport=sorted(set(transports)),
            application_protocol=applications,
            local_ports=sorted(set(local_ports)),
            remote_ports=sorted(set(remote_ports)),
            remote_hosts=_remote_hosts(row),
            encryption_expected=encryption_expected,
            encryption_protocol=encryption_protocols,
            minimum_version=_minimum_version("\n".join((version, crypto, security))),
            algorithm_claims=_algorithm_claims(row, crypto),
            normalization_warnings=row_warnings,
        ))

    return DeclarationExtractionResult(
        declarations=declarations,
        warnings=_unique(warnings),
        communication_table_present=True,
    )


__all__ = ["DeclarationExtractionResult", "extract_traffic_declarations"]
