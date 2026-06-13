#!/usr/bin/env python3
"""
xray_parser.py — Robust Xray/V2Ray client configuration parser
===============================================================
Parses, filters, and sorts outbounds from Xray client JSON configs
and VPN subscription URLs.

Protocols  : VLESS, VMess, Trojan, Shadowsocks, Hysteria2/1, WireGuard,
             SOCKS, HTTP, Freedom, Blackhole, Loopback, DNS + unknown
Transports : TCP, WebSocket, gRPC, xHTTP/SplitHTTP, HTTP/2,
             HTTPUpgrade, QUIC, KCP/mKCP
Security   : TLS, REALITY, XTLS (flow)
Extras     : comment stripping, CIDR/glob/regex address matching,
             multi-server outbounds, WireGuard peers, loopback chains,
             subscription URL fetching (base64 URI list, Xray JSON,
             SingBox JSON) with Happ/v2raytun/v2rayNG UA emulation

Requirements: Python 3.10+  (stdlib only, no extra deps)

Usage (API):
    parser = XrayConfigParser().load_file("client.json")
    parser = XrayConfigParser().load_url("https://sub.example.com/abc123")
    vless  = parser.collection().protocol("vless").sort("address")
    by_net = parser.collection().group_by("network")

Usage (CLI):
    python xray_parser.py client.json --summary
    python xray_parser.py client.json -p vless,hysteria2
    python xray_parser.py client.json -a "*.example.com" -a "10.0.0.0/8"
    python xray_parser.py client.json -n ws,grpc -s reality --json
    python xray_parser.py client.json --group protocol

    python xray_parser.py --url https://sub.example.com/abc123
    python xray_parser.py --url https://sub.example.com/abc123 --ua v2raytun
    python xray_parser.py --url https://sub.example.com/abc123 -p vless --json
    python xray_parser.py --url https://sub.example.com/abc123 --insecure
"""
from __future__ import annotations

import argparse
import base64
import copy
import gzip
import ipaddress
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional, Union


# ══════════════════════════════════════════════════════════════════════════════
#  Subscription Constants
# ══════════════════════════════════════════════════════════════════════════════

SUBSCRIPTION_USER_AGENTS: dict[str, str] = {
    "happ":     "Happ/3.22.1/Android/17800541067281831514",
    "v2raytun": "v2raytun/android",
    "v2rayng":  "v2rayNG/1.8.19",
    "v2rayn":   "v2rayN/6.47",
    "clash":    "clash-verge/1.6.6",
    "singbox":  "sing-box/1.9.0",
    "nekobox":  "Nekobox/1.2.6",
}
DEFAULT_SUB_UA = "v2rayng"

# All scheme prefixes recognised in proxy URI lists
_PROXY_URI_SCHEMES: frozenset[str] = frozenset({
    "vmess", "vless", "trojan",
    "ss", "shadowsocks",
    "hy2", "hysteria2", "hysteria",
    "wireguard", "wg",
    "socks", "socks5",
})


# ══════════════════════════════════════════════════════════════════════════════
#  Protocol Registry
# ══════════════════════════════════════════════════════════════════════════════

class Protocol(str, Enum):
    VLESS       = "vless"
    VMESS       = "vmess"
    TROJAN      = "trojan"
    SHADOWSOCKS = "shadowsocks"
    SOCKS       = "socks"
    HTTP        = "http"
    HYSTERIA2   = "hysteria2"
    HYSTERIA    = "hysteria"
    WIREGUARD   = "wireguard"
    FREEDOM     = "freedom"
    BLACKHOLE   = "blackhole"
    LOOPBACK    = "loopback"
    DNS         = "dns"
    UNKNOWN     = "unknown"

    # Aliases accepted by some clients/generators
    _ALIASES: dict = {}  # populated below

    @classmethod
    def parse(cls, s: str) -> "Protocol":
        s = (s or "").lower().strip()
        aliases = {
            "ss": "shadowsocks", "hy2": "hysteria2",
            "wg": "wireguard",   "h2": "http",
        }
        s = aliases.get(s, s)
        try:
            return cls(s)
        except ValueError:
            return cls.UNKNOWN

    @property
    def is_proxy(self) -> bool:
        """True for real proxy protocols (excludes freedom/blackhole/loopback/dns)."""
        return self not in {
            Protocol.FREEDOM, Protocol.BLACKHOLE,
            Protocol.LOOPBACK, Protocol.DNS, Protocol.UNKNOWN,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  Data Models
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ServerEndpoint:
    address: str = ""
    port:    int = 0

    def __str__(self) -> str:
        if not self.address:
            return "(empty)"
        if ":" in self.address and not self.address.startswith("["):
            # Raw IPv6 — bracket it
            return f"[{self.address}]:{self.port}" if self.port else self.address
        return f"{self.address}:{self.port}" if self.port else self.address

    def is_loopback(self) -> bool:
        return self.address in ("127.0.0.1", "::1", "localhost")

    def is_private(self) -> bool:
        try:
            return ipaddress.ip_address(self.address).is_private
        except ValueError:
            return False


@dataclass
class StreamInfo:
    network:  str = "tcp"
    security: str = "none"

    # Security layer payloads (raw dicts from config)
    tls:     dict = field(default_factory=dict)
    reality: dict = field(default_factory=dict)

    # Transport payloads
    tcp:     dict = field(default_factory=dict)
    ws:      dict = field(default_factory=dict)
    grpc:    dict = field(default_factory=dict)
    http:    dict = field(default_factory=dict)   # also covers H2 / httpupgrade
    xhttp:   dict = field(default_factory=dict)   # xhttp / splithttp
    quic:    dict = field(default_factory=dict)
    kcp:     dict = field(default_factory=dict)

    # Misc
    sockopt: dict = field(default_factory=dict)
    extra:   dict = field(default_factory=dict)   # unknown keys preserved

    # ── Derived properties ────────────────────────────────────────────────────

    @property
    def sni(self) -> str:
        return (self.tls.get("serverName", "")
                or self.reality.get("serverName", ""))

    @property
    def fingerprint(self) -> str:
        return (self.tls.get("fingerprint", "")
                or self.reality.get("fingerprint", ""))

    @property
    def alpn(self) -> list[str]:
        return self.tls.get("alpn", []) or []

    @property
    def ws_host(self) -> str:
        return ((self.ws.get("headers") or {}).get("Host", "")
                or self.ws.get("host", ""))

    @property
    def ws_path(self) -> str:
        return self.ws.get("path", "")

    @property
    def grpc_service(self) -> str:
        names = self.grpc.get("serviceNames")
        if names and isinstance(names, list):
            return names[0]
        return self.grpc.get("serviceName", "")

    @property
    def reality_public_key(self) -> str:
        return self.reality.get("publicKey", "")

    @property
    def reality_short_id(self) -> str:
        return self.reality.get("shortId", "")

    def summary(self) -> str:
        parts = [self.network]
        if self.security not in ("none", ""):
            parts.append(self.security)
        if self.sni:
            parts.append(f"sni={self.sni}")
        if self.fingerprint:
            parts.append(f"fp={self.fingerprint}")
        if self.ws_path:
            parts.append(f"path={self.ws_path}")
        if self.grpc_service:
            parts.append(f"svc={self.grpc_service}")
        if self.alpn:
            parts.append(f"alpn={','.join(self.alpn)}")
        if self.reality_short_id:
            parts.append(f"sid={self.reality_short_id}")
        return "+".join(parts)

    def to_dict(self) -> dict:
        return {
            "network":      self.network,
            "security":     self.security,
            "sni":          self.sni,
            "fingerprint":  self.fingerprint,
            "alpn":         self.alpn,
            "ws_host":      self.ws_host,
            "ws_path":      self.ws_path,
            "grpc_service": self.grpc_service,
            "reality_pk":   self.reality_public_key,
            "reality_sid":  self.reality_short_id,
            "tls":          self.tls,
            "reality":      self.reality,
            "extra":        self.extra,
        }


@dataclass
class OutboundInfo:
    tag:             str        = ""
    protocol:        Protocol   = Protocol.UNKNOWN
    servers:         list       = field(default_factory=list)  # list[ServerEndpoint]
    stream:          StreamInfo = field(default_factory=StreamInfo)
    mux:             dict       = field(default_factory=dict)
    users:           list       = field(default_factory=list)  # list[dict]

    # Special outbound flags
    is_direct:       bool = False   # freedom
    is_block:        bool = False   # blackhole
    is_loopback:     bool = False   # loopback
    loopback_target: str  = ""      # inboundTag pointed to

    send_through:    str  = ""      # bind address override

    # Preserved raw data for anything we don't explicitly model
    raw_settings:  dict = field(default_factory=dict)
    raw_outbound:  dict = field(default_factory=dict)
    parse_errors:  list = field(default_factory=list)  # list[str]

    # ── Accessors ─────────────────────────────────────────────────────────────

    @property
    def primary(self) -> Optional[ServerEndpoint]:
        return self.servers[0] if self.servers else None

    @property
    def address(self) -> str:
        return self.primary.address if self.primary else ""

    @property
    def port(self) -> int:
        return self.primary.port if self.primary else 0

    @property
    def all_addresses(self) -> list[str]:
        return [s.address for s in self.servers]

    def matches_address(self, pattern: str) -> bool:
        return any(match_address(s.address, pattern) for s in self.servers)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self, include_raw: bool = False) -> dict:
        d: dict = {
            "tag":             self.tag,
            "protocol":        self.protocol.value,
            "servers":         [str(s) for s in self.servers],
            "stream":          self.stream.to_dict(),
            "mux_enabled":     bool(self.mux.get("enabled")) if self.mux else False,
            "users_count":     len(self.users),
            "is_direct":       self.is_direct,
            "is_block":        self.is_block,
            "is_loopback":     self.is_loopback,
            "loopback_target": self.loopback_target,
            "send_through":    self.send_through,
            "parse_errors":    self.parse_errors,
        }
        if include_raw:
            d["raw_settings"] = self.raw_settings
            d["raw_outbound"] = self.raw_outbound
        return d

    def __repr__(self) -> str:
        srv = ""
        if self.servers:
            srv = " → " + ", ".join(str(s) for s in self.servers)
        elif self.is_loopback:
            srv = f" → loopback:{self.loopback_target}"
        elif self.is_direct:
            srv = " → direct"
        elif self.is_block:
            srv = " → block"
        err = f" ⚠{len(self.parse_errors)}" if self.parse_errors else ""
        return f"<Outbound [{self.protocol.value}] {self.tag!r}{srv} [{self.stream.summary()}]{err}>"


# ══════════════════════════════════════════════════════════════════════════════
#  Subscription Metadata  (from Subscription-UserInfo response header)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SubscriptionMeta:
    """
    Parsed values from the  Subscription-UserInfo  HTTP response header.
    Example header:  upload=1234; download=5678; total=10737418240; expire=1735689600
    """
    upload:   int = 0    # bytes uploaded
    download: int = 0    # bytes downloaded
    total:    int = 0    # quota in bytes (0 = unlimited / not reported)
    expire:   int = 0    # Unix timestamp of expiry (0 = not reported)
    source:   str = ""   # URL this subscription came from

    @classmethod
    def from_header(cls, header: str, source: str = "") -> "SubscriptionMeta":
        m = cls(source=source)
        for kv in header.split(";"):
            kv = kv.strip()
            if "=" not in kv:
                continue
            k, _, v = kv.partition("=")
            k = k.strip().lower()
            v = v.strip()
            if k == "upload":
                m.upload = _safe_int(v)
            elif k == "download":
                m.download = _safe_int(v)
            elif k == "total":
                m.total = _safe_int(v)
            elif k == "expire":
                m.expire = _safe_int(v)
        return m

    def used_gb(self) -> float:
        return (self.upload + self.download) / 1024 ** 3

    def remaining_gb(self) -> float:
        if not self.total:
            return float("inf")
        return max(0.0, (self.total - self.upload - self.download) / 1024 ** 3)

    def __str__(self) -> str:
        if not self.total and not self.expire:
            return "(no quota info)"
        parts: list[str] = []
        if self.total:
            parts.append(
                f"used={self.used_gb():.2f}GB / {self.total / 1024**3:.2f}GB "
                f"(rem={self.remaining_gb():.2f}GB)"
            )
        if self.expire:
            import datetime
            exp = datetime.datetime.fromtimestamp(self.expire).strftime("%Y-%m-%d")
            parts.append(f"expires={exp}")
        return "  ".join(parts) or "(no quota info)"


# ══════════════════════════════════════════════════════════════════════════════
#  Address Matching
# ══════════════════════════════════════════════════════════════════════════════

def match_address(address: str, pattern: str) -> bool:
    """
    Match *address* against *pattern*.  Three syntaxes supported:

      Exact / glob   "1.2.3.4", "*.example.com", "10.0.*"
      CIDR           "10.0.0.0/8", "2001:db8::/32"
      Regex          "/^cdn\\d+\\.example\\.com$/"   (wrap in forward-slashes)
    """
    if not address or not pattern:
        return False
    pattern = pattern.strip()

    # ── Regex (/pattern/)
    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        try:
            return bool(re.search(pattern[1:-1], address, re.IGNORECASE))
        except re.error:
            return False

    # ── CIDR (/prefix notation)
    if re.search(r"/\d+$", pattern):
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            ip  = ipaddress.ip_address(address)
            return ip in net
        except ValueError:
            pass   # fall through to glob

    # ── Glob (case-insensitive)
    return fnmatch(address.lower(), pattern.lower())


# ══════════════════════════════════════════════════════════════════════════════
#  Stream-settings Key Mappings
# ══════════════════════════════════════════════════════════════════════════════

# network name → (canonical settings key, StreamInfo attribute)
_NETWORK_SETTINGS: dict[str, tuple[str, str]] = {
    "tcp":         ("tcpSettings",          "tcp"),
    "ws":          ("wsSettings",           "ws"),
    "websocket":   ("wsSettings",           "ws"),
    "grpc":        ("grpcSettings",         "grpc"),
    "gun":         ("grpcSettings",         "grpc"),
    "http":        ("httpSettings",         "http"),
    "h2":          ("httpSettings",         "http"),
    "httpupgrade": ("httpupgradeSettings",  "http"),
    "xhttp":       ("xhttpSettings",        "xhttp"),
    "splithttp":   ("splithttpSettings",    "xhttp"),
    "quic":        ("quicSettings",         "quic"),
    "kcp":         ("kcpSettings",          "kcp"),
    "mkcp":        ("kcpSettings",          "kcp"),
    "hysteria": ("hysteriaSettings", "http"),
}

_KNOWN_STREAM_KEYS: frozenset[str] = frozenset({
    "network", "security",
    "tlsSettings", "tls",
    "realitySettings", "reality",
    "sockopt",
} | {k for k, _ in _NETWORK_SETTINGS.values()}
  | {n + "Settings" for n in _NETWORK_SETTINGS})


# ══════════════════════════════════════════════════════════════════════════════
#  Utility Functions
# ══════════════════════════════════════════════════════════════════════════════

def _safe_dict(d: dict, key: str) -> dict:
    v = d.get(key)
    return v if isinstance(v, dict) else {}

def _safe_list(d: dict, key: str) -> list:
    v = d.get(key)
    return v if isinstance(v, list) else []

def _safe_int(val, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default

def _ensure_list(val) -> list:
    if isinstance(val, list):
        return val
    if val is None:
        return []
    return [val]

def _parse_hostport(s: str) -> ServerEndpoint:
    """Parse 'host:port' or '[ipv6]:port'."""
    s = s.strip()
    m = re.fullmatch(r"\[(.+)\]:(\d+)", s)          # [::1]:443
    if m:
        return ServerEndpoint(m.group(1), int(m.group(2)))
    if ":" in s:
        host, _, port_str = s.rpartition(":")
        try:
            return ServerEndpoint(host.strip("[]"), int(port_str))
        except ValueError:
            pass
    return ServerEndpoint(s, 0)


# ══════════════════════════════════════════════════════════════════════════════
#  Subscription: HTTP Fetcher
# ══════════════════════════════════════════════════════════════════════════════

class SubscriptionFetcher:
    """
    Fetches a VPN subscription URL while emulating an Android VPN client.

    Supported server response formats (auto-detected):
      • Base64-encoded proxy URI list   — most common
      • Plain proxy URI list            — one URI per line
      • Xray JSON config                — outbounds[] with "protocol" key
      • SingBox JSON config             — outbounds[] with "type"+"server" keys
    """

    DEFAULT_TIMEOUT = 15

    def __init__(
        self,
        user_agent: str = SUBSCRIPTION_USER_AGENTS["happ"],
        timeout: int = DEFAULT_TIMEOUT,
        insecure: bool = False,
    ):
        self.user_agent = user_agent
        self.timeout    = timeout
        self.insecure   = insecure
        self.last_meta: Optional[SubscriptionMeta] = None

    _RETRY_UA: list[str] = [
        "v2rayNG/1.8.19",
        "v2rayN/6.47",
        "v2raytun/android",
        "Happ/3.22.1/Android/17800541067281831514",
        "clash-verge/1.6.6",
        "sing-box/1.9.0",
    ]

    def fetch(self, url: str) -> bytes:
        """
        GET *url* и вернуть тело ответа.
        При HTTP 5xx автоматически перебирает UA из _RETRY_UA.
        Сохраняет итоговый успешный UA в self.used_ua.
        """
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

        # Очередь UA: сначала заданный пользователем, потом остальные без дублей
        ua_queue = [self.user_agent] + [
            ua for ua in self._RETRY_UA if ua != self.user_agent
        ]

        last_exc: Exception = ConnectionError("No UA tried")

        for ua in ua_queue:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent":      ua,
                    "Accept":          "application/json, text/plain, */*",
                    "Accept-Encoding": "gzip, deflate, identity",
                    "Connection":      "close",
                },
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self.timeout, context=ctx
                ) as resp:
                    # Только 5xx считаем «попробуй другой UA»
                    raw = resp.read()

                    enc = (resp.getheader("Content-Encoding") or "").lower()
                    if "gzip" in enc:
                        try:
                            raw = gzip.decompress(raw)
                        except Exception:
                            pass

                    ui_hdr = resp.getheader("Subscription-UserInfo") or ""
                    if ui_hdr:
                        self.last_meta = SubscriptionMeta.from_header(
                            ui_hdr, source=url
                        )

                    self.used_ua = ua   # запомнить успешный UA
                    return raw

            except urllib.error.HTTPError as exc:
                if exc.code >= 500:
                    # Сервер отверг этот UA — пробуем следующий
                    last_exc = ConnectionError(
                        f"HTTP {exc.code} с UA {ua!r}: {exc.reason}"
                    )
                    continue
                # 4xx — смысла перебирать UA нет
                raise ConnectionError(
                    f"HTTP {exc.code} fetching {url!r}: {exc.reason}"
                ) from exc
            except urllib.error.URLError as exc:
                raise ConnectionError(
                    f"Failed to fetch {url!r}: {exc.reason}"
                ) from exc

        raise last_exc


# ══════════════════════════════════════════════════════════════════════════════
#  Subscription: Format Detection
# ══════════════════════════════════════════════════════════════════════════════

def _b64_flexible(data: bytes) -> Optional[bytes]:
    """
    Try to base64-decode *data*, auto-fixing missing padding.
    Tries both standard (+/) and URL-safe (-_) alphabets.
    Returns decoded bytes on success, None on failure.
    """
    data = data.strip()
    for pad in (b"", b"=", b"==", b"==="):
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return fn(data + pad)
            except Exception:
                pass
    return None


def _has_proxy_uris(text: str) -> bool:
    """Return True if *text* contains at least one recognisable proxy URI line."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "://" in line and line.split("://", 1)[0].lower() in _PROXY_URI_SCHEMES:
            return True
    return False


def _detect_sub_format(text: str) -> str:
    stripped = text.strip()

    if stripped.startswith("{") or stripped.startswith("["):  # ← добавить "["
        try:
            obj = json.loads(stripped)

            if isinstance(obj, list):
                if obj and isinstance(obj[0], dict) and (
                        "outbounds" in obj[0] or "inbounds" in obj[0] or "routing" in obj[0]
                ):
                    return "xray_json_array"

            if isinstance(obj, dict):
                obs = obj.get("outbounds")
                if isinstance(obs, list) and obs:
                    first = obs[0]
                    if isinstance(first, dict):
                        if "server" in first and "type" in first and "protocol" not in first:
                            return "singbox_json"
                    return "xray_json"
                if "log" in obj or "inbounds" in obj or "routing" in obj:
                    return "xray_json"
        except json.JSONDecodeError:
            pass

    # Clash YAML signature
    if stripped.startswith("proxies:") or "\nproxies:" in stripped[:2048]:
        return "clash_yaml"

    # Plain URI list
    if _has_proxy_uris(stripped):
        return "uri_list"

    return "unknown"


# ══════════════════════════════════════════════════════════════════════════════
#  Subscription: URI Parsers  (VLESS / VMess / Trojan / SS / Hy2 / Hysteria)
# ══════════════════════════════════════════════════════════════════════════════

def _p1(params: dict, key: str, default: str = "") -> str:
    """Get the first value of *key* from a parse_qs-style dict."""
    vals = params.get(key)
    return vals[0] if vals else default


def _stream_from_uri_params(params: dict) -> StreamInfo:
    """
    Build a StreamInfo from VLESS/Trojan-style query parameters.

    Standard params:
      type=tcp|ws|grpc|h2|xhttp|splithttp|quic|kcp
      security=none|tls|reality|xtls
      host=<WS/H2 host header>
      path=<WS/H2/xHTTP path>
      sni=<TLS SNI>
      fp=<uTLS fingerprint>
      alpn=<comma-separated>
      flow=xtls-rprx-vision
      pbk=<REALITY public key>
      sid=<REALITY short ID>
      spx=<REALITY spiderX>
      serviceName=<gRPC service name>
      mode=gun|multi   (gRPC)
    """
    s = StreamInfo()

    net_raw = _p1(params, "type", "tcp").lower()
    net_aliases = {
        "websocket": "ws",
        "h2":        "http",
        "gun":       "grpc",
        "splithttp": "xhttp",
    }
    s.network = net_aliases.get(net_raw, net_raw)

    security = _p1(params, "security", "none").lower()
    s.security = security

    sni      = _p1(params, "sni")
    fp       = _p1(params, "fp")
    alpn_raw = _p1(params, "alpn")
    alpn     = [a for a in alpn_raw.split(",") if a] if alpn_raw else []

    if security in ("tls", "xtls"):
        s.tls = {"serverName": sni, "fingerprint": fp, "alpn": alpn}
    elif security == "reality":
        s.reality = {
            "serverName":  sni,
            "fingerprint": fp,
            "publicKey":   _p1(params, "pbk"),
            "shortId":     _p1(params, "sid"),
            "spiderX":     _p1(params, "spx"),
        }

    host = _p1(params, "host")
    path = _p1(params, "path", "/")
    net  = s.network

    if net == "ws":
        s.ws = {
            "path":    path,
            "headers": {"Host": host} if host else {},
        }
    elif net in ("http", "h2"):
        s.http = {
            "host": [host] if host else [],
            "path": path,
        }
    elif net == "grpc":
        svc  = _p1(params, "serviceName") or path or ""
        mode = _p1(params, "mode", "gun")
        s.grpc = {"serviceName": svc, "multiMode": mode == "multi"}
    elif net in ("xhttp", "splithttp"):
        s.xhttp = {"path": path, "host": host}

    return s


def _parse_vmess_uri(raw: str) -> Optional[OutboundInfo]:
    """
    Parse  vmess://BASE64_JSON  URI.

    The base64 encodes a JSON object (VMess V2 share link format) with fields:
      ps   — profile name
      add  — server address
      port — server port
      id   — UUID
      aid  — alterId
      scy  — encryption (auto/none/aes-128-gcm/…)
      net  — network (tcp/ws/grpc/h2/quic/kcp)
      type — header obfuscation type (none/http/…)
      host — WS host / H2 host
      path — WS/H2/gRPC path
      tls  — security ("tls" | "")
      sni  — TLS SNI
      alpn — comma-separated ALPN
      fp   — uTLS fingerprint
    """
    b64 = raw[len("vmess://"):]
    decoded = _b64_flexible(b64.encode("ascii", errors="ignore"))
    if decoded is None:
        return None
    try:
        obj = json.loads(decoded.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    info          = OutboundInfo()
    info.protocol = Protocol.VMESS
    info.tag      = str(obj.get("ps") or obj.get("name") or "vmess").strip()

    addr = str(obj.get("add") or "")
    port = _safe_int(obj.get("port"), 0)
    if addr:
        info.servers.append(ServerEndpoint(addr, port))

    uuid   = str(obj.get("id") or "")
    alt_id = _safe_int(obj.get("aid"), 0)
    enc    = str(obj.get("scy") or obj.get("security") or "auto")
    info.users.append({"id": uuid, "alterId": alt_id, "security": enc})

    # ── Stream ──
    s = StreamInfo()
    net_raw    = str(obj.get("net") or "tcp").lower()
    net_aliases = {"websocket": "ws", "h2": "http", "gun": "grpc",
                   "splithttp": "xhttp"}
    s.network  = net_aliases.get(net_raw, net_raw)

    tls_raw    = str(obj.get("tls") or "").lower()
    s.security = tls_raw if tls_raw in ("tls", "reality", "xtls") else "none"

    sni      = str(obj.get("sni") or "")
    fp       = str(obj.get("fp")  or "")
    alpn_raw = str(obj.get("alpn") or "")
    alpn     = [a for a in alpn_raw.split(",") if a] if alpn_raw else []

    if s.security in ("tls", "xtls"):
        s.tls = {"serverName": sni, "fingerprint": fp, "alpn": alpn}

    host = str(obj.get("host") or "")
    path = str(obj.get("path") or "/")
    net  = s.network

    if net == "ws":
        s.ws = {"path": path, "headers": {"Host": host} if host else {}}
    elif net in ("http", "h2"):
        s.http = {"host": [host] if host else [], "path": path}
    elif net == "grpc":
        # In VMess V2 links the "path" field carries the gRPC service name
        s.grpc = {"serviceName": path or host}

    info.stream = s
    return info


def _parse_vless_uri(raw: str) -> Optional[OutboundInfo]:
    """Parse  vless://UUID@HOST:PORT?params#name  URI."""
    try:
        body = raw[len("vless://"):]

        frag = ""
        if "#" in body:
            body, frag = body.rsplit("#", 1)
            frag = urllib.parse.unquote(frag).strip()

        qs = ""
        if "?" in body:
            body, qs = body.split("?", 1)
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)

        at_idx   = body.index("@")
        uuid     = urllib.parse.unquote(body[:at_idx])
        hostport = body[at_idx + 1:]
        ep       = _parse_hostport(hostport)

        info            = OutboundInfo()
        info.protocol   = Protocol.VLESS
        info.tag        = frag or f"vless-{ep.address}"
        info.servers.append(ep)

        flow = _p1(params, "flow")
        info.users.append({"id": uuid, "encryption": "none", "flow": flow})
        info.stream = _stream_from_uri_params(params)
        return info
    except Exception:
        return None


def _parse_trojan_uri(raw: str) -> Optional[OutboundInfo]:
    """Parse  trojan://PASSWORD@HOST:PORT?params#name  URI."""
    try:
        body = raw[len("trojan://"):]

        frag = ""
        if "#" in body:
            body, frag = body.rsplit("#", 1)
            frag = urllib.parse.unquote(frag).strip()

        qs = ""
        if "?" in body:
            body, qs = body.split("?", 1)
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)

        at_idx   = body.index("@")
        password = urllib.parse.unquote(body[:at_idx])
        hostport = body[at_idx + 1:]
        ep       = _parse_hostport(hostport)

        info            = OutboundInfo()
        info.protocol   = Protocol.TROJAN
        info.tag        = frag or f"trojan-{ep.address}"
        info.servers.append(ep)
        info.users.append({"password": password})
        info.stream = _stream_from_uri_params(params)
        return info
    except Exception:
        return None


def _parse_ss_uri(raw: str) -> Optional[OutboundInfo]:
    """
    Parse Shadowsocks URI in either of two formats.

    SIP002:  ss://BASE64(method:password)@HOST:PORT?plugin=...#name
    Legacy:  ss://BASE64(method:password@HOST:PORT)#name
             ss://method:password@HOST:PORT#name   (plain, no base64)
    """
    try:
        body = raw[len("ss://"):]

        frag = ""
        if "#" in body:
            body, frag = body.rsplit("#", 1)
            frag = urllib.parse.unquote(frag).strip()

        info            = OutboundInfo()
        info.protocol   = Protocol.SHADOWSOCKS

        if "@" in body:
            # ── SIP002 / plain  ss://[BASE64(method:pass)|method:pass]@host:port
            qs = ""
            if "?" in body:
                body, qs = body.split("?", 1)

            at_idx   = body.rindex("@")
            user_part = body[:at_idx]
            hostport  = body[at_idx + 1:]

            # user_part might be raw base64 or plain "method:password"
            decoded = _b64_flexible(user_part.encode("ascii", errors="ignore"))
            if decoded is not None:
                try:
                    method_pwd = decoded.decode("utf-8", errors="replace")
                except Exception:
                    method_pwd = user_part
            else:
                method_pwd = urllib.parse.unquote(user_part)

            if ":" in method_pwd:
                method, _, password = method_pwd.partition(":")
            else:
                method, password = "aes-256-gcm", method_pwd

            ep = _parse_hostport(hostport)
            info.tag = frag or f"ss-{ep.address}"
            info.servers.append(ep)
            info.users.append({"method": method.strip(), "password": password.strip()})

        else:
            # ── Legacy  ss://BASE64(method:pass@host:port)
            decoded = _b64_flexible(body.encode("ascii", errors="ignore"))
            if decoded is None:
                return None
            inner = decoded.decode("utf-8", errors="replace")

            if "@" not in inner:
                return None
            method_pwd, _, hostport = inner.rpartition("@")

            if ":" not in method_pwd:
                return None
            method, _, password = method_pwd.partition(":")

            ep = _parse_hostport(hostport.strip())
            info.tag = frag or f"ss-{ep.address}"
            info.servers.append(ep)
            info.users.append({"method": method.strip(), "password": password.strip()})

        return info
    except Exception:
        return None


def _parse_hy2_uri(raw: str) -> Optional[OutboundInfo]:
    """Parse  hysteria2://  or  hy2://  URI."""
    try:
        scheme = raw.split("://", 1)[0] + "://"
        body   = raw[len(scheme):]

        frag = ""
        if "#" in body:
            body, frag = body.rsplit("#", 1)
            frag = urllib.parse.unquote(frag).strip()

        qs = ""
        if "?" in body:
            body, qs = body.split("?", 1)
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)

        at_idx   = body.index("@")
        password = urllib.parse.unquote(body[:at_idx])
        hostport = body[at_idx + 1:]
        ep       = _parse_hostport(hostport)

        info            = OutboundInfo()
        info.protocol   = Protocol.HYSTERIA2
        info.tag        = frag or f"hy2-{ep.address}"
        info.servers.append(ep)
        info.users.append({
            "password":      password,
            "obfs":          _p1(params, "obfs"),
            "obfs-password": _p1(params, "obfs-password"),
        })

        s = StreamInfo()
        s.network  = "tcp"
        s.security = "tls"
        sni      = _p1(params, "sni")
        insecure = _p1(params, "insecure", "0") in ("1", "true")
        s.tls    = {"serverName": sni, "allowInsecure": insecure}
        info.stream = s
        return info
    except Exception:
        return None


def _parse_hysteria1_uri(raw: str) -> Optional[OutboundInfo]:
    """Parse  hysteria://  (v1) URI."""
    try:
        body = raw[len("hysteria://"):]

        frag = ""
        if "#" in body:
            body, frag = body.rsplit("#", 1)
            frag = urllib.parse.unquote(frag).strip()

        qs = ""
        if "?" in body:
            body, qs = body.split("?", 1)
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)

        ep = _parse_hostport(body)

        info            = OutboundInfo()
        info.protocol   = Protocol.HYSTERIA
        info.tag        = frag or f"hysteria-{ep.address}"
        info.servers.append(ep)
        info.users.append({
            "auth":      _p1(params, "auth"),
            "obfs":      _p1(params, "obfs"),
            "up_mbps":   _safe_int(_p1(params, "upmbps"),   0),
            "down_mbps": _safe_int(_p1(params, "downmbps"), 0),
        })

        s = StreamInfo()
        s.network  = "udp"
        s.security = "tls"
        sni = _p1(params, "peer") or _p1(params, "sni")
        s.tls = {"serverName": sni}
        info.stream = s
        return info
    except Exception:
        return None


def _parse_uri(raw: str) -> Optional[OutboundInfo]:
    """Dispatch a single proxy URI string to the appropriate parser."""
    raw = raw.strip()
    if not raw or "://" not in raw:
        return None

    scheme = raw.split("://", 1)[0].lower()
    if scheme == "vmess":
        return _parse_vmess_uri(raw)
    if scheme == "vless":
        return _parse_vless_uri(raw)
    if scheme == "trojan":
        return _parse_trojan_uri(raw)
    if scheme in ("ss", "shadowsocks"):
        return _parse_ss_uri(raw)
    if scheme in ("hy2", "hysteria2"):
        return _parse_hy2_uri(raw)
    if scheme == "hysteria":
        return _parse_hysteria1_uri(raw)
    return None  # unsupported scheme — silently skip


def _parse_uri_list(text: str) -> list[OutboundInfo]:
    """Parse a newline-separated list of proxy URIs into OutboundInfo objects."""
    results: list[OutboundInfo] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ob = _parse_uri(line)
        if ob is not None:
            results.append(ob)
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  Subscription: SingBox JSON Parser
# ══════════════════════════════════════════════════════════════════════════════

def _singbox_stream(tls: dict, transport: dict) -> StreamInfo:
    """Convert SingBox  tls  +  transport  dicts to a StreamInfo."""
    s = StreamInfo()

    # Transport type → network
    t_type = str(transport.get("type") or "").lower()
    net_map = {
        "websocket":   "ws",
        "http":        "h2",
        "grpc":        "grpc",
        "httpupgrade": "httpupgrade",
        "xhttp":       "xhttp",
    }
    s.network = net_map.get(t_type, t_type or "tcp")

    # TLS / security
    if tls.get("enabled"):
        reality_cfg = tls.get("reality") or {}
        utls_cfg    = tls.get("utls") or {}
        fp          = utls_cfg.get("fingerprint", "")

        if reality_cfg.get("enabled"):
            s.security = "reality"
            s.reality  = {
                "serverName":  tls.get("server_name", ""),
                "fingerprint": fp,
                "publicKey":   reality_cfg.get("public_key", ""),
                "shortId":     reality_cfg.get("short_id", ""),
            }
        else:
            s.security = "tls"
            alpn = tls.get("alpn") or []
            s.tls = {
                "serverName":  tls.get("server_name", ""),
                "alpn":        alpn if isinstance(alpn, list) else [alpn],
                "fingerprint": fp,
            }
    else:
        s.security = "none"

    # Transport-specific settings
    net = s.network
    if net == "ws":
        s.ws = {
            "path":    transport.get("path", "/"),
            "headers": transport.get("headers") or {},
        }
    elif net == "grpc":
        s.grpc = {"serviceName": transport.get("service_name", "")}
    elif net in ("h2", "http"):
        hosts = transport.get("host") or []
        s.http = {
            "host": hosts if isinstance(hosts, list) else [hosts],
            "path": transport.get("path", "/"),
        }
    elif net in ("xhttp", "httpupgrade"):
        s.xhttp = {
            "path": transport.get("path", "/"),
            "host": transport.get("host", ""),
        }

    return s


def _singbox_outbound_to_info(ob: dict) -> Optional[OutboundInfo]:
    """Convert a single SingBox outbound dict to OutboundInfo. Returns None to skip."""
    sb_type = str(ob.get("type") or "").lower()

    _sb_proto_map: dict[str, Protocol] = {
        "vless":       Protocol.VLESS,
        "vmess":       Protocol.VMESS,
        "trojan":      Protocol.TROJAN,
        "shadowsocks": Protocol.SHADOWSOCKS,
        "ss":          Protocol.SHADOWSOCKS,
        "hysteria2":   Protocol.HYSTERIA2,
        "hy2":         Protocol.HYSTERIA2,
        "hysteria":    Protocol.HYSTERIA,
        "wireguard":   Protocol.WIREGUARD,
        "socks":       Protocol.SOCKS,
        "http":        Protocol.HTTP,
        "direct":      Protocol.FREEDOM,
        "block":       Protocol.BLACKHOLE,
        "dns":         Protocol.DNS,
    }
    proto = _sb_proto_map.get(sb_type)
    if proto is None:
        # selector / urltest / loadbalance etc. — skip
        return None

    info          = OutboundInfo()
    info.protocol = proto
    info.tag      = str(ob.get("tag") or sb_type)

    server = str(ob.get("server") or "")
    port   = _safe_int(ob.get("server_port"), 0)
    if server:
        info.servers.append(ServerEndpoint(server, port))

    # Credentials
    if sb_type in ("vless", "vmess"):
        info.users.append({
            "id":   str(ob.get("uuid") or ""),
            "flow": str(ob.get("flow") or ""),
        })
    elif sb_type == "trojan":
        info.users.append({"password": str(ob.get("password") or "")})
    elif sb_type in ("shadowsocks", "ss"):
        info.users.append({
            "method":   str(ob.get("method") or ""),
            "password": str(ob.get("password") or ""),
        })
    elif sb_type in ("hysteria2", "hy2"):
        info.users.append({"password": str(ob.get("password") or "")})
    elif sb_type == "hysteria":
        info.users.append({
            "auth":      str(ob.get("auth") or ob.get("auth_str") or ""),
            "up_mbps":   _safe_int(ob.get("up_mbps"),   0),
            "down_mbps": _safe_int(ob.get("down_mbps"), 0),
        })
    elif sb_type == "wireguard":
        info.users.append({
            "private_key":    str(ob.get("private_key") or ""),
            "peer_public_key": str(ob.get("peer_public_key") or ""),
        })

    # Stream settings
    tls_obj   = ob.get("tls") or {}
    trans_obj = ob.get("transport") or {}
    if sb_type == "wireguard":
        info.stream = StreamInfo(network="udp", security="none")
    else:
        info.stream = _singbox_stream(tls_obj, trans_obj)

    return info


def _parse_singbox_json(obj: dict) -> list[OutboundInfo]:
    """Extract all proxy outbounds from a SingBox config dict."""
    results: list[OutboundInfo] = []
    for ob in _safe_list(obj, "outbounds"):
        if not isinstance(ob, dict):
            continue
        info = _singbox_outbound_to_info(ob)
        if info is not None and info.protocol.is_proxy:
            results.append(info)
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  Subscription: Tag Deduplication Helper
# ══════════════════════════════════════════════════════════════════════════════

def _dedup_tags(outbounds: list[OutboundInfo]) -> None:
    """Append an index suffix to any duplicate tags, in-place."""
    seen: dict[str, int] = {}
    for ob in outbounds:
        tag = ob.tag
        if tag in seen:
            seen[tag] += 1
            ob.tag = f"{tag}-{seen[tag]}"
        else:
            seen[tag] = 0


# ══════════════════════════════════════════════════════════════════════════════
#  Parser Core
# ══════════════════════════════════════════════════════════════════════════════

class XrayConfigParser:
    """
    Main parser.  Load once, then query via `.collection()`.

    Parameters
    ----------
    strict : bool
        If True, raise ValueError on first parse error.
        If False (default), accumulate errors in `.parse_errors`.
    """

    def __init__(self, strict: bool = False):
        self.strict        = strict
        self.outbounds:    list[OutboundInfo] = []
        self.inbounds:     list[dict]         = []
        self.routing:      dict               = {}
        self.dns:          dict               = {}
        self.log:          dict               = {}
        self.parse_errors: list[str]          = []
        self._raw:         dict               = {}

    # ── Loaders ───────────────────────────────────────────────────────────────

    def load_file(self, path: Union[str, Path]) -> "XrayConfigParser":
        text = Path(path).read_text(encoding="utf-8")
        return self.load_string(text)

    def load_string(self, text: str) -> "XrayConfigParser":
        return self.load_dict(self._parse_json(text))

    def load_dict(self, raw: dict) -> "XrayConfigParser":
        self._raw = raw
        self._parse_top_level()
        return self

    def load_url(
        self,
        url: str,
        user_agent: str = SUBSCRIPTION_USER_AGENTS["happ"],
        timeout: int    = 15,
        insecure: bool  = False,
    ) -> "XrayConfigParser":
        """
        Fetch a VPN subscription URL and parse all profiles into this parser.

        Handles:
          • Base64-encoded proxy URI list  (most common server format)
          • Plain proxy URI list           (one URI per line)
          • Xray client JSON config        (outbounds[].protocol)
          • SingBox JSON config            (outbounds[].type + .server)

        Parameters
        ----------
        url        Subscription URL, e.g. ``https://sub.example.com/abc123``
        user_agent One of the :data:`SUBSCRIPTION_USER_AGENTS` values, or any
                   custom UA string.  Default emulates Happ/Android.
        timeout    HTTP request timeout in seconds.
        insecure   If True, skip TLS certificate verification.

        Raises
        ------
        ConnectionError   On network / HTTP error.
        """
        fetcher   = SubscriptionFetcher(user_agent=user_agent,
                                        timeout=timeout, insecure=insecure)
        raw_bytes = fetcher.fetch(url)
        if fetcher.last_meta:
            self._sub_meta: Optional[SubscriptionMeta] = fetcher.last_meta

        # Decode bytes → text
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = raw_bytes.decode("latin-1")
        text = text.strip()

        # If not obviously JSON or URI list, try base64 decoding the whole body
        if not text.startswith("{") and not _has_proxy_uris(text):
            decoded = _b64_flexible(raw_bytes)
            if decoded is not None:
                try:
                    candidate = decoded.decode("utf-8")
                    # Accept only if it looks like something useful
                    if _has_proxy_uris(candidate) or candidate.strip().startswith("{"):
                        text = candidate.strip()
                except UnicodeDecodeError:
                    pass

        fmt = _detect_sub_format(text)

        if fmt == "xray_json":
            self.load_string(text)

        elif fmt == "singbox_json":
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as exc:
                self._err(f"SingBox JSON parse error: {exc}")
                return self
            new_obs = _parse_singbox_json(obj)
            _dedup_tags(new_obs)
            self.outbounds.extend(new_obs)

        elif fmt == "uri_list":
            new_obs = _parse_uri_list(text)
            _dedup_tags(new_obs)
            self.outbounds.extend(new_obs)

        elif fmt == "clash_yaml":
            self._err(
                f"Subscription from {url!r} uses Clash/Mihomo YAML format, "
                "which is not supported. Convert to Xray or SingBox JSON, "
                "or use a Clash-compatible client."
            )

        elif fmt == "xray_json_array":
            try:
                configs = json.loads(text)
            except json.JSONDecodeError as exc:
                self._err(f"Xray JSON array parse error: {exc}")
                return self
            for i, cfg in enumerate(configs):
                if not isinstance(cfg, dict):
                    continue
                sub_parser = XrayConfigParser(strict=self.strict)
                sub_parser.load_dict(cfg)
                remarks = str(cfg.get("remarks", "") or f"config-{i}")
                for ob in sub_parser.outbounds:
                    ob.tag = f"[{remarks}] {ob.tag}"
                self.outbounds.extend(sub_parser.outbounds)
                self.parse_errors.extend(sub_parser.parse_errors)
            _dedup_tags(self.outbounds)

        else:
            self._err(
                f"Could not detect subscription format from {url!r}. "
                "Response is not valid JSON, a proxy URI list, or base64-encoded content. "
                "Try a different --ua preset."
            )

        return self

    # ── JSON pre-processing ───────────────────────────────────────────────────

    @staticmethod
    def _strip_comments(text: str) -> str:
        # Remove // line comments — but not inside strings or URL-like patterns
        text = re.sub(r'(?<![:"\\])//[^\n]*', "", text)
        # Remove /* … */ block comments
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        return text

    def _parse_json(self, text: str) -> dict:
        text = self._strip_comments(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            self._err(f"JSON parse error: {e}")
            return {}

    # ── Top-level ─────────────────────────────────────────────────────────────

    def _parse_top_level(self):
        r = self._raw
        self.log      = _safe_dict(r, "log")
        self.dns      = _safe_dict(r, "dns")
        self.routing  = _safe_dict(r, "routing")
        self.inbounds = _safe_list(r, "inbounds")

        raw_obs = r.get("outbounds")
        if raw_obs is None:
            self._err("No 'outbounds' key found in config")
            return
        if not isinstance(raw_obs, list):
            self._err(f"'outbounds' must be a list, got {type(raw_obs).__name__}")
            return

        self.outbounds = []
        for idx, ob in enumerate(raw_obs):
            if not isinstance(ob, dict):
                self._err(f"outbound[{idx}] is not a dict — skipped")
                continue
            self.outbounds.append(self._parse_outbound(ob, index=idx))

    # ── Outbound ──────────────────────────────────────────────────────────────

    def _parse_outbound(self, ob: dict, index: int) -> OutboundInfo:
        info = OutboundInfo()
        info.raw_outbound = copy.deepcopy(ob)
        info.tag          = str(ob.get("tag") or f"outbound-{index}")
        info.protocol     = Protocol.parse(str(ob.get("protocol", "")))
        info.send_through = str(ob.get("sendThrough") or ob.get("send_through") or "")
        info.mux          = _safe_dict(ob, "mux")

        if info.protocol == Protocol.UNKNOWN and ob.get("protocol"):
            info.parse_errors.append(f"Unknown protocol: {ob['protocol']!r}")

        settings = ob.get("settings") or {}
        if not isinstance(settings, dict):
            info.parse_errors.append(
                f"'settings' is {type(settings).__name__}, expected dict — ignored"
            )
            settings = {}
        info.raw_settings = copy.deepcopy(settings)

        try:
            self._extract_servers(info, settings)
        except Exception as exc:
            info.parse_errors.append(f"Server extraction failed: {exc}")

        stream_raw = ob.get("streamSettings") or {}
        try:
            info.stream = self._parse_stream(stream_raw)
        except Exception as exc:
            info.parse_errors.append(f"Stream parse failed: {exc}")
            info.stream = StreamInfo()

        return info

    # ── Server Extraction — protocol-specific ─────────────────────────────────

    def _extract_servers(self, info: OutboundInfo, settings: dict):
        p = info.protocol

        if p in (Protocol.VLESS, Protocol.VMESS):
            self._from_vnext(info, settings)

        elif p in (Protocol.TROJAN, Protocol.SHADOWSOCKS,
                   Protocol.SOCKS, Protocol.HTTP):
            self._from_servers_list(info, settings)

        elif p in (Protocol.HYSTERIA2, Protocol.HYSTERIA):
            addr = str(settings.get("address") or settings.get("host") or "")
            port = _safe_int(settings.get("port"), 0)
            if addr:
                info.servers.append(ServerEndpoint(addr, port))
            else:
                self._from_hysteria(info, settings)

        elif p == Protocol.WIREGUARD:
            self._from_wireguard(info, settings)

        elif p == Protocol.LOOPBACK:
            info.is_loopback    = True
            info.loopback_target = str(settings.get("inboundTag", "") or "")

        elif p == Protocol.FREEDOM:
            info.is_direct = True

        elif p == Protocol.BLACKHOLE:
            info.is_block = True

        elif p == Protocol.DNS:
            addr = str(settings.get("address", "") or "")
            port = _safe_int(settings.get("port"), 53)
            if addr:
                info.servers.append(ServerEndpoint(addr, port))

        else:
            # Unknown protocol — best-effort
            self._from_fallback(info, settings)

    def _from_vnext(self, info: OutboundInfo, settings: dict):
        """VLESS / VMess: settings.vnext[]"""
        vnext = settings.get("vnext") or []
        for srv in _ensure_list(vnext):
            if not isinstance(srv, dict):
                continue
            ep = ServerEndpoint(
                address=str(srv.get("address", "") or ""),
                port=_safe_int(srv.get("port"), 0),
            )
            info.servers.append(ep)
            for u in _ensure_list(srv.get("users") or []):
                if isinstance(u, dict):
                    info.users.append(u)

    def _from_servers_list(self, info: OutboundInfo, settings: dict):
        """Trojan / SS / SOCKS / HTTP: settings.servers[]"""
        servers = settings.get("servers") or []
        for srv in _ensure_list(servers):
            if isinstance(srv, str):
                info.servers.append(_parse_hostport(srv))
                continue
            if not isinstance(srv, dict):
                continue
            addr = str(srv.get("address") or srv.get("host") or "")
            port = _safe_int(srv.get("port"), 0)
            info.servers.append(ServerEndpoint(addr, port))

            if pwd := srv.get("password"):
                info.users.append({"password": str(pwd)})
            # SS method
            if method := srv.get("method"):
                if info.users:
                    info.users[-1]["method"] = method
            # nested users/clients arrays
            for key in ("users", "clients"):
                for u in _ensure_list(srv.get(key) or []):
                    if isinstance(u, dict):
                        info.users.append(u)

    def _from_hysteria(self, info: OutboundInfo, settings: dict):
        """
        Hysteria2 / Hysteria.
        Multiple forms supported:
          { servers: [{address, port, password, obfs}] }
          { servers: [{addr: "host:port", password}] }
          { address, port, password }   (flat)
        """
        servers = settings.get("servers") or []
        if _ensure_list(servers):
            for srv in _ensure_list(servers):
                if not isinstance(srv, dict):
                    continue
                # "addr" key used by some generators: "host:port"
                if raw := srv.get("addr"):
                    ep = _parse_hostport(str(raw))
                else:
                    addr = str(srv.get("address") or srv.get("host") or "")
                    port = _safe_int(srv.get("port"), 0)
                    ep   = ServerEndpoint(addr, port)
                info.servers.append(ep)
                if pwd := srv.get("password"):
                    info.users.append({
                        "password": str(pwd),
                        "obfs":     srv.get("obfs", {}),
                    })
        else:
            # Flat form
            addr = str(settings.get("address") or settings.get("host") or "")
            port = _safe_int(settings.get("port"), 0)
            if addr:
                info.servers.append(ServerEndpoint(addr, port))
            if pwd := settings.get("password"):
                info.users.append({"password": str(pwd)})

    def _from_wireguard(self, info: OutboundInfo, settings: dict):
        """WireGuard: settings.peers[].endpoint"""
        peers = settings.get("peers") or []
        for peer in _ensure_list(peers):
            if not isinstance(peer, dict):
                continue
            if ep_str := peer.get("endpoint"):
                info.servers.append(_parse_hostport(str(ep_str)))

    def _from_fallback(self, info: OutboundInfo, settings: dict):
        """Best-effort extraction for completely unknown protocols."""
        # Try VLESS/VMess shape
        if "vnext" in settings:
            self._from_vnext(info, settings)
            return
        # Try Trojan/SS shape
        if "servers" in settings:
            self._from_servers_list(info, settings)
            return
        # Try WireGuard shape
        if "peers" in settings:
            self._from_wireguard(info, settings)
            return
        # Flat address fields
        for key in ("address", "host", "server", "addr", "hostname"):
            if addr := str(settings.get(key, "") or ""):
                port = _safe_int(settings.get("port"), 0)
                info.servers.append(ServerEndpoint(addr, port))
                return

    # ── Stream Settings ───────────────────────────────────────────────────────

    def _parse_stream(self, raw: dict) -> StreamInfo:
        if not isinstance(raw, dict):
            return StreamInfo()

        s = StreamInfo()
        s.network  = str(raw.get("network",  "tcp")  or "tcp").lower()
        s.security = str(raw.get("security", "none") or "none").lower()
        s.sockopt  = _safe_dict(raw, "sockopt")

        # Security-layer settings (two naming conventions)
        s.tls     = (_safe_dict(raw, "tlsSettings")
                     or _safe_dict(raw, "tls"))
        s.reality = (_safe_dict(raw, "realitySettings")
                     or _safe_dict(raw, "reality"))

        # Inherit TLS from REALITY when security == "reality"
        if s.security == "reality" and not s.tls and s.reality:
            # Some exporters put combined settings under tls key
            pass

        # Transport-layer settings
        net = s.network
        if mapping := _NETWORK_SETTINGS.get(net):
            settings_key, attr = mapping
            val = (
                _safe_dict(raw, settings_key)
                or _safe_dict(raw, net + "Settings")
                or _safe_dict(raw, net)
                or {}
            )
            setattr(s, attr, val)

        # Preserve any unrecognised keys verbatim
        s.extra = {k: v for k, v in raw.items() if k not in _KNOWN_STREAM_KEYS}

        return s

    # ── Error handling ────────────────────────────────────────────────────────

    def _err(self, msg: str):
        if self.strict:
            raise ValueError(msg)
        self.parse_errors.append(msg)

    # ── Public API ────────────────────────────────────────────────────────────

    def collection(self, proxies_only: bool = False) -> "OutboundCollection":
        """Return a chainable OutboundCollection over all (or proxy-only) outbounds."""
        items = self.outbounds
        if proxies_only:
            items = [o for o in items if o.protocol.is_proxy]
        return OutboundCollection(items)

    def summary(self) -> str:
        return self.collection().summary(
            title=f"Config — {len(self.outbounds)} outbound(s), "
                  f"{len(self.inbounds)} inbound(s)"
        )

    def __repr__(self) -> str:
        return (f"<XrayConfigParser outbounds={len(self.outbounds)} "
                f"inbounds={len(self.inbounds)} errors={len(self.parse_errors)}>")


# ══════════════════════════════════════════════════════════════════════════════
#  OutboundCollection — chainable filter / sort / group API
# ══════════════════════════════════════════════════════════════════════════════

class OutboundCollection:
    """
    Fluent wrapper for a list of OutboundInfo objects.
    All filter methods return a *new* OutboundCollection, so calls can be chained:

        parser.collection()
               .protocol("vless", "hysteria2")
               .security("reality")
               .sort("address")
               .print_summary()
    """

    def __init__(self, items: list[OutboundInfo]):
        self._items: list[OutboundInfo] = list(items)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    def __repr__(self) -> str:
        return f"OutboundCollection({len(self._items)} items)"

    @property
    def items(self) -> list[OutboundInfo]:
        return list(self._items)

    # ── Filters ───────────────────────────────────────────────────────────────

    def protocol(self, *protos: Union[str, Protocol]) -> "OutboundCollection":
        """Keep outbounds matching any of the given protocols."""
        targets = {Protocol.parse(p) if isinstance(p, str) else p for p in protos}
        return self._wrap(o for o in self._items if o.protocol in targets)

    def exclude_protocol(self, *protos: Union[str, Protocol]) -> "OutboundCollection":
        """Remove outbounds matching the given protocols."""
        targets = {Protocol.parse(p) if isinstance(p, str) else p for p in protos}
        return self._wrap(o for o in self._items if o.protocol not in targets)

    def address(self, *patterns: str) -> "OutboundCollection":
        """Keep outbounds whose server address matches *any* of the patterns.
        Supports glob, CIDR, and /regex/ syntax."""
        return self._wrap(
            o for o in self._items
            if any(o.matches_address(p) for p in patterns)
        )

    def tag(self, *patterns: str) -> "OutboundCollection":
        """Filter by tag (glob / /regex/)."""
        return self._wrap(
            o for o in self._items
            if any(match_address(o.tag, p) for p in patterns)
        )

    def network(self, *nets: str) -> "OutboundCollection":
        """Filter by transport network: tcp, ws, grpc, xhttp, quic, kcp…"""
        target = {n.lower() for n in nets}
        # Accept aliases
        aliases = {"websocket": "ws", "h2": "http", "gun": "grpc",
                   "splithttp": "xhttp", "mkcp": "kcp"}
        target |= {aliases.get(n, n) for n in target}
        return self._wrap(o for o in self._items if o.stream.network in target)

    def security(self, *secs: str) -> "OutboundCollection":
        """Filter by security layer: none, tls, reality, xtls."""
        target = {s.lower() for s in secs}
        return self._wrap(o for o in self._items if o.stream.security in target)

    def port(self, *ports: int) -> "OutboundCollection":
        """Filter by primary server port."""
        target = set(ports)
        return self._wrap(o for o in self._items if o.port in target)

    def sni(self, *patterns: str) -> "OutboundCollection":
        """Filter by SNI (glob / /regex/)."""
        return self._wrap(
            o for o in self._items
            if any(match_address(o.stream.sni, p) for p in patterns)
        )

    def proxies_only(self) -> "OutboundCollection":
        """Remove freedom / blackhole / loopback / dns outbounds."""
        return self._wrap(o for o in self._items if o.protocol.is_proxy)

    def has_errors(self) -> "OutboundCollection":
        """Keep only outbounds that had parse errors."""
        return self._wrap(o for o in self._items if o.parse_errors)

    def private_addresses(self) -> "OutboundCollection":
        """Keep outbounds pointing to private/loopback addresses."""
        return self._wrap(
            o for o in self._items
            if o.primary and o.primary.is_private()
        )

    # ── Sorting ───────────────────────────────────────────────────────────────

    _SORT_KEYS = {
        "protocol": lambda o: o.protocol.value,
        "address":  lambda o: o.address,
        "port":     lambda o: o.port,
        "tag":      lambda o: o.tag,
        "network":  lambda o: o.stream.network,
        "security": lambda o: o.stream.security,
        "sni":      lambda o: o.stream.sni,
    }

    def sort(self, key: str = "protocol", reverse: bool = False) -> "OutboundCollection":
        """
        Sort by one of: protocol, address, port, tag, network, security, sni.
        """
        fn = self._SORT_KEYS.get(key)
        if fn is None:
            raise ValueError(
                f"Unknown sort key {key!r}. Valid: {list(self._SORT_KEYS)}"
            )
        return OutboundCollection(sorted(self._items, key=fn, reverse=reverse))

    # ── Grouping ──────────────────────────────────────────────────────────────

    _GROUP_KEYS = {
        "protocol": lambda o: o.protocol.value,
        "network":  lambda o: o.stream.network,
        "security": lambda o: o.stream.security,
        "port":     lambda o: str(o.port),
        "sni":      lambda o: o.stream.sni or "(none)",
    }

    def group_by(self, key: str) -> dict[str, "OutboundCollection"]:
        """
        Group by one of: protocol, network, security, port, sni.
        Returns OrderedDict[group_value → OutboundCollection].
        """
        fn = self._GROUP_KEYS.get(key)
        if fn is None:
            raise ValueError(
                f"Unknown group key {key!r}. Valid: {list(self._GROUP_KEYS)}"
            )
        buckets: dict[str, list] = {}
        for o in self._items:
            buckets.setdefault(fn(o), []).append(o)
        return {k: OutboundCollection(v) for k, v in sorted(buckets.items())}

    # ── Output ────────────────────────────────────────────────────────────────

    def to_json(self, indent: int = 2, include_raw: bool = False) -> str:
        return json.dumps(
            [o.to_dict(include_raw=include_raw) for o in self._items],
            indent=indent, ensure_ascii=False,
        )

    def summary(self, title: str = "") -> str:
        lines: list[str] = []
        if title:
            lines += [title, "─" * min(len(title), 80)]

        # Group by protocol for readability
        buckets: dict[str, list] = {}
        for o in self._items:
            buckets.setdefault(o.protocol.value, []).append(o)

        for proto in sorted(buckets):
            obs = buckets[proto]
            lines.append(f"\n[{proto.upper()}]  ({len(obs)})")
            for o in obs:
                # Server string
                if o.servers:
                    srv_str = "  ".join(str(s) for s in o.servers)
                elif o.is_loopback:
                    srv_str = f"loopback → {o.loopback_target}"
                elif o.is_direct:
                    srv_str = "direct"
                elif o.is_block:
                    srv_str = "block"
                else:
                    srv_str = "(no server)"

                stream  = o.stream.summary()
                err_sfx = f"  ⚠ {o.parse_errors}" if o.parse_errors else ""
                lines.append(
                    f"  • {o.tag:<28s}  {srv_str:<40s}  [{stream}]{err_sfx}"
                )

        lines.append(f"\nTotal: {len(self._items)} outbound(s)")
        return "\n".join(lines)

    def print_summary(self, title: str = ""):
        print(self.summary(title=title))

    # ── Internal ──────────────────────────────────────────────────────────────

    def _wrap(self, gen) -> "OutboundCollection":
        return OutboundCollection(list(gen))


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xray_parser",
        description="Parse and filter Xray client configuration outbounds.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples (file):
  %(prog)s config.json
  %(prog)s config.json -p vless,hysteria2
  %(prog)s config.json -a "*.example.com" -a "10.0.0.0/8"
  %(prog)s config.json -a "/cdn[0-9]+\\./"
  %(prog)s config.json -n ws,grpc -s reality
  %(prog)s config.json --group protocol
  %(prog)s config.json --sort address --json
  %(prog)s config.json --port 443 --port 8443

Examples (subscription URL):
  %(prog)s --url https://sub.example.com/abc123
  %(prog)s --url https://sub.example.com/abc123 --ua v2raytun
  %(prog)s --url https://sub.example.com/abc123 -p vless --json
  %(prog)s --url https://sub.example.com/abc123 --insecure
  %(prog)s --url https://sub.example.com/abc123 --ua happ --timeout 30

Supported UA presets: """ + ", ".join(SUBSCRIPTION_USER_AGENTS) + """
""",
    )
    p.add_argument(
        "config", nargs="?", default=None,
        help="Path to Xray JSON config file (optional if --url is used)",
    )

    # Subscription options
    sub = p.add_argument_group("subscription")
    sub.add_argument(
        "--url", "-u", metavar="URL",
        help="Fetch and parse a VPN subscription URL",
    )
    sub.add_argument(
        "--ua", metavar="PRESET",
        default=DEFAULT_SUB_UA,
        help=(
            f"User-agent preset for subscription fetch "
            f"(default: {DEFAULT_SUB_UA!r}). "
            f"Presets: {', '.join(SUBSCRIPTION_USER_AGENTS)}. "
            "Any other value is used as a literal UA string."
        ),
    )
    sub.add_argument(
        "--timeout", metavar="N", type=int, default=15,
        help="HTTP timeout in seconds for subscription fetch (default: 15)",
    )
    sub.add_argument(
        "--insecure", action="store_true",
        help="Skip TLS certificate verification when fetching subscription",
    )

    # Filters
    f = p.add_argument_group("filters")
    f.add_argument("-p", "--protocol", metavar="PROTO",
                   help="Comma-separated protocol list: vless,vmess,trojan,…")
    f.add_argument("-a", "--address", metavar="PATTERN", action="append",
                   help="Address pattern (glob/CIDR//regex/). Repeatable.")
    f.add_argument("-t", "--tag",      metavar="PATTERN",
                   help="Filter by tag pattern")
    f.add_argument("-n", "--network",  metavar="NET",
                   help="Transport(s): tcp,ws,grpc,xhttp,quic,…")
    f.add_argument("-s", "--security", metavar="SEC",
                   help="Security layer(s): none,tls,reality,…")
    f.add_argument("--port", metavar="N", type=int, action="append",
                   help="Filter by port. Repeatable.")
    f.add_argument("--sni", metavar="PATTERN",
                   help="Filter by SNI pattern")
    f.add_argument("--proxies-only", action="store_true",
                   help="Exclude freedom/blackhole/loopback outbounds")
    f.add_argument("--errors", action="store_true",
                   help="Show only outbounds with parse errors")

    # Display
    d = p.add_argument_group("display")
    d.add_argument("--group", metavar="KEY",
                   choices=["protocol", "network", "security", "port", "sni"],
                   help="Group by key")
    d.add_argument("--sort", metavar="KEY",
                   choices=["protocol", "address", "port", "tag",
                             "network", "security", "sni"],
                   help="Sort by key")
    d.add_argument("--reverse", action="store_true", help="Reverse sort")
    d.add_argument("--json",    action="store_true", help="JSON output")
    d.add_argument("--raw",     action="store_true",
                   help="Include raw settings in JSON output")
    d.add_argument("--strict",  action="store_true",
                   help="Raise on first parse error")
    return p


def run_cli(argv: Optional[list[str]] = None):
    args = _build_arg_parser().parse_args(argv)

    if not args.config and not args.url:
        _build_arg_parser().print_usage(sys.stderr)
        print(
            "\nerror: provide a config file path and/or --url <subscription_url>",
            file=sys.stderr,
        )
        sys.exit(1)

    parser = XrayConfigParser(strict=args.strict)

    # ── Load file ────────────────────────────────────────────────────────────
    if args.config:
        try:
            parser.load_file(args.config)
        except FileNotFoundError:
            print(f"Error: file not found: {args.config}", file=sys.stderr)
            sys.exit(1)
        except ValueError as exc:
            print(f"Parse error: {exc}", file=sys.stderr)
            sys.exit(1)

    # ── Load subscription URL ────────────────────────────────────────────────
    if args.url:
        ua = SUBSCRIPTION_USER_AGENTS.get(args.ua, args.ua)
        try:
            parser.load_url(
                args.url,
                user_agent=ua,
                timeout=args.timeout,
                insecure=args.insecure,
            )
        except ConnectionError as exc:
            print(f"Subscription fetch error: {exc}", file=sys.stderr)
            sys.exit(1)
        except Exception as exc:
            print(f"Subscription error: {exc}", file=sys.stderr)
            sys.exit(1)

        meta: Optional[SubscriptionMeta] = getattr(parser, "_sub_meta", None)
        if meta:
            print(f"[sub] {meta}", file=sys.stderr)

    # ── Shared parse-error reporting ─────────────────────────────────────────
    if parser.parse_errors:
        for e in parser.parse_errors:
            print(f"⚠  {e}", file=sys.stderr)

    # ── Filter ───────────────────────────────────────────────────────────────
    c = parser.collection(proxies_only=args.proxies_only)

    if args.protocol:
        c = c.protocol(*[p.strip() for p in args.protocol.split(",")])
    if args.address:
        c = c.address(*args.address)
    if args.tag:
        c = c.tag(args.tag)
    if args.network:
        c = c.network(*[n.strip() for n in args.network.split(",")])
    if args.security:
        c = c.security(*[s.strip() for s in args.security.split(",")])
    if args.port:
        c = c.port(*args.port)
    if args.sni:
        c = c.sni(args.sni)
    if args.errors:
        c = c.has_errors()
    if args.sort:
        c = c.sort(args.sort, reverse=args.reverse)

    # ── Output ───────────────────────────────────────────────────────────────
    if args.json:
        print(c.to_json(include_raw=args.raw))
    elif args.group:
        for key, grp in c.group_by(args.group).items():
            print(grp.summary(title=f"── {args.group.upper()}: {key}"))
    else:
        title = args.url or args.config or "Xray Config"
        print(c.summary(title=f"Xray Config — {title}"))


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_cli()