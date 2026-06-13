"""
services/provider.py
====================
Async provider subscription fetcher.

We replicate the SubscriptionFetcher logic from parser.py using httpx
(async-safe), then feed the raw content into XrayConfigParser for parsing.
The Subscription-UserInfo header is parsed manually to update traffic stats.
"""
from __future__ import annotations

import gzip
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ProviderSubscription
from app.parser import (
    SUBSCRIPTION_USER_AGENTS,
    SubscriptionMeta,
    XrayConfigParser,
    _b64_flexible,
    _detect_sub_format,
    _has_proxy_uris,
    _parse_singbox_json,
    _parse_uri_list,
    _dedup_tags,
)

logger = logging.getLogger(__name__)

_RETRY_UAS: list[str] = [
    SUBSCRIPTION_USER_AGENTS["v2rayng"],
    SUBSCRIPTION_USER_AGENTS["v2rayn"],
    SUBSCRIPTION_USER_AGENTS["v2raytun"],
    SUBSCRIPTION_USER_AGENTS["happ"],
    SUBSCRIPTION_USER_AGENTS["singbox"],
]

FETCH_TIMEOUT = 20  # seconds


async def _fetch_subscription(url: str) -> tuple[bytes, SubscriptionMeta | None]:
    """
    Async fetch of a provider subscription URL.
    Tries multiple User-Agents on 5xx. Returns (body_bytes, meta_or_None).
    """
    meta: SubscriptionMeta | None = None
    last_exc: Exception = RuntimeError("No UA tried")

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=FETCH_TIMEOUT,
        verify=True,
    ) as client:
        for ua in _RETRY_UAS:
            headers = {
                "User-Agent": ua,
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, identity",
                "Connection": "close",
            }
            try:
                resp = await client.get(url, headers=headers)

                if resp.status_code >= 500:
                    last_exc = ConnectionError(
                        f"HTTP {resp.status_code} with UA {ua!r}"
                    )
                    continue

                resp.raise_for_status()

                # Decompress if needed (httpx usually handles this,
                # but provider servers sometimes double-gzip)
                raw = resp.content
                ce = resp.headers.get("content-encoding", "").lower()
                if "gzip" in ce:
                    try:
                        raw = gzip.decompress(raw)
                    except Exception:
                        pass

                # Parse Subscription-UserInfo header
                ui_hdr = resp.headers.get("Subscription-UserInfo", "")
                if ui_hdr:
                    meta = SubscriptionMeta.from_header(ui_hdr, source=url)

                return raw, meta

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code >= 500:
                    last_exc = ConnectionError(
                        f"HTTP {exc.response.status_code}: {exc}"
                    )
                    continue
                raise ConnectionError(f"HTTP error fetching {url!r}: {exc}") from exc
            except httpx.RequestError as exc:
                raise ConnectionError(f"Network error fetching {url!r}: {exc}") from exc

    raise last_exc


def _outbound_info_to_xray_dict(ob: "OutboundInfo") -> dict:
    """
    Reconstruct a minimal xray-compatible outbound dict from a parsed OutboundInfo.

    This is needed when the subscription was a URI list (vless://, vmess://, etc.)
    rather than a native xray JSON config.  In that case OutboundInfo.raw_outbound
    is always empty because the URI parsers never set it — only XrayConfigParser
    does when loading a JSON config.

    The dict produced here matches the xray outbound schema closely enough to be
    used as a proxy outbound in a generated client config.
    """
    import json as _json

    protocol = ob.protocol.value  # e.g. "vless", "vmess", "trojan", …
    s = ob.stream

    # ── streamSettings ────────────────────────────────────────────────────────
    stream: dict = {"network": s.network}

    if s.security and s.security != "none":
        stream["security"] = s.security

    if s.security in ("tls", "xtls") and s.tls:
        tls_obj: dict = {}
        if s.tls.get("serverName"):
            tls_obj["serverName"] = s.tls["serverName"]
        if s.tls.get("fingerprint"):
            tls_obj["fingerprint"] = s.tls["fingerprint"]
        if s.tls.get("alpn"):
            tls_obj["alpn"] = s.tls["alpn"]
        if tls_obj:
            stream["tlsSettings"] = tls_obj

    elif s.security == "reality" and s.reality:
        reality_obj: dict = {}
        if s.reality.get("serverName"):
            reality_obj["serverName"] = s.reality["serverName"]
        if s.reality.get("fingerprint"):
            reality_obj["fingerprint"] = s.reality["fingerprint"]
        if s.reality.get("publicKey"):
            reality_obj["publicKey"] = s.reality["publicKey"]
        if s.reality.get("shortId"):
            reality_obj["shortId"] = s.reality["shortId"]
        if s.reality.get("spiderX"):
            reality_obj["spiderX"] = s.reality["spiderX"]
        if reality_obj:
            stream["realitySettings"] = reality_obj

    net = s.network
    if net == "ws" and s.ws:
        stream["wsSettings"] = s.ws
    elif net in ("http", "h2") and s.http:
        stream["httpSettings"] = s.http
    elif net == "grpc" and s.grpc:
        stream["grpcSettings"] = s.grpc
    elif net in ("xhttp", "splithttp") and s.xhttp:
        stream["xhttpSettings"] = s.xhttp
    elif net == "tcp" and s.tcp:
        stream["tcpSettings"] = s.tcp

    if s.sockopt:
        stream["sockopt"] = s.sockopt

    # ── settings (protocol-specific) ─────────────────────────────────────────
    settings: dict = {}

    if protocol in ("vless", "vmess"):
        vnext_servers = []
        for ep in ob.servers:
            users = []
            for u in ob.users:
                user_dict: dict = {}
                if protocol == "vless":
                    user_dict["id"] = u.get("id", "")
                    user_dict["encryption"] = u.get("encryption", "none")
                    flow = u.get("flow", "")
                    if flow:
                        user_dict["flow"] = flow
                elif protocol == "vmess":
                    user_dict["id"] = u.get("id", "")
                    user_dict["alterId"] = u.get("alterId", 0)
                    user_dict["security"] = u.get("security", "auto")
                users.append(user_dict)
            vnext_servers.append({
                "address": ep.address,
                "port": ep.port,
                "users": users,
            })
        settings["vnext"] = vnext_servers

    elif protocol == "trojan":
        trojan_servers = []
        for ep in ob.servers:
            for u in ob.users:
                trojan_servers.append({
                    "address": ep.address,
                    "port": ep.port,
                    "password": u.get("password", ""),
                })
        settings["servers"] = trojan_servers

    elif protocol == "shadowsocks":
        ss_servers = []
        for ep in ob.servers:
            for u in ob.users:
                ss_servers.append({
                    "address": ep.address,
                    "port": ep.port,
                    "method": u.get("method", "none"),
                    "password": u.get("password", ""),
                })
        settings["servers"] = ss_servers

    elif protocol in ("hysteria2", "hy2"):
        hy_servers = []
        for ep in ob.servers:
            for u in ob.users:
                hy_servers.append({
                    "address": ep.address,
                    "port": ep.port,
                    "password": u.get("password", ""),
                })
        settings["servers"] = hy_servers

    else:
        # Generic fallback: preserve raw_settings if available
        settings = ob.raw_settings or {}

    result: dict = {
        "tag": ob.tag,
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream,
    }
    if ob.mux:
        result["mux"] = ob.mux

    return result


def _parse_raw_content(raw: bytes) -> list[dict]:
    """
    Parse raw subscription bytes into a list of raw xray outbound dicts.
    Uses the parser's internal helpers for format detection and URI parsing,
    then returns xray-compatible outbound dicts (JSON-serialisable).

    For Xray JSON format:  OutboundInfo.raw_outbound is used (set by XrayConfigParser).
    For URI list format:   OutboundInfo.raw_outbound is EMPTY (URI parsers never set it),
                           so we reconstruct the xray dict from the parsed OutboundInfo fields.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    text = text.strip()

    # Try base64 decode if not obviously JSON/URI list
    if not text.startswith("{") and not _has_proxy_uris(text):
        decoded = _b64_flexible(raw)
        if decoded is not None:
            try:
                candidate = decoded.decode("utf-8")
                if _has_proxy_uris(candidate) or candidate.strip().startswith("{"):
                    text = candidate.strip()
            except UnicodeDecodeError:
                pass

    fmt = _detect_sub_format(text)
    parser = XrayConfigParser()

    if fmt == "xray_json":
        parser.load_string(text)
    elif fmt == "singbox_json":
        import json
        try:
            obj = json.loads(text)
            obs = _parse_singbox_json(obj)
            _dedup_tags(obs)
            parser.outbounds.extend(obs)
        except Exception as exc:
            logger.warning("SingBox parse error: %s", exc)
    elif fmt == "uri_list":
        obs = _parse_uri_list(text)
        _dedup_tags(obs)
        parser.outbounds.extend(obs)
    elif fmt in ("xray_json_array",):
        import json
        try:
            configs = json.loads(text)
            for i, cfg in enumerate(configs):
                if not isinstance(cfg, dict):
                    continue
                sub = XrayConfigParser()
                sub.load_dict(cfg)
                remarks = str(cfg.get("remarks", f"config-{i}"))
                for ob in sub.outbounds:
                    ob.tag = f"[{remarks}] {ob.tag}"
                parser.outbounds.extend(sub.outbounds)
        except Exception as exc:
            logger.warning("Xray JSON array parse error: %s", exc)
    else:
        logger.warning("Unknown subscription format, got 0 outbounds")

    result = []
    for ob in parser.collection(proxies_only=True):
        if ob.raw_outbound:
            # Xray JSON source: raw_outbound is already a complete xray outbound dict
            result.append(ob.raw_outbound)
        else:
            # URI list source (vless://, vmess://, trojan://, etc.):
            # raw_outbound is always empty because URI parsers don't set it.
            # Reconstruct a valid xray outbound dict from the parsed OutboundInfo fields.
            try:
                result.append(_outbound_info_to_xray_dict(ob))
            except Exception as exc:
                logger.warning("Failed to reconstruct xray dict for %r: %s", ob.tag, exc)

    return result


async def refresh_provider_sub(
    db: AsyncSession,
    sub: ProviderSubscription,
) -> tuple[int, SubscriptionMeta | None]:
    """
    Fetch provider subscription, parse outbounds, update DB record.
    Returns (outbound_count, meta).
    """
    raw, meta = await _fetch_subscription(sub.url)
    outbounds = _parse_raw_content(raw)

    sub.outbounds_json = outbounds
    sub.last_fetched_at = datetime.now(timezone.utc)

    if meta:
        sub.traffic_used_gb = meta.used_gb()
        if meta.total:
            sub.traffic_total_gb = meta.total / 1024**3
        if meta.expire:
            sub.expires_at = datetime.fromtimestamp(meta.expire, tz=timezone.utc)

    await db.flush()

    logger.info(
        "Refreshed provider sub %s (%s): %d outbounds",
        sub.id, sub.alias, len(outbounds),
    )
    return len(outbounds), meta


async def get_all_active_subs(db: AsyncSession) -> list[ProviderSubscription]:
    result = await db.execute(
        select(ProviderSubscription).where(ProviderSubscription.is_active == True)
    )
    return list(result.scalars().all())
