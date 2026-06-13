"""
services/address_filter.py
==========================
Applies admin-configured address filter rules to the outbound pool.

Flow:
1. Load all active AddressFilterRule rows from DB.
2. For each outbound dict, extract its server address(es).
3. If an address looks like a domain (not a bare IP), resolve it via DNS
   and collect all resolved IPs.
4. Check the original address AND every resolved IP against each rule.
5. Apply block / allow semantics:
   - block  → outbound is discarded if it matches ANY block rule
   - allow  → if at least one allow rule exists, the outbound must match
              at least one allow rule to survive (whitelist mode)

DNS resolution is async, uses asyncio.get_event_loop().getaddrinfo().
Results are cached for the lifetime of one pool-build to avoid redundant
lookups for the same host.

Error handling: DNS failures are logged as warnings but never raise –
  the unresolved address is still checked against patterns.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AddressFilterRule
from app.parser import match_address

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _is_ip(address: str) -> bool:
    """Return True if *address* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


async def _resolve_domain(host: str) -> list[str]:
    """
    Resolve *host* to a list of IP strings (may be empty on failure).
    Uses the event loop's getaddrinfo so it doesn't block the event loop.
    """
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(host, None)
        ips: list[str] = []
        seen: set[str] = set()
        for _af, _type, _proto, _canon, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
    except Exception as exc:
        logger.debug("DNS resolution failed for %r: %s", host, exc)
        return []


# ---------------------------------------------------------------------------
# Filter state (loaded once per pool-build)
# ---------------------------------------------------------------------------

@dataclass
class _FilterState:
    block_patterns: list[str] = field(default_factory=list)
    allow_patterns: list[str] = field(default_factory=list)

    @property
    def has_allow_rules(self) -> bool:
        return bool(self.allow_patterns)

    def is_blocked(self, candidates: list[str]) -> bool:
        """Return True if any candidate address matches a block rule."""
        return any(
            match_address(addr, pat)
            for addr in candidates
            for pat in self.block_patterns
        )

    def is_allowed(self, candidates: list[str]) -> bool:
        """Return True if any candidate address matches an allow rule."""
        return any(
            match_address(addr, pat)
            for addr in candidates
            for pat in self.allow_patterns
        )


async def _load_filter_state(db: AsyncSession) -> _FilterState:
    result = await db.execute(
        select(AddressFilterRule).where(AddressFilterRule.is_active == True)
    )
    rules = list(result.scalars().all())

    state = _FilterState()
    for rule in rules:
        if rule.action == "block":
            state.block_patterns.append(rule.pattern)
        else:
            state.allow_patterns.append(rule.pattern)

    logger.debug(
        "Loaded %d block rule(s) and %d allow rule(s)",
        len(state.block_patterns), len(state.allow_patterns),
    )
    return state


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _extract_addresses(outbound: dict) -> list[str]:
    """
    Extract all server addresses from a raw xray outbound dict.
    Handles vnext (vless/vmess) and servers (trojan/ss/hy2) shapes.
    """
    addresses: list[str] = []
    settings = outbound.get("settings", {})

    for server in settings.get("vnext", []):
        if addr := server.get("address", "").strip():
            addresses.append(addr)

    for server in settings.get("servers", []):
        if addr := server.get("address", "").strip():
            addresses.append(addr)

    return addresses


async def apply_address_filters(
    db: AsyncSession,
    pool: list[dict],
) -> list[dict]:
    """
    Filter *pool* outbounds using active AddressFilterRule rows from the DB.

    Returns a (possibly smaller) list of outbound dicts.
    No-op when there are no active rules.
    """
    state = await _load_filter_state(db)

    if not state.block_patterns and not state.has_allow_rules:
        logger.debug("No active address filter rules – pool unchanged")
        return pool

    # Resolve all unique domain addresses upfront (parallel)
    unique_domains: set[str] = set()
    for ob in pool:
        for addr in _extract_addresses(ob):
            if not _is_ip(addr):
                unique_domains.add(addr.lower())

    resolve_tasks = {domain: _resolve_domain(domain) for domain in unique_domains}
    resolved: dict[str, list[str]] = {}
    if resolve_tasks:
        results = await asyncio.gather(*resolve_tasks.values(), return_exceptions=True)
        for domain, result in zip(resolve_tasks.keys(), results):
            if isinstance(result, Exception):
                logger.warning("Unexpected error resolving %r: %s", domain, result)
                resolved[domain] = []
            else:
                resolved[domain] = result
            if resolved[domain]:
                logger.debug("Resolved %s → %s", domain, resolved[domain])

    filtered: list[dict] = []
    blocked = 0
    not_allowed = 0

    for ob in pool:
        raw_addresses = _extract_addresses(ob)
        if not raw_addresses:
            # Outbound has no extractable server address – keep it
            filtered.append(ob)
            continue

        # Build the full candidate set: original + resolved IPs
        candidates: list[str] = []
        for addr in raw_addresses:
            candidates.append(addr)
            if not _is_ip(addr):
                candidates.extend(resolved.get(addr.lower(), []))

        # Block check (evaluated first)
        if state.block_patterns and state.is_blocked(candidates):
            logger.debug(
                "Blocked outbound %r (address(es): %s)",
                ob.get("tag"), ", ".join(raw_addresses),
            )
            blocked += 1
            continue

        # Allow check (whitelist – only when allow rules exist)
        if state.has_allow_rules and not state.is_allowed(candidates):
            logger.debug(
                "Not-allowed outbound %r (address(es): %s)",
                ob.get("tag"), ", ".join(raw_addresses),
            )
            not_allowed += 1
            continue

        filtered.append(ob)

    if blocked or not_allowed:
        logger.info(
            "Address filter: %d blocked, %d not in allow-list, %d remaining (of %d)",
            blocked, not_allowed, len(filtered), len(pool),
        )

    return filtered
