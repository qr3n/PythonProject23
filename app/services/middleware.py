import base64
import json
import logging
import time
import copy
from typing import Optional, AsyncIterator, Union

import asyncpg
import httpx
from fastapi import HTTPException
from app.config import settings

logger = logging.getLogger(__name__)

# Cache for bot headers
_header_cache: dict[str, tuple[Optional[tuple[str, Optional[str]]], float]] = {}

def _cache_get(token: str) -> tuple[bool, Optional[tuple[str, Optional[str]]]]:
    entry = _header_cache.get(token)
    if entry is None:
        return False, None
    value, expires_at = entry
    if time.monotonic() > expires_at:
        _header_cache.pop(token, None)
        return False, None
    return True, value

def _cache_set(token: str, value: Optional[tuple[str, Optional[str]]], ttl: int) -> None:
    _header_cache[token] = (value, time.monotonic() + ttl)

async def resolve_bot_headers(
    rw_pool: asyncpg.Pool,
    bot_pool: asyncpg.Pool,
    token: str
) -> Optional[tuple[str, Optional[str]]]:
    if not rw_pool or not bot_pool:
        return None

    hit, cached = _cache_get(token)
    if hit:
        return cached

    try:
        rw_sql = f'SELECT "uuid"::text FROM {settings.db_schema}.users WHERE short_uuid = $1 LIMIT 1'
        rw_row = await rw_pool.fetchrow(rw_sql, token)
        if rw_row is None:
            _cache_set(token, None, 30)
            return None

        rw_uuid = rw_row["uuid"]

        bot_sql = f"""
            SELECT bi.name, bi.subtitle
            FROM {settings.bot_db_schema}.users u
            JOIN {settings.bot_db_schema}.bot_instances bi ON bi.bot_id = u.bot_id AND bi.is_active = true
            WHERE u.remnawave_uuid = $1 LIMIT 1
        """
        bot_row = await bot_pool.fetchrow(bot_sql, rw_uuid)
        if bot_row is None:
            _cache_set(token, None, 30)
            return None

        bot_name = bot_row["name"]
        bot_subtitle = bot_row["subtitle"] or None

        b64_title = base64.b64encode(bot_name.encode()).decode()
        b64_subtitle = base64.b64encode(bot_subtitle.encode()).decode() if bot_subtitle else None

        result = (b64_title, b64_subtitle)
        _cache_set(token, result, 300)
        return result
    except Exception as exc:
        logger.error("Failed to resolve bot headers for %s: %s", token, exc)
        return None

async def fetch_upstream_config(
    path: str, 
    query: str = "", 
    method: str = "GET", 
    headers: dict = None
) -> tuple[int, dict, bytes]:
    url = f"{settings.subscription_page_url}/{path}"
    if query:
        url += f"?{query}"
    
    _drop = {"host", "content-length", "transfer-encoding", "connection"}
    fwd_headers = {k: v for k, v in (headers or {}).items() if k.lower() not in _drop}
    
    async with httpx.AsyncClient(
        timeout=settings.api_timeout_seconds,
        follow_redirects=True,
        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
    ) as client:
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=fwd_headers,
            )
            return resp.status_code, dict(resp.headers), resp.content
        except Exception as exc:
            logger.error("Failed to fetch upstream config from %s: %s", url, exc)
            raise HTTPException(status_code=502, detail="Upstream error")

def _clean_config_for_reserve(config: dict, name: str):
    """Strips config down to only proxy-top and essentials."""
    config["remarks"] = name
    
    # 1. Outbounds: Keep proxy-top, direct, block. Remove others.
    new_outbounds = []
    for ob in config.get("outbounds", []):
        tag = ob.get("tag", "")
        if tag in ["proxy-top", "direct", "block"] or ob.get("protocol") in ["freedom", "blackhole"]:
            new_outbounds.append(ob)
    config["outbounds"] = new_outbounds

    # 2. Balancers: Keep only balancer-top, remove its fallback
    routing = config.get("routing", {})
    old_balancers = routing.get("balancers", [])
    new_balancers = []
    for b in old_balancers:
        if b.get("tag") == "balancer-top":
            b.pop("fallbackTag", None)
            new_balancers.append(b)
    routing["balancers"] = new_balancers

    # 3. Routing Rules: Remove any loop-tag rules
    new_rules = []
    for r in routing.get("rules", []):
        inbound = r.get("inboundTag", [])
        if isinstance(inbound, str): inbound = [inbound]
        if any(tag.startswith("loop-tag-") for tag in inbound):
            continue
        new_rules.append(r)
    routing["rules"] = new_rules
    
    return config

def _finalize_outbounds(config: dict):
    """Ensures loopbacks and special protocols are at the end of the list."""
    outbounds = config.get("outbounds", [])
    proxies = []
    others = []
    for ob in outbounds:
        if ob.get("protocol") in ["loopback", "freedom", "blackhole"]:
            others.append(ob)
        else:
            proxies.append(ob)
    config["outbounds"] = proxies + others

def _fix_observatory(config: dict):
    """Updates subjectSelector and pingConfig to use reliable Google endpoint."""
    obs = config.get("burstObservatory")
    if not obs:
        return
    
    obs["pingConfig"] = {
        "timeout": "5s",
        "interval": "10s",
        "sampling": 1,
        "httpMethod": "HEAD",
        "destination": "http://www.gstatic.com/generate_204"
    }
    
    proxies = []
    for ob in config.get("outbounds", []):
        protocol = ob.get("protocol")
        tag = ob.get("tag")
        if tag and protocol not in ["loopback", "freedom", "blackhole"]:
            proxies.append(tag)
    obs["subjectSelector"] = proxies

def _prioritize_loop_rules(config: dict):
    """Moves all rules with loop-tag-* inboundTag to the top of the rules list."""
    routing = config.get("routing", {})
    rules = routing.get("rules", [])
    if not rules:
        return
    
    loop_rules = []
    other_rules = []
    
    for r in rules:
        itags = r.get("inboundTag", [])
        if isinstance(itags, str): itags = [itags]
        
        is_loop = any(t.startswith("loop-tag-") for t in itags)
        if is_loop:
            loop_rules.append(r)
        else:
            other_rules.append(r)
            
    routing["rules"] = loop_rules + other_rules

def inject_outbounds(upstream_json: Union[list[dict], dict], our_outbounds: list[dict]) -> Union[list[dict], dict]:
    if not upstream_json: return upstream_json
    
    original_configs = upstream_json if isinstance(upstream_json, list) else [upstream_json]
    if not original_configs: return upstream_json
    
    template = copy.deepcopy(original_configs[0])
    final_configs = []
    total_to_inject = len(our_outbounds)
    
    # --- PHASE 1: Handle the Main Config (Config 0) ---
    main_config = original_configs[0]
    routing = main_config.get("routing", {})
    rules = routing.get("rules", [])
    
    if total_to_inject > 0:
        first_ob = copy.deepcopy(our_outbounds[0])
        first_ob["tag"] = "proxy-fb4-our"
        main_config["outbounds"].append(first_ob)
        
        main_config["outbounds"].append({
            "tag": "loopback-4",
            "protocol": "loopback",
            "settings": {"inboundTag": "loop-tag-4"}
        })
        
        for rule in rules:
            itags = rule.get("inboundTag", [])
            if isinstance(itags, str): itags = [itags]
            if "loop-tag-3" in itags:
                rule.pop("outboundTag", None)
                rule["balancerTag"] = "balancer-fb3"
        
        routing.setdefault("balancers", []).append({
            "tag": "balancer-fb3",
            "selector": ["proxy-fb3"],
            "strategy": {"type": "leastPing"},
            "fallbackTag": "loopback-4"
        })
        
        # Add our new loop rule
        rules.append({
            "type": "field",
            "inboundTag": ["loop-tag-4"],
            "outboundTag": "proxy-fb4-our"
        })
    
    _prioritize_loop_rules(main_config)
    _fix_observatory(main_config)
    _finalize_outbounds(main_config)
    final_configs.append(main_config)
    
    # --- PHASE 2: Handle Reserve Configs ---
    idx = 1
    reserve_num = 1
    while idx < total_to_inject:
        res_config = _clean_config_for_reserve(copy.deepcopy(template), f"🇷🇺 Резерв {reserve_num}")
        res_routing = res_config.get("routing", {})
        res_rules = res_routing.get("rules", [])
        
        for b in res_routing.get("balancers", []):
            if b["tag"] == "balancer-top":
                b["fallbackTag"] = "loopback-1"
        
        res_config["outbounds"].append({"tag": "loopback-1", "protocol": "loopback", "settings": {"inboundTag": "loop-tag-1"}})
        
        for s in range(4):
            if idx >= total_to_inject: break
            
            curr_ob = copy.deepcopy(our_outbounds[idx])
            tag = f"proxy-custom-{s+1}"
            curr_ob["tag"] = tag
            res_config["outbounds"].append(curr_ob)
            
            is_last = (s == 3) or (idx + 1 >= total_to_inject)
            if not is_last:
                next_loop_tag = f"loop-tag-{s+2}"
                next_loopback_tag = f"loopback-{s+2}"
                res_config["outbounds"].append({"tag": next_loopback_tag, "protocol": "loopback", "settings": {"inboundTag": next_loop_tag}})
                
                res_routing.setdefault("balancers", []).append({
                    "tag": f"balancer-custom-{s+1}",
                    "selector": [tag],
                    "strategy": {"type": "leastPing"},
                    "fallbackTag": next_loopback_tag
                })
                
                res_rules.append({
                    "type": "field",
                    "inboundTag": [f"loop-tag-{s+1}"],
                    "balancerTag": f"balancer-custom-{s+1}"
                })
            else:
                res_rules.append({
                    "type": "field",
                    "inboundTag": [f"loop-tag-{s+1}"],
                    "outboundTag": tag
                })
            idx += 1
            
        _prioritize_loop_rules(res_config)
        _fix_observatory(res_config)
        _finalize_outbounds(res_config)
        final_configs.append(res_config)
        reserve_num += 1

    return final_configs
