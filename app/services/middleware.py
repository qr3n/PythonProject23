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
        _cache_get.pop(token, None)
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
        # If it has inboundTag loop-tag-*, we skip it
        inbound = r.get("inboundTag", [])
        if isinstance(inbound, str): inbound = [inbound]
        if any(tag.startswith("loop-tag-") for tag in inbound):
            continue
        new_rules.append(r)
    config["routing"]["rules"] = new_rules
    
    return config

def inject_outbounds(upstream_json: Union[list[dict], dict], our_outbounds: list[dict]) -> Union[list[dict], dict]:
    if not upstream_json: return upstream_json
    
    # Convert to list for processing
    original_configs = upstream_json if isinstance(upstream_json, list) else [upstream_json]
    if not original_configs: return upstream_json
    
    template = copy.deepcopy(original_configs[0])
    final_configs = []
    
    # Total outbounds we have to inject
    total_to_inject = len(our_outbounds)
    
    # --- PHASE 1: Handle the Main Config (Config 0) ---
    # It has 4 remnawave proxies: top, fb1, fb2, fb3. Capacity left: 1.
    main_config = original_configs[0]
    
    if total_to_inject > 0:
        # 1. Add our first outbound
        first_ob = copy.deepcopy(our_outbounds[0])
        first_ob["tag"] = "proxy-fb4-our"
        main_config["outbounds"].append(first_ob)
        
        # 2. Add loopback-4
        main_config["outbounds"].append({
            "tag": "loopback-4",
            "protocol": "loopback",
            "settings": {"inboundTag": "loop-tag-4"}
        })
        
        # 3. Update proxy-fb3 routing rule to point to a new balancer instead of direct outbound
        # Find rule for loop-tag-3
        for rule in main_config.get("routing", {}).get("rules", []):
            itags = rule.get("inboundTag", [])
            if isinstance(itags, str): itags = [itags]
            if "loop-tag-3" in itags:
                rule.pop("outboundTag", None)
                rule["balancerTag"] = "balancer-fb3"
        
        # 4. Create balancer-fb3
        main_config.get("routing", {}).setdefault("balancers", []).append({
            "tag": "balancer-fb3",
            "selector": ["proxy-fb3"],
            "strategy": {"type": "leastPing"},
            "fallbackTag": "loopback-4"
        })
        
        # 5. Add routing rule for loop-tag-4 -> proxy-fb4-our
        main_config.get("routing", {}).get("rules", []).append({
            "type": "field",
            "inboundTag": ["loop-tag-4"],
            "outboundTag": "proxy-fb4-our"
        })
        
    final_configs.append(main_config)
    
    # --- PHASE 2: Handle Reserve Configs ---
    # Each reserve config has 1 remnawave proxy (top) + up to 4 our outbounds.
    
    idx = 1 # Start from second outbound
    reserve_num = 1
    while idx < total_to_inject:
        res_config = _clean_config_for_reserve(copy.deepcopy(template), f"Резерв {reserve_num}")
        res_routing = res_config.get("routing", {})
        
        # Fill up to 4 slots
        # Chain: balancer-top -> loop-tag-1 -> balancer-custom-1 -> loop-tag-2 -> balancer-custom-2 -> loop-tag-3 -> balancer-custom-3 -> loop-tag-4 -> proxy-custom-4
        
        # Hook balancer-top to start our chain
        for b in res_routing.get("balancers", []):
            if b["tag"] == "balancer-top":
                b["fallbackTag"] = "loopback-1"
        
        # Add loopback-1
        res_config["outbounds"].append({"tag": "loopback-1", "protocol": "loopback", "settings": {"inboundTag": "loop-tag-1"}})
        
        slots_filled = 0
        for s in range(4):
            if idx >= total_to_inject: break
            
            curr_ob = copy.deepcopy(our_outbounds[idx])
            tag = f"proxy-custom-{s+1}"
            curr_ob["tag"] = tag
            res_config["outbounds"].append(curr_ob)
            
            is_last = (s == 3) or (idx + 1 >= total_to_inject)
            
            if not is_last:
                # Need another link in the chain
                next_loop_tag = f"loop-tag-{s+2}"
                next_loopback_tag = f"loopback-{s+2}"
                res_config["outbounds"].append({"tag": next_loopback_tag, "protocol": "loopback", "settings": {"inboundTag": next_loop_tag}})
                
                # Balancer for current custom proxy
                res_routing.setdefault("balancers", []).append({
                    "tag": f"balancer-custom-{s+1}",
                    "selector": [tag],
                    "strategy": {"type": "leastPing"},
                    "fallbackTag": next_loopback_tag
                })
                
                # Rule to connect current loop-tag to this balancer
                res_routing.setdefault("rules", []).append({
                    "type": "field",
                    "inboundTag": [f"loop-tag-{s+1}"],
                    "balancerTag": f"balancer-custom-{s+1}"
                })
            else:
                # End of chain
                res_routing.setdefault("rules", []).append({
                    "type": "field",
                    "inboundTag": [f"loop-tag-{s+1}"],
                    "outboundTag": tag
                })
            
            idx += 1
            slots_filled += 1
            
        final_configs.append(res_config)
        reserve_num += 1

    if settings.debug:
        logger.info("[DEBUG] Pagination complete. Total configs: %d", len(final_configs))
        # logger.info("[DEBUG] Final JSON: %s", json.dumps(final_configs, indent=2))

    return final_configs
