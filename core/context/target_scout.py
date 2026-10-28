"""M269：活水目标侦察（GitHub 搜索 + 离线种子回退）。

只负责“找候选仓”，不做扫描。在线搜索按 stars / 最近 push / 语言过滤；
无 token 时 GitHub 限流严格，失败就回退到本地种子，并明确标注 source。
"""
from __future__ import annotations

import os
import urllib.parse

try:
    import httpx
except ImportError:                                          # pragma: no cover
    httpx = None

GH_API = "https://api.github.com"

OFFLINE_SEEDS = [
    {"slug": "newbee-ltd/newbee-mall-api", "stars": 1200, "language": "Java"},
    {"slug": "newbee-ltd/newbee-mall", "stars": 4800, "language": "Java"},
    {"slug": "jeecgboot/JeecgBoot", "stars": 42000, "language": "Java"},
    {"slug": "apolloconfig/apollo", "stars": 29000, "language": "Java"},
    {"slug": "xuxueli/xxl-job", "stars": 27000, "language": "Java"},
    {"slug": "YunaiV/ruoyi-vue-pro", "stars": 26000, "language": "Java"},
    {"slug": "elunez/eladmin", "stars": 21000, "language": "Java"},
    {"slug": "macrozheng/mall", "stars": 78000, "language": "Java"},
    {"slug": "ZHENFENG13/My-Blog", "stars": 1800, "language": "Java"},
    {"slug": "linlinjava/litemall", "stars": 19000, "language": "Java"},
]


def _get(url: str, timeout: float = 20.0) -> tuple[bool, dict | None, str]:
    if os.getenv("NEXUS_NO_NETWORK", "").lower() in {"1", "true", "yes"}:
        return False, None, "network_disabled"
    if httpx is None:
        return False, None, "httpx_missing"
    try:
        with httpx.Client(timeout=timeout) as c:
            r = c.get(url, headers={"Accept": "application/vnd.github+json",
                                    "User-Agent": "nexus-audit/1.2"})
        if r.status_code != 200:
            return False, None, f"http_{r.status_code}"
        return True, r.json(), ""
    except Exception as e:                                    # noqa: BLE001
        return False, None, f"{type(e).__name__}: {e}"[:200]


def scout(language: str = "java", min_stars: int = 300,
          max_stars: int = 5000, pushed_since: str = "2026-01-01",
          limit: int = 20, allow_online: bool = True) -> dict:
    q = (f"language:{language} stars:{min_stars}..{max_stars} "
         f"pushed:>{pushed_since} archived:false fork:false")
    url = f"{GH_API}/search/repositories?q={urllib.parse.quote(q)}&sort=updated&per_page={min(limit, 50)}"
    if allow_online:
        ok, data, err = _get(url)
        if ok and isinstance(data, dict):
            items = []
            for it in (data.get("items") or [])[:limit]:
                items.append({
                    "slug": it.get("full_name", ""),
                    "stars": int(it.get("stargazers_count") or 0),
                    "language": it.get("language") or language,
                    "pushed_at": it.get("pushed_at") or "",
                    "description": (it.get("description") or "")[:160],
                    "source": "github_search",
                })
            return {"ok": True, "source": "github_search", "query": q,
                    "items": items, "error": ""}
        fallback = _offline(language, min_stars, max_stars, limit)
        fallback["error"] = err
        return fallback
    return _offline(language, min_stars, max_stars, limit)


def _offline(language: str, min_stars: int, max_stars: int,
             limit: int) -> dict:
    items = [dict(x, pushed_at="", description="offline seed",
                  source="offline_seed")
             for x in OFFLINE_SEEDS
             if x["language"].lower() == language.lower()
             and min_stars <= x["stars"] <= max_stars]
    return {"ok": True, "source": "offline_seed", "query": "",
            "items": items[:limit], "error": ""}
