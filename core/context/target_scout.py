"""M269/M285：活水目标侦察（GitHub 搜索 + 离线种子回退）。

M269 只做“找候选仓”；M285 增加 scout_daily()：

  · 查询窗口：pushed:>={近 N 天} stars:{min}..{max} archived:false fork:false
  · 多语言轮询：java / python / solidity（可传任意语言）
  · 自动剔除 demo / tutorial / ctf / interview 等教学仓
  · 优先保留开启 Issues 的仓（有私密 Security Advisory 的仓同样能走
    advisory 入口，见 live_hunt_report._advisory_url）
  · 无 token 时 GitHub 限流严格，失败就回退到本地种子，并明确标注 source

本模块只负责“找候选仓”，不克隆、不扫描。
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import urllib.parse

try:
    import httpx
except ImportError:                                          # pragma: no cover
    httpx = None

GH_API = "https://api.github.com"
UA = "nexus-audit/1.3"

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
    {"slug": "flask-admin/flask-admin", "stars": 5800, "language": "Python"},
    {"slug": "bottlepy/bottle", "stars": 8500, "language": "Python"},
    {"slug": "OpenZeppelin/openzeppelin-contracts", "stars": 25000,
     "language": "Solidity"},
    {"slug": "Uniswap/v2-core", "stars": 2400, "language": "Solidity"},
    {"slug": "transmissions11/solmate", "stars": 4600, "language": "Solidity"},
]

# 教学/示例仓标记：命中即整仓丢弃。必须按“词”匹配，避免误杀
# democracy / demonstration 这类正常单词。
_TUTORIAL_RE = re.compile(
    r"(?:^|[^a-z0-9])(demo|demos|tutorial|tutorials|ctf|ctfs|interview|"
    r"interviews|awesome|example|examples|sample|samples|boilerplate|"
    r"starter|starters|course|courses|learning|practice|exercise|"
    r"homework|book|books|playground)(?:[^a-z0-9]|$)", re.I)


def is_tutorial(slug: str, description: str = "",
                topics: list[str] | tuple[str, ...] = ()) -> bool:
    """仓库名 / 描述 / topics 命中教学标记即判教学仓。"""
    text = " ".join([slug or "", description or "", " ".join(topics or [])])
    return bool(_TUTORIAL_RE.search(text))


# M293：业务限定词。裸搜 language+pushed 抓回来的大半是驱动/插件/桌面工具，
# 按语言轮询注入一个业务词，把候选拉回“有 Web 路由的业务后台”。
BUSINESS_QUALIFIERS: dict[str, tuple[str, ...]] = {
    "java": ("spring-boot", "admin", "cms", "erp", "crm", "mall"),
    # M298：`panel` 实测只捞到桌面/UI panel（holoviz-panel、nwg-panel、
    # SpiderPanel…），一半扫出 0；换成业务后台词。
    "python": ("fastapi", "django", "flask", "admin", "backend", "cms",
               "saas", "erp"),
    "solidity": ("vault", "staking", "lending", "swap"),
}

# M293/M300：纯工具库/驱动/插件/CLI/桌面/评测框架/开发工具/测试框架，
# 没有业务路由，直接丢。2026-10-31 实盘里 datamodel-code-generator（代码生成器）、
# logfire（日志 SDK）、citrus（测试框架）、spring-tools（IDE 工具）各占掉一个
# 实扫名额 —— 这些词必须在侦察阶段就挡掉，把名额留给真业务后台。
# 注意：IDE 系（ide-/vscode-/intellij-/eclipse-）只认带连字符的前缀，
# 避免把描述里写 “IDE integration” 的业务仓误杀。
_TOOL_LIB_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:(?:driver|drivers|sdk|plugin|plugins|sphinx|cli|desktop|"
    r"eval|evaluat\w*|benchmark|generator|generators|codegen|datamodel|"
    r"telemetry|observability|logfire|spring-tools|citrus|test-framework|"
    r"testing-framework|testcontainers)(?:[^a-z0-9]|$)"
    r"|(?:ide|vscode|intellij|eclipse)-)", re.I)


def is_tool_lib(slug: str, description: str = "",
                topics: list[str] | tuple[str, ...] = ()) -> bool:
    """仓库名/描述/topics 命中工具库标记即丢（M293）。"""
    text = " ".join([slug or "", description or "", " ".join(topics or [])])
    return bool(_TOOL_LIB_RE.search(text))


def next_qualifier(language: str, day_index: int) -> str:
    """按天轮询该语言的业务限定词（同一天结果稳定，逐日轮换）。"""
    qs = BUSINESS_QUALIFIERS.get(str(language).lower()) or ()
    return qs[day_index % len(qs)] if qs else ""


def search_query(language: str, min_stars: int, max_stars: int,
                 pushed_since: str, limit: int = 20,
                 qualifier: str = "") -> str:
    """GitHub Search 限定串（M285 口径 + M293 业务限定词）。"""
    base = (f"language:{language} stars:{min_stars}..{max_stars} "
            f"pushed:>{pushed_since} archived:false fork:false")
    return f"{qualifier} {base}".strip() if qualifier else base


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "User-Agent": UA}
    token = (os.getenv("GITHUB_TOKEN") or os.getenv("NEXUS_GITHUB_TOKEN")
             or os.getenv("GH_TOKEN") or "").strip()
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(url: str, timeout: float = 20.0) -> tuple[bool, dict | None, str]:
    if os.getenv("NEXUS_NO_NETWORK", "").lower() in {"1", "true", "yes"}:
        return False, None, "network_disabled"
    if httpx is None:
        return False, None, "httpx_missing"
    try:
        with httpx.Client(timeout=timeout) as c:
            r = c.get(url, headers=_headers())
        if r.status_code != 200:
            return False, None, f"http_{r.status_code}"
        return True, r.json(), ""
    except Exception as e:                                    # noqa: BLE001
        return False, None, f"{type(e).__name__}: {e}"[:200]


def _offline(language: str, min_stars: int, max_stars: int,
             limit: int) -> dict:
    items = [dict(x, pushed_at="", description="offline seed",
                  has_issues=False, topics=[], channel="advisory",
                  source="offline_seed")
             for x in OFFLINE_SEEDS
             if x["language"].lower() == language.lower()
             and min_stars <= x["stars"] <= max_stars]
    return {"ok": True, "source": "offline_seed", "query": "", "queries": [],
            "items": items[:limit], "dropped": 0, "error": ""}


def _parse_search(payload: dict,
                  language: str) -> tuple[list[dict], int, int]:
    """把 GitHub 搜索响应转成候选项。

    返回 (items, 教学仓剔除数, 工具库剔除数)。
    """
    items: list[dict] = []
    dropped = 0
    dropped_tool = 0
    for it in (payload.get("items") or []):
        slug = it.get("full_name") or ""
        if not slug:
            continue
        desc = (it.get("description") or "")[:200]
        topics = [t for t in (it.get("topics") or []) if isinstance(t, str)]
        if is_tutorial(slug, desc, topics):
            dropped += 1
            continue
        if is_tool_lib(slug, desc, topics):
            dropped_tool += 1
            continue
        has_issues = bool(it.get("has_issues", True))
        items.append({
            "slug": slug,
            "stars": int(it.get("stargazers_count") or 0),
            "language": it.get("language") or language,
            "pushed_at": it.get("pushed_at") or "",
            "description": desc,
            "has_issues": has_issues,
            # 私密 Security Advisory 无法在无鉴权下探测；有 Issues 的仓优先进
            # “issue” 通道，其余仍可走 advisory 入口（手册里两条链接都给）。
            "channel": "issues" if has_issues else "advisory",
            "topics": topics[:10],
            "source": "github_search",
        })
    return items, dropped, dropped_tool


def scout(language: str = "java", min_stars: int = 300,
          max_stars: int = 5000, pushed_since: str = "2026-01-01",
          limit: int = 20, allow_online: bool = True) -> dict:
    """M269：单语言候选仓侦察（保留旧入口）。"""
    q = search_query(language, min_stars, max_stars, pushed_since, limit)
    url = (f"{GH_API}/search/repositories?q={urllib.parse.quote(q)}"
           f"&sort=updated&per_page={min(max(limit, 1), 50)}")
    if allow_online:
        ok, data, err = _get(url)
        if ok and isinstance(data, dict):
            items, dropped, dropped_tool = _parse_search(data, language)
            return {"ok": True, "source": "github_search", "query": q,
                    "queries": [q], "items": items[:limit], "dropped": dropped,
                    "dropped_tool": dropped_tool, "error": ""}
        fallback = _offline(language, min_stars, max_stars, limit)
        fallback["error"] = err
        return fallback
    return _offline(language, min_stars, max_stars, limit)


def scout_daily(languages: list[str] | tuple[str, ...] = ("java", "python",
                                                          "solidity"),
                days: int = 14, limit: int = 10, min_stars: int = 300,
                max_stars: int = 30000, allow_online: bool = True,
                today: _dt.date | None = None) -> dict:
    """M285：每日动态抓新仓。

    每个语言各查一次，合并去重后按“有 Issues → 最近 push → stars”排序。
    在线查询全部失败时整体回退离线种子，source 明确标注 offline_seed。
    """
    langs = [str(x).strip() for x in (languages or []) if str(x).strip()]
    today = today or _dt.date.today()
    since = (today - _dt.timedelta(days=max(1, int(days)))).isoformat()
    per_page = min(max(int(limit) * 2, 10), 50)

    items: list[dict] = []
    queries: list[str] = []
    errors: list[str] = []
    dropped = 0
    dropped_tool = 0
    online_ok = 0
    day_index = today.toordinal()

    for lang in langs:
        qualifier = next_qualifier(lang, day_index)
        q = search_query(lang, min_stars, max_stars, since, limit, qualifier)
        queries.append(q)
        if not allow_online:
            continue
        url = (f"{GH_API}/search/repositories?q={urllib.parse.quote(q)}"
               f"&sort=updated&order=desc&per_page={per_page}")
        ok, data, err = _get(url)
        if not ok or not isinstance(data, dict):
            errors.append(f"{lang}: {err}")
            continue
        online_ok += 1
        parsed, drop, drop_tool = _parse_search(data, lang)
        items += parsed
        dropped += drop
        dropped_tool += drop_tool

    if online_ok == 0:
        seeds: list[dict] = []
        for lang in langs:
            seeds += _offline(lang, min_stars, max_stars, per_page)["items"]
        # 去重后仍按“有 Issues / stars”排序，保持调用方一致。
        merged = {it["slug"]: it for it in seeds}
        ordered = sorted(merged.values(),
                         key=lambda x: (not x.get("has_issues"),
                                        -int(x.get("stars") or 0)))
        return {"ok": bool(ordered), "source": "offline_seed",
                "queries": queries, "items": ordered[:max(1, limit)],
                "dropped": 0, "dropped_tool": 0,
                "error": "; ".join(errors)[:400]}

    merged: dict[str, dict] = {}
    for it in items:
        cur = merged.get(it["slug"])
        if cur is None or int(it["stars"]) > int(cur["stars"]):
            merged[it["slug"]] = it
    # 稳定排序两遍：先按最近 push 倒序，再把有 Issues 的仓提到前面。
    ordered = sorted(merged.values(),
                     key=lambda x: (x.get("pushed_at") or "",
                                    int(x.get("stars") or 0)),
                     reverse=True)
    ordered.sort(key=lambda x: not x.get("has_issues"))
    return {"ok": bool(ordered), "source": "github_search",
            "queries": queries, "items": ordered,
            "dropped": dropped, "dropped_tool": dropped_tool,
            "error": "; ".join(errors)[:400]}
