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


# M320：粘连命名的个人练习仓（Mestudy / javastudy / mylearn）——
# `study`/`learn` 前面没有分隔符，词边界正则抓不到。
_GLUED_STUDY_RE = re.compile(
    r"(?:^|my|me|java|py|web|test|code)(?:study|learn|practice|homework)$",
    re.I)


def is_tutorial(slug: str, description: str = "",
                topics: list[str] | tuple[str, ...] = ()) -> bool:
    """仓库名 / 描述 / topics 命中教学标记即判教学仓。"""
    text = " ".join([slug or "", description or "", " ".join(topics or [])])
    if _TUTORIAL_RE.search(text):
        return True
    name = (slug or "").split("/")[-1]
    return bool(_GLUED_STUDY_RE.match(name))


# M293：业务限定词。裸搜 language+pushed 抓回来的大半是驱动/插件/桌面工具，
# 按语言轮询注入一个业务词，把候选拉回“有 Web 路由的业务后台”。
BUSINESS_QUALIFIERS: dict[str, tuple[str, ...]] = {
    # M311：Java 富矿词池 —— 真实企业后台/脚手架（mybatis-plus / sa-token /
    # shiro 是出洞率最高的一批），不再只写一个裸 "spring-boot"。
    "java": ("mybatis-plus", "sa-token", "shiro", '"spring-boot" admin', "erp",
             "crm", "mall", "oa", "cms", "mes", "wms"),
    # M311：Python 用"框架 + 业务"组合词，裸 django/fastapi 会捞回一堆
    # 类型桩/Linter/插件库（django-stubs、djLint、django-auditlog…）。
    "python": ("fastapi admin", "fastapi cms", "django erp", "django crm",
               "django mall", "flask admin", "rag admin"),
    "solidity": ("vault", "staking", "lending", "swap"),
}

# M325：新生代赛道。2024-06 之后新建、2026-09 之后仍有 push 的仓，
# 传统猎手还没扫过；用 created/pushed 双时间窗把它们从“第 1 页老仓”里捞出来。
NEW_GEN_CREATED_SINCE = "2024-06-01"
NEW_GEN_PUSHED_SINCE = "2026-09-01"
NEW_GEN_STARS = (80, 5000)
NEW_GEN_KEYWORDS: dict[str, tuple[str, ...]] = {
    # 短词/缩写必须加引号：裸 mes 会捞回 meshcore/messages，裸 bi 会捞回
    # binary 之类；GitHub 的 quoted phrase 才按词匹配。
    # M335：Python 必须绑 Web 框架，否则裸 "iot"/"agent" 会捞回 Home Assistant
    # 插件与本地 CLI（v1.4.1 的 27 候选里 18 个因此白克隆）。
    "java": ('"spring-boot" "rag"', '"spring-boot" "agent"',
             '"spring-boot" "mcp"', 'mybatis-plus "workflow"',
             'mybatis-plus "text2sql"', '"spring-boot" "chatbi"',
             '"spring-boot" "knowledge-base"', 'mybatis-plus "lowcode"',
             '"spring-boot" "iot"', 'mybatis-plus "wms"',
             'mybatis-plus "mes"', '"spring-boot" "his"',
             'mybatis-plus "lims"', '"spring-boot" "report"',
             'mybatis-plus "bi"'),
    "python": ('fastapi "rag"', 'fastapi "agent"', 'fastapi "mcp"',
               'fastapi "workflow"', 'fastapi "text2sql"',
               'fastapi "chatbi"', 'fastapi "knowledge-base"',
               'fastapi "lowcode"', 'django "wms"', 'django "mes"',
               'django "his"', 'flask "iot"', 'fastapi "report"',
               'fastapi "bi"', 'django "erp"'),
}
# 传统业务词也按星标分桶；80..450 抓新锐小仓，451..2000 抓中型业务仓。
TRADITIONAL_STAR_BUCKETS = ((80, 450), (451, 2000))


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
    r"testing-framework|testcontainers|stubs|djlint|linter|auditlog|graphql|"
    r"huey|celery|defectdojo|spring-boot-admin|home[-_]?assistant|"
    r"hacs|custom_components|esphome)(?:[^a-z0-9]|$)"
    r"|(?:ide|vscode|intellij|eclipse)-)", re.I)

# M312：名字以框架前缀开头、描述又是"库/插件/中间件/可复用包"的第三方组件，
# 不是端到端业务后台（如 django-layout、fastapi-utils 这类）。
_COMPONENT_NAME_RE = re.compile(r"^(?:django|flask|fastapi|spring)-", re.I)
_COMPONENT_DESC_RE = re.compile(
    r"\b(?:library|plugin|extension|middleware|reusable|package|adapter)\b",
    re.I)


def is_tool_lib(slug: str, description: str = "",
                topics: list[str] | tuple[str, ...] = ()) -> bool:
    """仓库名/描述/topics 命中工具库标记即丢（M293/M312）。"""
    text = " ".join([slug or "", description or "", " ".join(topics or [])])
    if _TOOL_LIB_RE.search(text):
        return True
    name = (slug or "").split("/")[-1]
    return bool(_COMPONENT_NAME_RE.match(name)
                and _COMPONENT_DESC_RE.search(description or ""))


def next_qualifier(language: str, day_index: int) -> str:
    """按天轮询该语言的业务限定词（同一天结果稳定，逐日轮换）。"""
    qs = BUSINESS_QUALIFIERS.get(str(language).lower()) or ()
    return qs[day_index % len(qs)] if qs else ""


def search_query(language: str, min_stars: int, max_stars: int,
                 pushed_since: str, limit: int = 20,
                 qualifier: str = "", created_since: str = "",
                 star_range: tuple[int, int] | None = None) -> str:
    """GitHub Search 限定串（M285 口径 + M293 业务词 + M325 新生代窗口）。"""
    lo, hi = star_range if star_range else (min_stars, max_stars)
    base = (f"language:{language} stars:{int(lo)}..{int(hi)} "
            f"pushed:>{pushed_since}")
    if created_since:
        base += f" created:>{created_since}"
    base += " archived:false fork:false"
    return f"{qualifier} {base}".strip() if qualifier else base


def search_url(query: str, page: int = 1, per_page: int = 30) -> str:
    """GitHub 搜索 URL（M325：显式 page，不再永远第 1 页）。"""
    per_page = min(max(int(per_page), 1), 50)
    url = (f"{GH_API}/search/repositories?q={urllib.parse.quote(query)}"
           f"&sort=updated&order=desc&per_page={per_page}")
    if int(page) > 1:
        url += f"&page={int(page)}"
    return url


def _bounded_star_range(min_stars: int, max_stars: int,
                        bucket: tuple[int, int]) -> tuple[int, int]:
    """把分桶夹在调用方给的 min/max 内；夹空了就退回全局区间。"""
    lo = max(int(min_stars), int(bucket[0]))
    hi = min(int(max_stars), int(bucket[1]))
    return (lo, hi) if lo <= hi else (int(min_stars), int(max_stars))


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


def _merge_round_robin(buckets: dict[str, list[dict]],
                       langs: list[str]) -> list[dict]:
    """按语言分桶排序后轮转交织（M311）。

    桶内：有 Issues 优先 → 最近 push → stars；桶间按 langs 顺序轮流取
    （java #1 → python #1 → solidity #1 → java #2 …），保证前 N 个候选里
    每种语言都有份，不再被单语言爆量挤占。
    """
    prepared: dict[str, list[dict]] = {}
    for lang in langs:
        uniq: dict[str, dict] = {}
        for it in buckets.get(lang) or []:
            cur = uniq.get(it["slug"])
            if (cur is None
                    or int(it.get("stars") or 0) > int(cur.get("stars") or 0)):
                uniq[it["slug"]] = it
        vals = sorted(uniq.values(),
                      key=lambda x: (x.get("pushed_at") or "",
                                     int(x.get("stars") or 0)),
                      reverse=True)
        vals.sort(key=lambda x: not x.get("has_issues"))
        prepared[lang] = vals

    ordered: list[dict] = []
    seen: set[str] = set()
    idx = 0
    while True:
        added = False
        for lang in langs:
            vals = prepared.get(lang) or []
            if idx >= len(vals):
                continue
            added = True
            it = vals[idx]
            if it["slug"] in seen:
                continue
            seen.add(it["slug"])
            ordered.append(it)
        if not added:
            break
        idx += 1
    return ordered


def scout_daily(languages: list[str] | tuple[str, ...] = ("java", "python",
                                                          "solidity"),
                days: int = 14, limit: int = 10, min_stars: int = 150,
                max_stars: int = 10000, allow_online: bool = True,
                today: _dt.date | None = None,
                terms_per_language: int = 2) -> dict:
    """M285/M311/M325：每日动态抓新仓（跨语言 Round-Robin 混排）。

    每个语言分两条轨：
      · 新生代（约一半名额）：created:>2024-06-01 + pushed:>2026-09-01，
        关键词走 RAG/Agent/MES/WMS/HIS 等 2024-2026 新场景；
      · 传统业务：保留 erp/crm/mall 等词，但按天轮转 page=1..4 和星标分桶，
        避免每天都被第 1 页的 2018-2022 老仓占满。
    在线查询全部失败时整体回退离线种子，同样轮转混排。
    """
    langs = [str(x).strip() for x in (languages or []) if str(x).strip()]
    today = today or _dt.date.today()
    since = (today - _dt.timedelta(days=max(1, int(days)))).isoformat()
    per_page = min(max(int(limit) * 3, 30), 50)

    buckets: dict[str, list[dict]] = {lang: [] for lang in langs}
    specs: list[dict] = []
    queries: list[str] = []
    errors: list[str] = []
    dropped = 0
    dropped_tool = 0
    online_ok = 0
    day_index = today.toordinal()

    terms = max(1, int(terms_per_language))
    if terms == 1:
        new_gen_terms, traditional_terms = 1, 0
    else:
        # 约 60% 名额给新生代；至少留 1 个传统词，避免完全丢掉老矿。
        new_gen_terms = min(terms - 1, max(1, int(round(terms * 0.6))))
        traditional_terms = terms - new_gen_terms

    for lang in langs:
        new_keywords = NEW_GEN_KEYWORDS.get(lang, ())
        ng = new_gen_terms if new_keywords else 0
        for k in range(ng):
            keyword = new_keywords[(day_index + k) % len(new_keywords)]
            q = search_query(
                lang, NEW_GEN_STARS[0], NEW_GEN_STARS[1],
                NEW_GEN_PUSHED_SINCE, limit, keyword,
                created_since=NEW_GEN_CREATED_SINCE,
                star_range=NEW_GEN_STARS)
            specs.append({"language": lang, "track": "new_gen",
                          "qualifier": keyword, "query": q, "page": 1})
        for k in range(traditional_terms):
            offset = day_index + ng + k
            qualifier = next_qualifier(lang, offset)
            bucket = TRADITIONAL_STAR_BUCKETS[
                offset % len(TRADITIONAL_STAR_BUCKETS)]
            star_range = _bounded_star_range(min_stars, max_stars, bucket)
            page = (offset % 4) + 1
            q = search_query(lang, min_stars, max_stars, since, limit,
                             qualifier, star_range=star_range)
            specs.append({"language": lang, "track": "traditional",
                          "qualifier": qualifier, "query": q, "page": page})

    for spec in specs:
        queries.append(spec["query"])
        if not allow_online:
            continue
        page = int(spec.get("page") or 1)
        ok, data, err = _get(search_url(spec["query"], page, per_page))
        if not ok or not isinstance(data, dict):
            errors.append(f"{spec['language']}: {err}")
            continue
        # 新生代词太窄/当天该词没结果时，顺延 1..2 个词，避免整条轨道空手。
        if (spec["track"] == "new_gen"
                and int(data.get("total_count") or 0) == 0):
            kws = NEW_GEN_KEYWORDS.get(spec["language"], ())
            if kws and spec["qualifier"] in kws:
                start = kws.index(spec["qualifier"])
                for step in range(1, min(3, len(kws))):
                    alt_kw = kws[(start + step) % len(kws)]
                    alt_q = search_query(
                        spec["language"], NEW_GEN_STARS[0], NEW_GEN_STARS[1],
                        NEW_GEN_PUSHED_SINCE, limit, alt_kw,
                        created_since=NEW_GEN_CREATED_SINCE,
                        star_range=NEW_GEN_STARS)
                    ok2, data2, err2 = _get(search_url(alt_q, 1, per_page))
                    if (ok2 and isinstance(data2, dict)
                            and int(data2.get("total_count") or 0) > 0):
                        data = data2
                        spec["query"] = alt_q
                        spec["qualifier"] = alt_kw
                        spec["fallback"] = True
                        queries.append(alt_q)
                        break
        # M335：框架+业务词全干时，退到“框架 only”新生代查询，保证 8 个
        # 实扫名额有足够候选；仍保留 created/pushed/stars 窗口与 Web 框架限定。
        if (spec["track"] == "new_gen"
                and int(data.get("total_count") or 0) == 0):
            frameworks = (("fastapi", "django", "flask")
                          if spec["language"] == "python"
                          else ('"spring-boot"', "mybatis-plus"))
            for fw in frameworks:
                alt_q = search_query(
                    spec["language"], NEW_GEN_STARS[0], NEW_GEN_STARS[1],
                    NEW_GEN_PUSHED_SINCE, limit, fw,
                    created_since=NEW_GEN_CREATED_SINCE,
                    star_range=NEW_GEN_STARS)
                ok3, data3, err3 = _get(search_url(alt_q, 1, per_page))
                if (ok3 and isinstance(data3, dict)
                        and int(data3.get("total_count") or 0) > 0):
                    data = data3
                    spec["query"] = alt_q
                    spec["qualifier"] = fw
                    spec["fallback"] = "framework_only"
                    queries.append(alt_q)
                    break
        # 轮转到 page 2..4 但该页为空时回退第 1 页，避免空手而归。
        if page > 1 and int(data.get("total_count") or 0) == 0:
            ok, data, err = _get(search_url(spec["query"], 1, per_page))
            if not ok or not isinstance(data, dict):
                errors.append(f"{spec['language']}: {err}")
                continue
            spec["page_used"] = 1
        else:
            spec["page_used"] = page
        online_ok += 1
        parsed, drop, drop_tool = _parse_search(data, spec["language"])
        buckets[spec["language"]] += parsed
        dropped += drop
        dropped_tool += drop_tool

    new_gen_queries = sum(1 for s in specs if s["track"] == "new_gen")
    if online_ok == 0:
        seeds: dict[str, list[dict]] = {}
        for lang in langs:
            seeds[lang] = _offline(lang, min_stars, max_stars, per_page)["items"]
        ordered = _merge_round_robin(seeds, langs)
        return {"ok": bool(ordered), "source": "offline_seed",
                "queries": queries, "query_specs": specs,
                "new_gen_queries": new_gen_queries,
                "items": ordered[:max(1, limit)],
                "dropped": 0, "dropped_tool": 0,
                "error": "; ".join(errors)[:400]}

    ordered = _merge_round_robin(buckets, langs)
    return {"ok": bool(ordered), "source": "github_search",
            "queries": queries, "query_specs": specs,
            "new_gen_queries": new_gen_queries,
            "items": ordered,
            "dropped": dropped, "dropped_tool": dropped_tool,
            "error": "; ".join(errors)[:400]}
