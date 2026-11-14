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
import hashlib
import json
import os
import re
import time
import urllib.parse
from pathlib import Path

try:
    import httpx
except ImportError:                                          # pragma: no cover
    httpx = None

GH_API = "https://api.github.com"
UA = "nexus-audit/1.3"

# M396：GitHub 搜索响应本地磁盘缓存。无 Token 时 /search/repositories 只有
# 10 次/分钟，一轮 scout_daily 动辄十几次查询，跑到一半 403 就前功尽弃。
# 6 小时内的相同 URL 直接复用本地响应（0 网络请求），半途限流时还能把
# 历史缓存页当"备用候选池"回填，避免一轮只剩 1 个仓。
DEFAULT_CACHE_DIR = (Path(__file__).resolve().parents[2] / ".cache" /
                     "scout_search")
DEFAULT_CACHE_TTL = 21600                      # 6 小时


def _cache_dir(explicit: Path | str | None = None) -> Path:
    """缓存目录优先级：显式参数 > NEXUS_SCOUT_CACHE_DIR > 仓库内默认值。"""
    if explicit is not None:
        return Path(explicit)
    env = (os.getenv("NEXUS_SCOUT_CACHE_DIR") or "").strip()
    return Path(env) if env else DEFAULT_CACHE_DIR


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
    # M342：带连字符/下划线的练习仓（Java-Agent-Study / foo_learn）。
    r"(?:^|[-_])(?:study|learn|practice|homework)$|"
    r"(?:^|my|me|java|py|web|test|code)(?:study|learn|practice|homework)$",
    re.I)


def is_tutorial(slug: str, description: str = "",
                topics: list[str] | tuple[str, ...] = ()) -> bool:
    """仓库名 / 描述 / topics 命中教学标记即判教学仓。"""
    text = " ".join([slug or "", description or "", " ".join(topics or [])])
    if _TUTORIAL_RE.search(text):
        return True
    name = (slug or "").split("/")[-1]
    # M320 的既有边界：case-study 是业务/案例仓，不是练习仓；M342 只拦
    # Java-Agent-Study / foo_learn 这类后缀。
    if name.lower() == "case-study" or name.lower().endswith("-case-study"):
        return False
    return bool(_GLUED_STUDY_RE.search(name))


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
NEW_GEN_STARS = (150, 5000)
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
# M339：新生代“框架+业务词”全干时的回退词。上一版回退到裸框架名，
# 把函数式库/桌面包装器当成了 Web 业务系统；这次只搜真实系统级业务词，
# 不再和框架硬 AND（靠 language/created/pushed/stars 自然筛）。
NEW_GEN_FALLBACK_WORDS = (
    "admin", "cms", "erp", "crm", "mall", "oa", "rbac", "portal",
    "workflow", "knowledge", "rag", "lowcode", "mes", "wms", "iot",
)
NEW_GEN_FALLBACK_CREATED_SINCE = "2024-01-01"
NEW_GEN_FALLBACK_STARS = (150, 5000)

# 传统业务词也按星标分桶；80..450 抓新锐小仓，451..2000 抓中型业务仓。
TRADITIONAL_STAR_BUCKETS = ((300, 1000), (1001, 5000))


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
    r"hacs|custom_components|esphome|comfyui|sd-webui|stable-diffusion|"
    r"gradio|streamlit|jupyter|notebook|mcp-server|"
    # M358：安全工具/漏洞库/靶场本体（AutoCVE、vuln-scanner、exploit-db、
    # honeypot 等）不是业务系统，扫它们只会把知识库示例当漏洞报。
    # M392：PoC/漏洞文库/靶场模板仓也不是业务系统（Vulnerability-Wiki-PoC、
    # nuclei-templates、payloads 等），侦察阶段直接拦掉。
    r"autocve|vuln-scanner|pentest|exploit-db|honeypot|"
    r"poc|pocs|vulnerability-wiki|vuln-wiki|writeup|writeups|payloads|"
    r"nuclei-templates|cve-\d{4})(?:[^a-z0-9]|$)"
    r"|(?:ide|vscode|intellij|eclipse)-)", re.I)

# M312：名字以框架前缀开头、描述又是"库/插件/中间件/可复用包"的第三方组件，
# 不是端到端业务后台（如 django-layout、fastapi-utils 这类）。
_COMPONENT_NAME_RE = re.compile(r"^(?:django|flask|fastapi|spring)-", re.I)
_COMPONENT_DESC_RE = re.compile(
    r"\b(?:library|plugin|extension|middleware|reusable|package|adapter)\b",
    re.I)


_BUSINESS_SIGNAL_RE = re.compile(
    r"\b(?:platform|admin|management|erp|crm|mall|oa|workflow|"
    r"low[- ]?code|business|enterprise|system)\b", re.I)


def is_tool_lib(slug: str, description: str = "",
                topics: list[str] | tuple[str, ...] = ()) -> bool:
    """仓库名/描述/topics 命中工具库标记即丢（M293/M312）。

    M353：topics 里的 cli/codegenerator/mcp 不能单独否掉一个企业级低代码
    主仓（JeecgBoot 的 topics 同时有 cli/codegenerator/low-code）。因此
    slug+description 命中工具词仍直接丢；仅 topics 命中时，若同时存在
    platform/admin/low-code/erp 等业务信号，则保留。
    """
    text = " ".join([slug or "", description or "", " ".join(topics or [])])
    if _TOOL_LIB_RE.search(" ".join([slug or "", description or ""])):
        return True
    if _TOOL_LIB_RE.search(" ".join(topics or [])) and not _BUSINESS_SIGNAL_RE.search(text):
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


def _get_cached(url: str, *, cache_dir: Path | None = None,
                cache_ttl: int = DEFAULT_CACHE_TTL
                ) -> tuple[bool, dict | None, str, bool]:
    """M396：带 6 小时磁盘缓存的 `_get`。

    返回 (ok, data, err, from_cache)。`from_cache=True` 表示本次 **0 网络
    请求**，调用方可据此统计 cache_hits。缓存文件以 URL 的 sha1 命名，
    内容 {"ts", "url", "data"}；坏文件 / 过期 / 目录不可写一律静默降级为
    直连，绝不让缓存把侦察卡死。
    """
    root = _cache_dir(cache_dir)
    key = hashlib.sha1(url.encode("utf-8")).hexdigest()
    path = root / f"{key}.json"
    try:
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            if (isinstance(payload, dict)
                    and isinstance(payload.get("data"), dict)
                    and time.time() - float(payload.get("ts") or 0)
                    <= max(0, int(cache_ttl))):
                return True, payload["data"], "", True
    except (OSError, ValueError, TypeError):
        pass                                    # 坏缓存 == 没有缓存
    ok, data, err = _get(url)
    if not (ok and isinstance(data, dict)):
        return ok, data, err, False
    try:
        root.mkdir(parents=True, exist_ok=True)
        tmp = root / f"{key}.{os.getpid()}.tmp"
        tmp.write_text(json.dumps({"ts": time.time(), "url": url,
                                   "data": data}, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(path)                       # 原子替换，避免读到半截 JSON
    except (OSError, ValueError, TypeError):
        pass
    return True, data, "", False


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


def _is_rate_limit(err: object) -> bool:
    """GitHub 搜索限流（无 Token 10 次/分钟）（M393）。"""
    s = str(err or "").lower()
    return "403" in s or "429" in s or "rate limit" in s or "ratelimit" in s


def _ts_epoch(value: str) -> float | None:
    """ISO 时间 → UTC epoch 秒；无时区标记按**本地时区**解释（M391）。

    旧实现直接比较去 `Z` 的字符串，把 UTC 的 `pushed_at` 与本地
    `last_scanned_at` 混算 —— 在 UTC+8 下会把"扫描后 8 小时内"的新 push
    误判成"未变"，白白跳过刚更新的仓。
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith(("Z", "z")):
            dt = _dt.datetime.fromisoformat(raw[:-1] + "+00:00")
        else:
            dt = _dt.datetime.fromisoformat(raw)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = _dt.datetime.strptime(raw[:19], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.astimezone()  # naive → 本地时区
    return dt.timestamp()


def _pushed_before(item: dict, scanned_at: dict[str, str]) -> bool:
    """远端 pushed_at 是否 <= 上次扫描时刻（之后没有任何新 push）（M388/M391）。"""
    slug = str(item.get("slug") or "")
    pushed_ts = _ts_epoch(str(item.get("pushed_at") or ""))
    scanned_ts = _ts_epoch(scanned_at.get(slug) or "")
    if pushed_ts is None or scanned_ts is None:
        return False
    return pushed_ts <= scanned_ts


def scout_daily(languages: list[str] | tuple[str, ...] = ("java", "python",
                                                          "solidity"),
                days: int = 14, limit: int = 10, min_stars: int = 300,
                max_stars: int = 10000, allow_online: bool = True,
                today: _dt.date | None = None,
                terms_per_language: int = 2,
                exclude_slugs: set[str] | list[str] | None = None,
                scanned_at: dict[str, str] | None = None,
                cache_dir: Path | str | None = None,
                cache_ttl: int = DEFAULT_CACHE_TTL) -> dict:
    """M285/M311/M325：每日动态抓新仓（跨语言 Round-Robin 混排）。

    每个语言分两条轨：
      · 新生代（约一半名额）：created:>2024-06-01 + pushed:>2026-09-01，
        关键词走 RAG/Agent/MES/WMS/HIS 等 2024-2026 新场景；
      · 传统业务：保留 erp/crm/mall 等词，但按天轮转 page=1..4 和星标分桶，
        避免每天都被第 1 页的 2018-2022 老仓占满。
    在线查询全部失败时整体回退离线种子，同样轮转混排。
    """
    langs = [str(x).strip() for x in (languages or []) if str(x).strip()]
    excluded = {str(x) for x in (exclude_slugs or set())}
    today = today or _dt.date.today()
    since = (today - _dt.timedelta(days=max(1, int(days)))).isoformat()
    per_page = min(max(int(limit) * 3, 30), 50)

    buckets: dict[str, list[dict]] = {lang: [] for lang in langs}
    specs: list[dict] = []
    queries: list[str] = []
    errors: list[str] = []
    dropped = 0
    dropped_tool = 0
    dropped_unchanged = 0
    online_ok = 0
    day_index = today.toordinal()
    # M396：缓存目录 + 本轮统计。cache_hits 计「命中缓存的查询页数」，
    # backfilled 计「半途 403 后从缓存/离线种子补进来的仓数」。
    cache_root = _cache_dir(cache_dir)
    cache_hits = 0
    backfilled = 0

    def _fetch(url: str) -> tuple[bool, dict | None, str]:
        """统一走缓存；命中即记一笔，供报告披露。"""
        nonlocal cache_hits
        ok, data, err, from_cache = _get_cached(
            url, cache_dir=cache_root, cache_ttl=cache_ttl)
        if from_cache:
            cache_hits += 1
        return ok, data, err

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

    rate_limited = False
    for spec in specs:
        if rate_limited:
            break
        queries.append(spec["query"])
        if not allow_online:
            continue
        page = int(spec.get("page") or 1)
        ok, data, err = _fetch(search_url(spec["query"], page, per_page))
        if not ok or not isinstance(data, dict):
            errors.append(f"{spec['language']}: {err}")
            if _is_rate_limit(err):
                rate_limited = True
                break
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
                    ok2, data2, err2 = _fetch(search_url(alt_q, 1, per_page))
                    if not ok2 and _is_rate_limit(err2):
                        rate_limited = True
                        break
                    if (ok2 and isinstance(data2, dict)
                            and int(data2.get("total_count") or 0) > 0):
                        data = data2
                        spec["query"] = alt_q
                        spec["qualifier"] = alt_kw
                        spec["fallback"] = True
                        queries.append(alt_q)
                        break
        # M339：框架+业务词全干时，退到**单业务系统词**（admin/cms/erp/...），
        # 绝不再裸搜框架名；用 created:>2024-01-01 + stars:60..5000 保持新锐。
        if (spec["track"] == "new_gen"
                and int(data.get("total_count") or 0) == 0):
            words = NEW_GEN_FALLBACK_WORDS
            start = day_index % len(words)
            for step in range(min(5, len(words))):
                word = words[(start + step) % len(words)]
                alt_q = search_query(
                    spec["language"], NEW_GEN_FALLBACK_STARS[0],
                    NEW_GEN_FALLBACK_STARS[1], NEW_GEN_PUSHED_SINCE, limit,
                    word, created_since=NEW_GEN_FALLBACK_CREATED_SINCE,
                    star_range=NEW_GEN_FALLBACK_STARS)
                ok3, data3, err3 = _fetch(search_url(alt_q, 1, per_page))
                if not ok3 and _is_rate_limit(err3):
                    rate_limited = True
                    break
                if (ok3 and isinstance(data3, dict)
                        and int(data3.get("total_count") or 0) > 0):
                    data = data3
                    spec["query"] = alt_q
                    spec["qualifier"] = word
                    spec["fallback"] = "business_word"
                    queries.append(alt_q)
                    break
        # 轮转到 page 2..4 但该页为空时回退第 1 页，避免空手而归。
        if page > 1 and int(data.get("total_count") or 0) == 0:
            ok, data, err = _fetch(search_url(spec["query"], 1, per_page))
            if not ok or not isinstance(data, dict):
                errors.append(f"{spec['language']}: {err}")
                if _is_rate_limit(err):
                    rate_limited = True
                    break
                continue
            spec["page_used"] = 1
        else:
            spec.setdefault("page_used", page)
        online_ok += 1
        parsed, drop, drop_tool = _parse_search(data, spec["language"])
        if excluded:
            parsed = [x for x in parsed if x.get("slug") not in excluded]
        # M388：已扫仓若远端 pushed_at 不晚于上次扫描时刻，说明自那以后
        # 没有任何新 push —— 侦察阶段直接排除，不克隆、不占名额。
        if scanned_at:
            _before = len(parsed)
            parsed = [x for x in parsed
                      if not _pushed_before(x, scanned_at)]
            dropped_unchanged += _before - len(parsed)
        # M346：当前页剔除冷却仓后不足 2 个，且还有下一页时，顺延 page+1/+2。
        # 单查询最多多翻 2 页，避免把整轮变成无限分页。
        try:
            total_count = int(data.get("total_count") or 0)
        except (TypeError, ValueError):
            total_count = 0
        extra = 0
        while (excluded and len(parsed) < 2 and extra < 2
               and total_count > (page + extra) * per_page):
            nxt = page + extra + 1
            okp, datap, errp = _fetch(search_url(spec["query"], nxt, per_page))
            if not okp or not isinstance(datap, dict):
                errors.append(f"{spec['language']}: {errp}")
                if _is_rate_limit(errp):
                    rate_limited = True
                break
            more, d2, t2 = _parse_search(datap, spec["language"])
            if excluded:
                more = [x for x in more if x.get("slug") not in excluded]
            parsed += more
            dropped += d2
            dropped_tool += t2
            spec["page_used"] = nxt
            spec["cooldown_pages"] = extra + 1
            extra += 1
        buckets[spec["language"]] += parsed
        dropped += drop
        dropped_tool += drop_tool

    # M380：有效候选不足 limit 时，用下一组轮换业务词补拉（最多 2 轮）。
    # 背景：`--limit 8 --min-stars 300` 实测只回 3 个候选，供给不足会让
    # daily-hunt 的实扫名额空转。补拉只走传统轨的轮换词，且一旦撞上
    # GitHub 限流就立即停手（无 Token 时搜索限流 10 次/分钟）。
    def _candidate_count() -> int:
        seen: set[str] = set()
        for vals in buckets.values():
            for it in vals:
                slug = it.get("slug")
                if slug and slug not in excluded:
                    seen.add(slug)
        return len(seen)

    def _rate_limited() -> bool:
        return any("403" in e or "rate" in e.lower() for e in errors)

    extra_rounds = 0
    ng_off = new_gen_terms if any(NEW_GEN_KEYWORDS.get(lang) for lang in langs) else 0
    while (allow_online and online_ok > 0 and extra_rounds < 2
           and not rate_limited
           and _candidate_count() < max(1, int(limit))
           and not _rate_limited()):
        extra_rounds += 1
        for lang in langs:
            offset = day_index + ng_off + traditional_terms + extra_rounds
            qualifier = next_qualifier(lang, offset)
            bucket = TRADITIONAL_STAR_BUCKETS[
                offset % len(TRADITIONAL_STAR_BUCKETS)]
            star_range = _bounded_star_range(min_stars, max_stars, bucket)
            q = search_query(lang, min_stars, max_stars, since, limit,
                             qualifier, star_range=star_range)
            queries.append(q)
            specs.append({"language": lang, "track": "traditional",
                          "qualifier": qualifier, "query": q, "page": 1,
                          "topup_round": extra_rounds})
            ok, data, err = _fetch(search_url(q, 1, per_page))
            if not ok or not isinstance(data, dict):
                errors.append(f"{lang}: {err}")
                if _is_rate_limit(err):
                    rate_limited = True
                    break
                continue
            parsed, drop, drop_tool = _parse_search(data, lang)
            if excluded:
                parsed = [x for x in parsed if x.get("slug") not in excluded]
            if scanned_at:
                parsed = [x for x in parsed
                          if not _pushed_before(x, scanned_at)]
            buckets[lang] += parsed
            dropped += drop
            dropped_tool += drop_tool
            if _candidate_count() >= max(1, int(limit)):
                break

    # M396：半途限流回填（Partial Rate-Limit Backfill）。
    # 背景：无 Token 时 /search 只有 10 次/分钟，查询循环常在第 5~6 条
    # 撞 403 提前 break；M380 的补拉轮一旦 rate_limited 就不再跑，于是一轮
    # 可能只回 1 个候选，daily-hunt 的 --limit 8 有 7 个名额空转。
    # 顺序：① 6 小时缓存页（按 ts 新→旧）→ ② OFFLINE_SEEDS。两级都按语言
    # 轮转补，严格复用 excluded / scanned_at 的过滤口径，不把冷却仓放回来。
    forced_source = ""
    if rate_limited and _candidate_count() == 0:
        # M393：0 在线候选也要显式标注来源，但不再早退 —— 统一走回填，
        # 让 cache_hits / backfilled 在报告里可解释。
        forced_source = "github_search_rate_limited"

    def _iter_round_robin(pool: dict[str, list[dict]]):
        lists = [pool.get(lang) or [] for lang in langs]
        i = 0
        while any(i < len(v) for v in lists):
            for lang_idx, vals in enumerate(lists):
                if i < len(vals):
                    yield langs[lang_idx], vals[i]
            i += 1

    def _fill(pool: dict[str, list[dict]], needed: int,
              seen: set[str]) -> int:
        """把池里的有效候选按语言轮转补进 buckets，返回实际补入数。"""
        nonlocal backfilled
        added = 0
        for lang, it in _iter_round_robin(pool):
            if added >= needed:
                break
            slug = str(it.get("slug") or "")
            if not slug or slug in seen or slug in excluded:
                continue
            try:
                stars = int(it.get("stars") or 0)
            except (TypeError, ValueError):
                stars = 0
            if not (min_stars <= stars <= max_stars):
                continue
            if scanned_at and _pushed_before(it, scanned_at):
                continue
            seen.add(slug)
            buckets.setdefault(lang, []).append(it)
            added += 1
        backfilled += added
        return added

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
                "dropped_unchanged": dropped_unchanged,
                "cache_hits": cache_hits, "backfilled": 0,
                "error": "; ".join(errors)[:400]}

    ordered = _merge_round_robin(buckets, langs)
    if (rate_limited or _rate_limited()) and len(ordered) < max(1, int(limit)):
        needed = max(1, int(limit)) - len(ordered)
        seen = {str(x.get("slug") or "") for x in ordered}

        # ① 缓存页：按 ts 从新到旧，逐页用 _parse_search 抽候选。
        cached_pages: list[tuple[float, dict]] = []
        try:
            for p in cache_root.glob("*.json"):
                try:
                    payload = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if (isinstance(payload, dict)
                        and isinstance(payload.get("data"), dict)):
                    try:
                        ts = float(payload.get("ts") or 0)
                    except (TypeError, ValueError):
                        ts = 0.0
                    cached_pages.append((ts, payload["data"]))
        except OSError:
            cached_pages = []
        cached_pages.sort(key=lambda x: x[0], reverse=True)

        lang_set = {str(x).lower() for x in langs}
        cache_pool: dict[str, list[dict]] = {lang: [] for lang in langs}
        pool_seen: set[str] = set()
        for _ts, data in cached_pages:
            for lang in langs:
                parsed, _, _ = _parse_search(data, lang)
                for x in parsed:
                    slug = str(x.get("slug") or "")
                    if not slug or slug in pool_seen:
                        continue
                    item_lang = str(x.get("language") or lang).strip().lower()
                    if item_lang not in lang_set:
                        continue
                    pool_seen.add(slug)
                    key = item_lang if item_lang in cache_pool else lang
                    cache_pool.setdefault(key, []).append(x)
        needed -= _fill(cache_pool, needed, seen)

        # ② 离线种子：缓存仍不够时按语言补差额。
        if needed > 0:
            seed_pool: dict[str, list[dict]] = {}
            for lang in langs:
                seed_pool[lang] = [
                    x for x in _offline(lang, min_stars, max_stars,
                                        per_page)["items"]
                    if x.get("slug") not in excluded]
            _fill(seed_pool, needed, seen)

        ordered = _merge_round_robin(buckets, langs)
        # 回填分支内才截断；正常路径仍不硬截断（M293：纯库仓不占名额）。
        if backfilled and len(ordered) > max(1, int(limit)):
            ordered = ordered[:max(1, int(limit))]

    return {"ok": bool(ordered), "source": forced_source or "github_search",
            "queries": queries, "query_specs": specs,
            "new_gen_queries": new_gen_queries,
            "items": ordered,
            "dropped": dropped, "dropped_tool": dropped_tool,
            "dropped_unchanged": dropped_unchanged,
            "cache_hits": cache_hits, "backfilled": backfilled,
            "error": "; ".join(errors)[:400]}
