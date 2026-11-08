"""M268：CVE / GHSA / Issue 自动查重（保守四态）。

状态：
  ZERO_RECORD_FRESH        四个来源都实际查过且 0 命中
  DUPLICATE_CVE            命中 NVD / 本地 CVE 种子
  DUPLICATE_ISSUE_OR_GHSA  命中 GitHub Issue / GHSA
  PATCHED_UPSTREAM         上游 HEAD 已修复（由 upstream_sync 判定）
  UNKNOWN                  任一来源未查/失败/限流；绝不降级成 FRESH

设计原则：**查不到 ≠ 没人报过**。只有所有来源都成功返回 0，才允许
ZERO_RECORD_FRESH；否则一律 UNKNOWN，并在 coverage 里写清楚谁没查。
"""
from __future__ import annotations

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

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "known_public_cves.json"
CACHE = ROOT / ".cache" / "cve_dedup"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API = "https://cve.circl.lu/api/search"
# CIRCL 固定 10 条/页；历史 CVE 会被新号挤到后续页（M323）。
CIRCL_MAX_PAGES = 3
GH_API = "https://api.github.com"

STATUS_FRESH = "ZERO_RECORD_FRESH"
STATUS_CVE = "DUPLICATE_CVE"
STATUS_ISSUE = "DUPLICATE_ISSUE_OR_GHSA"
STATUS_PATCHED = "PATCHED_UPSTREAM"
STATUS_STALE = "STALE_REPO"
STATUS_UNKNOWN = "UNKNOWN"
ALL_STATUSES = (STATUS_FRESH, STATUS_CVE, STATUS_ISSUE, STATUS_PATCHED,
                STATUS_STALE, STATUS_UNKNOWN)

_LAST_CALL = 0.0
_CACHE_TTL = 24 * 3600
# M294 性能：NVD 在部分网络被 TLS 阻断，每次白等 10s+；连续失败两次即熔断。
# 仓库级结果（CIRCL / advisories）在同一进程内只查一次，避免每根因重复请求。
_NVD_FAILS = 0
_REPO_MEMO: dict[tuple[str, str], dict] = {}


# M314：二开仓基座包名 → 上游主仓。芋道/若依/Jeecg 系二开仓的洞常常是
# 上游基座先公开过的；只按二开仓名查重会把上游旧洞当成"首杀"。
UPSTREAM_BASES: dict[str, tuple[str, ...]] = {
    "cn.iocoder.yudao": ("YunaiV/ruoyi-vue-pro", "yudao"),
    "org.jeecg": ("jeecgboot/JeecgBoot", "jeecg"),
    "com.ruoyi": ("yangzongzhuan/RuoYi", "ruoyi"),
    "com.baomidou": ("baomidou/mybatis-plus", "mybatis-plus"),
}
_UPSTREAM_PKG_RE = re.compile(
    r"package\s+(cn\.iocoder\.yudao|org\.jeecg|com\.ruoyi|com\.baomidou)\b")


def detect_upstream_aliases(repo_root: str | Path | None,
                            max_files: int = 400) -> list[str]:
    """扫源码里的基座包名，返回上游主仓别名（M314）。"""
    if not repo_root:
        return []
    root = Path(repo_root)
    if not root.exists():
        return []
    seen: set[str] = set()
    aliases: list[str] = []
    scanned = 0
    for p in root.rglob("*.java"):
        if any(part in (".git", "target", "build", "node_modules")
               for part in p.parts):
            continue
        scanned += 1
        if scanned > max_files:
            break
        try:
            head = p.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            continue
        m = _UPSTREAM_PKG_RE.search(head)
        if not m:
            continue
        base = m.group(1)
        if base in seen:
            continue
        seen.add(base)
        aliases.extend(UPSTREAM_BASES.get(base, ()))
    # 包名被二开方改掉时（LZ-litchi 用 com.lz、yshop 用 co.yixiang），
    # 退到 pom.xml 的 artifactId / parent 里找基座指纹。
    for pom in list(root.rglob("pom.xml"))[:20]:
        try:
            text = pom.read_text(encoding="utf-8", errors="replace")[:8000].lower()
        except OSError:
            continue
        for token, repos in (("yudao", ("YunaiV/ruoyi-vue-pro", "yudao")),
                             ("ruoyi", ("yangzongzhuan/RuoYi", "ruoyi")),
                             ("jeecg", ("jeecgboot/JeecgBoot", "jeecg"))):
            if f"<artifactId>{token}" in text or f">{token}-" in text:
                aliases.extend(repos)
    return list(dict.fromkeys(a for a in aliases if a))


def load_signatures(path: Path = CONFIG) -> list[dict]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data.get("signatures") or []


def _cache_path(slug: str, category: str, unit: str) -> Path:
    key = f"{slug}|{category}|{unit}".lower()
    return CACHE / (hashlib.sha256(key.encode()).hexdigest()[:24] + ".json")


def _cache_get(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if time.time() - float(rec.get("_cached_at") or 0) > _CACHE_TTL:
        return None
    rec.pop("_cached_at", None)
    return rec


def _cache_put(path: Path, rec: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(rec)
    payload["_cached_at"] = time.time()
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                    encoding="utf-8")


def _throttle(seconds: float = 0.7) -> None:
    global _LAST_CALL
    delta = time.time() - _LAST_CALL
    if delta < seconds:
        time.sleep(seconds - delta)
    _LAST_CALL = time.time()


def _get_json(url: str, headers: dict | None = None,
              timeout: float = 20.0) -> tuple[bool, dict | list | None, str]:
    if os.getenv("NEXUS_NO_NETWORK", "").lower() in {"1", "true", "yes"}:
        return False, None, "network_disabled"
    if httpx is None:
        return False, None, "httpx_missing"
    _throttle()
    try:
        with httpx.Client(timeout=timeout) as c:
            r = c.get(url, headers=headers or {})
        if r.status_code in (429, 403):
            return False, None, f"rate_limited_http_{r.status_code}"
        if r.status_code != 200:
            return False, None, f"http_{r.status_code}"
        return True, r.json(), ""
    except Exception as e:                                    # noqa: BLE001
        return False, None, f"{type(e).__name__}: {e}"[:200]


def _local_match(slug: str, aliases: list[str], category: str,
                 unit: str) -> list[dict]:
    out: list[dict] = []
    for sig in load_signatures():
        repo = str(sig.get("repo") or "")
        repo_aliases = {repo.lower(), str(sig.get("repo", "")).lower()}
        repo_aliases |= {str(a).lower() for a in (sig.get("aliases") or [])}
        if slug.lower() not in repo_aliases and not any(
                a.lower() in repo_aliases for a in aliases):
            continue
        cat = str(sig.get("category") or "")
        uni = str(sig.get("unit") or "")
        if cat and category and cat.lower() != category.lower():
            continue
        if uni and unit:
            # 精确到方法名：CVE 修的是 getFollowUpRecord，不能连坐
            # 同文件的 getFollowUpRecordPage（后者仍是未修复入口）。
            norm = lambda s: s.split("#")[0].strip().lower()
            if norm(uni) != norm(unit):
                # M349：seed 的 unit 只写类名（CVE 描述只点名整类）时，
                # 允许匹配该类的任意方法；单方法 seed 仍精确匹配。
                if ("." in uni or not norm(unit).startswith(norm(uni) + ".")):
                    continue
        out.append(sig)
    return out


def query_nvd(keyword: str) -> dict:
    global _NVD_FAILS
    q = urllib.parse.quote(keyword)
    url = f"{NVD_API}?keywordSearch={q}&resultsPerPage=5"
    if _NVD_FAILS >= 2:
        return {"ok": False, "total": 0, "ids": [], "url": url,
                "error": "nvd_circuit_open"}
    ok, data, err = _get_json(url, timeout=8.0)
    if not ok or not isinstance(data, dict):
        _NVD_FAILS += 1
        return {"ok": False, "total": 0, "ids": [], "url": url, "error": err}
    _NVD_FAILS = 0
    vulns = data.get("vulnerabilities") or []
    ids = [v.get("cve", {}).get("id") for v in vulns
           if isinstance(v, dict) and v.get("cve", {}).get("id")]
    return {"ok": True, "total": int(data.get("totalResults") or len(ids)),
            "ids": ids[:5], "url": url, "error": ""}


def _circl_parse(data: dict) -> tuple[int, list[str], list[dict]]:
    """CIRCL 单页 -> (total_count, 去重 ids, items)。"""
    total = int(data.get("total_count") or 0)
    ids: list[str] = []
    items: list[dict] = []
    results = data.get("results") or {}
    for key in ("nvd", "cvelistv5"):
        for item in results.get(key) or []:
            if not (isinstance(item, list) and item):
                continue
            cid = str(item[0]).upper()
            if cid in ids:
                continue
            ids.append(cid)
            items.append({"id": cid,
                          "text": json.dumps(item[1],
                                             ensure_ascii=False)[:6000]})
    return total, ids, items


def query_circl(slug: str) -> dict:
    """CIRCL CVE Search（NVD 在此网络被 TLS 阻断时的只读兜底）。

    M323 修两处漏判：
      1) 旧实现只要某 URL 返回 HTTP 200 就 return，哪怕 total_count == 0；
         于是 /owner/repo 的"0 命中"会吞掉 /repo 兜底。现在 0 结果必须
         continue 到下一个 URL。
      2) CIRCL 固定 10 条/页，旧实现只读第 1 页。x-springboot 的
         CVE-2025-6731 已被 2026 年的新 CVE 挤到第 2 页，只翻首页必然漏。
         现在按 total_count 翻页（最多 CIRCL_MAX_PAGES 页）。
    """
    memo_key = ("circl", slug)
    if memo_key in _REPO_MEMO:
        return _REPO_MEMO[memo_key]
    parts = [p for p in slug.split("/") if p]
    urls = []
    if len(parts) == 2:
        urls.append(f"{CIRCL_API}/{urllib.parse.quote(parts[0])}/"
                    f"{urllib.parse.quote(parts[1])}")
    if parts:
        urls.append(f"{CIRCL_API}/{urllib.parse.quote(parts[-1])}")
    last_err = ""
    zero: dict | None = None
    for url in urls:
        all_ids: list[str] = []
        all_items: list[dict] = []
        total = 0
        ok_any = False
        page_err = ""
        for page in range(1, CIRCL_MAX_PAGES + 1):
            page_url = url if page == 1 else f"{url}?page={page}"
            ok, data, err = _get_json(page_url)
            if not ok or not isinstance(data, dict):
                page_err = err
                break
            ok_any = True
            total, ids, page_items = _circl_parse(data)
            before = len(all_ids)
            for item in page_items:
                if item["id"] in all_ids:
                    continue
                all_ids.append(item["id"])
                all_items.append(item)
            # 空页 / 本页无新 ID / 已覆盖 total（total 是去重前计数，可能
            # 大于唯一 ID 数，三者任一满足即停，避免死循环）。
            if not ids or len(all_ids) == before or len(all_ids) >= total:
                break
        if not ok_any:
            last_err = page_err
            continue
        res = {"ok": True, "total": total, "ids": all_ids[:5],
               "items": all_items, "url": url,
               "error": "" if not page_err else f"partial: {page_err}"}
        if total > 0 or all_ids or all_items:
            _REPO_MEMO[memo_key] = res
            return res
        if zero is None:
            zero = res
    res = zero or {"ok": False, "total": 0, "ids": [], "items": [],
                   "url": urls[0] if urls else "",
                   "error": last_err or "no_url"}
    _REPO_MEMO[memo_key] = res
    return res


def query_github_issues(slug: str, unit: str, category: str) -> dict:
    term = unit or category
    q = urllib.parse.quote(f"repo:{slug} {term}")
    url = f"{GH_API}/search/issues?q={q}&per_page=5"
    ok, data, err = _get_json(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "nexus-audit/1.2"})
    if not ok or not isinstance(data, dict):
        return {"ok": False, "total": 0, "ids": [], "url": url, "error": err}
    items = data.get("items") or []
    ids = [f"#{it.get('number')} {it.get('title', '')[:60]}" for it in items]
    return {"ok": True, "total": int(data.get("total_count") or len(items)),
            "ids": ids[:5], "url": url, "error": ""}


def query_github_advisories(slug: str) -> dict:
    memo_key = ("advisories", slug)
    if memo_key in _REPO_MEMO:
        return _REPO_MEMO[memo_key]
    url = f"{GH_API}/repos/{slug}/security-advisories"
    ok, data, err = _get_json(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "nexus-audit/1.2"})
    if not ok:
        # 私有/无权限/未开启 advisories 的仓返回 404；这属于“没查到”，
        # 不等于“没有”，必须保留在 coverage 里。
        res = {"ok": False, "total": 0, "ids": [], "url": url, "error": err}
        _REPO_MEMO[memo_key] = res
        return res
    if not isinstance(data, list):
        res = {"ok": False, "total": 0, "ids": [], "url": url,
               "error": "non_list_response"}
        _REPO_MEMO[memo_key] = res
        return res
    ids = [x.get("ghsa_id") or x.get("cve_id") or "" for x in data
           if isinstance(x, dict)]
    ids = [x for x in ids if x]
    # M290：同时保留每条公告的文本（summary+description），供 dedup 做
    # 方法级匹配——"仓里有公告"不等于"这个端点已被覆盖"。
    items = [{"id": (x.get("ghsa_id") or x.get("cve_id") or ""),
              "text": " ".join(str(x.get(k) or "") for k in
                               ("summary", "description", "details"))}
             for x in data if isinstance(x, dict)]
    res = {"ok": True, "total": len(ids), "ids": ids[:5], "url": url,
           "items": items, "error": ""}
    _REPO_MEMO[memo_key] = res
    return res


def query_github_issues_global(class_name: str, method_name: str,
                                 repo_name: str = "") -> dict:
    """全网跨仓搜索 `"类名" "方法名"`（M314），并支持仓库名兜底（M323）。

    不锁 `repo:{slug}`：仓库改名（yshop-crm → yshop-oa-crm）、白帽把 PoC
    发到独立仓（W000i/vuln、LinYuanyi1/cve-request-poc）时，只有去掉 repo:
    才能搜到。

    M323：公开 CVE 报告常常只写 `"项目名" "方法名"`，不写 Java 控制器类名
    （CVE-2025-6731 只写 X-SpringBoot + uploadApk）。类名查询 0 命中时，
    再用 `"{repo_name}" "{method_name}"` 补一枪。
    """
    if not class_name or not method_name:
        return {"ok": True, "total": 0, "ids": [], "url": "",
                "error": "not_applicable"}
    terms = [f'"{class_name}" "{method_name}"']
    name = (repo_name or "").strip().split("/")[-1]
    if name and name.lower() not in class_name.lower():
        terms.append(f'"{name}" "{method_name}"')
    last_err = ""
    zero: dict | None = None
    for term in terms:
        q = urllib.parse.quote(term)
        url = f"{GH_API}/search/issues?q={q}&per_page=5"
        ok, data, err = _get_json(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "nexus-audit/1.3"})
        if not ok or not isinstance(data, dict):
            last_err = err
            continue
        items = data.get("items") or []
        ids = []
        for it in items:
            repo_url = str(it.get("repository_url") or "")
            repo = ("/".join(repo_url.rstrip("/").split("/")[-2:])
                    if repo_url else "")
            ids.append(f"{repo}#{it.get('number')} {it.get('title', '')[:60]}")
        res = {"ok": True,
               "total": int(data.get("total_count") or len(items)),
               "ids": ids[:5], "url": url, "error": "", "query": term}
        if res["total"] > 0 or ids:
            return res
        if zero is None:
            zero = res
    if zero is not None:
        # 有一个查询失败就不能宣称"全网已查且 0 命中"。
        if last_err:
            zero = dict(zero, ok=False, error=last_err)
        return zero
    return {"ok": False, "total": 0, "ids": [], "url": "",
            "error": last_err or "no_url"}


GLOBAL_ADV_CACHE = CACHE / "_global_advisories.json"
_GLOBAL_ADV_MEMO: dict = {"ok": None, "items": [], "error": ""}


def set_refresh_advisories(enabled: bool = True) -> None:
    """M318：`--refresh-advisories` —— 强制下一轮重新拉全局公告。

    默认 24h 缓存保证挂机巡猎不撞配额；人工复核时用这个开关把
    `.cache/cve_dedup/_global_advisories.json` 与进程内 memo 一起清掉。
    """
    if not enabled:
        return
    _GLOBAL_ADV_MEMO.update(ok=None, items=[], error="")
    try:
        GLOBAL_ADV_CACHE.unlink(missing_ok=True)
    except OSError:
        pass


def _github_token() -> str:
    return (os.getenv("GITHUB_TOKEN") or os.getenv("NEXUS_GITHUB_TOKEN")
            or os.getenv("GH_TOKEN") or "").strip()


def load_global_advisories() -> tuple[bool, list[dict], str]:
    """整轮共用一份全局 advisory 列表（M317）。

    `GET /advisories` 与"当前查哪个方法"无关；旧实现每个单元翻 3 页，
    一个仓 5 个单元就发 15 次重复请求。现在 24h 落盘缓存 + 进程内 memo：
    无 Token 拉 1 页（100 条），有 Token 拉 2 页（200 条）。
    """
    if _GLOBAL_ADV_MEMO["ok"] is not None:
        return (_GLOBAL_ADV_MEMO["ok"], _GLOBAL_ADV_MEMO["items"],
                _GLOBAL_ADV_MEMO["error"])
    if GLOBAL_ADV_CACHE.is_file():
        try:
            rec = json.loads(GLOBAL_ADV_CACHE.read_text(encoding="utf-8"))
            if time.time() - float(rec.get("_cached_at") or 0) <= _CACHE_TTL:
                items = rec.get("items") or []
                _GLOBAL_ADV_MEMO.update(ok=True, items=items, error="")
                return True, items, ""
        except (json.JSONDecodeError, OSError, ValueError):
            pass
    pages = 2 if _github_token() else 1
    items: list[dict] = []
    ok_any = False
    err = ""
    for page in range(1, pages + 1):
        ok, data, e = _get_json(
            f"{GH_API}/advisories?per_page=100&page={page}",
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "nexus-audit/1.3"})
        if not ok or not isinstance(data, list):
            err = e or "non_list_response"
            break
        ok_any = True
        items.extend(a for a in data if isinstance(a, dict))
        if len(data) < 100:
            break
    if ok_any:
        GLOBAL_ADV_CACHE.parent.mkdir(parents=True, exist_ok=True)
        GLOBAL_ADV_CACHE.write_text(json.dumps(
            {"_cached_at": time.time(), "items": items},
            ensure_ascii=False), encoding="utf-8")
    _GLOBAL_ADV_MEMO.update(ok=ok_any, items=items, error=err)
    return ok_any, items, err


def query_github_advisories_affects(repo_name: str) -> dict:
    """M323：`GET /advisories?affects={repo_name}` 按包名拉历史 GHSA。

    裸 `/advisories` 只返回最近 100 条全网公告（Linux 内核 / WordPress
    插件），目标仓的历史公告早就被冲掉。affects 由 GitHub 服务端按
    package 过滤，能直接取到该包名下的公告。

    注意：Java 仓大多没有 package ecosystem 元数据，返回空**不代表**
    没公告，所以它只是增量来源，不替代全局列表。
    """
    name = (repo_name or "").strip()
    if not name:
        return {"ok": True, "total": 0, "ids": [], "url": "",
                "items": [], "error": "not_applicable"}
    memo_key = ("advisories_affects", name.lower())
    if memo_key in _REPO_MEMO:
        return _REPO_MEMO[memo_key]
    url = (f"{GH_API}/advisories?affects={urllib.parse.quote(name)}"
           f"&per_page=30")
    ok, data, err = _get_json(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "nexus-audit/1.3"})
    if not ok or not isinstance(data, list):
        res = {"ok": False, "total": 0, "ids": [], "items": [], "url": url,
               "error": err or "non_list_response"}
        _REPO_MEMO[memo_key] = res
        return res
    items = []
    for adv in data:
        if not isinstance(adv, dict):
            continue
        aid = adv.get("cve_id") or adv.get("ghsa_id") or ""
        if not aid:
            continue
        text = " ".join(str(adv.get(k) or "") for k in
                        ("summary", "description", "source_code_location"))
        items.append({"id": aid, "text": text})
    ids = list(dict.fromkeys(x["id"] for x in items))
    res = {"ok": True, "total": len(ids), "ids": ids[:5], "items": items,
           "url": url, "error": ""}
    _REPO_MEMO[memo_key] = res
    return res


def query_github_global_advisories(slug: str, unit: str = "",
                                   file: str = "", pages: int = 0) -> dict:
    """GitHub 全局漏洞库 `GET /advisories` + `?affects=`（M314/M323）。

    `/repos/{slug}/security-advisories` 只返回作者手动发布的公告（国内仓几乎
    永远为空）；真正的 GHSA 在全局库里。全局列表只覆盖最近 100 条，因此
    先按仓库名在 summary/description/source_code_location 里匹配，再用
    `?affects=<包名>` 补拉该包历史公告；两者都过方法名收窄，避免"仓里有
    公告"连坐。
    """
    # 注意：memo 必须带 unit/file —— 同一仓库不同方法命中不同公告，
    # 只按 slug 缓存会把上一个方法的结果连坐给下一个（M317 修）。
    memo_key = ("global_advisories", slug.lower(), unit, file)
    if memo_key in _REPO_MEMO:
        return _REPO_MEMO[memo_key]
    ok_any, data, err = load_global_advisories()
    name = (slug.split("/")[-1] if slug else "").lower()
    ids: list[str] = []
    items: list[dict] = []
    for adv in data:
        if not isinstance(adv, dict):
            continue
        text = " ".join(str(adv.get(k) or "") for k in
                        ("summary", "description", "source_code_location"))
        low = text.lower()
        if name and name not in low:
            continue
        if unit and not _unit_in_text(unit, file, text):
            continue
        # CVE 优先：判重时 CVE 命中要压过 GHSA（[300] 也按 CVE 断言）
        aid = adv.get("cve_id") or adv.get("ghsa_id") or ""
        if aid:
            ids.append(aid)
            items.append({"id": aid, "text": text})
    # M323：再按 affects=<包名> 拉一次该仓历史公告。裸 /advisories 只有最近
    # 100 条，历史 GHSA 翻不到；affects 是服务端过滤，不要求文本里出现仓库名。
    aff = {"ok": True, "total": 0, "ids": [], "url": "",
           "items": [], "error": "not_applicable"}
    if name:
        aff = query_github_advisories_affects(name)
        for adv in aff.get("items") or []:
            aid = str(adv.get("id") or "")
            adv_text = str(adv.get("text") or "")
            if not aid or aid in ids:
                continue
            if unit and not _unit_in_text(unit, file, adv_text):
                continue
            ids.append(aid)
            items.append({"id": aid, "text": adv_text})
    res = {"ok": ok_any, "total": len(ids), "ids": ids[:5],
           "url": f"{GH_API}/advisories", "items": items, "error": err,
           "affects": {"ok": aff.get("ok"), "total": aff.get("total"),
                       "url": aff.get("url"), "error": aff.get("error")}}
    _REPO_MEMO[memo_key] = res
    return res


def _class_wide_match(unit: str, file: str, text: str) -> bool:
    """CVE 只点名 Controller 类、未点名方法 → 整类命中。

    CVE-2026-77036 的官方描述只写
    EmailController/AliPayController/GeneratorController/GenConfigController，
    没有方法名；这类描述对类内任意方法都应判重号。反之，CVE-2026-108706
    明确写 downloadS3Storage handler / GET .../download/{id}，只能拦下载方法，
    不能连坐同文件的 uploadS3Storage。
    """
    raw = text or ""
    t = raw.lower()
    cls = (unit.rsplit(".", 1)[0] if "." in unit else Path(file).stem).strip()
    cls = cls.split(".")[-1]
    if len(cls) < 8 or cls.lower() in {c.lower() for c in _GENERIC_CLASSES}:
        return False
    if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(cls)}(?![A-Za-z0-9_])",
                     t, re.I):
        return False
    # 明确点名了另一个 lowerCamel 方法（downloadS3Storage handler）→ 不整类。
    # 有些 GHSA 只写 downloadS3Storage、不带 handler 后缀；因此按 lowerCamel
    # token 判断，并排除 URL 段（/api/s3Storage/...）与类名自身后缀。
    for tok in re.findall(r"(?<![A-Za-z0-9_])[a-z][A-Za-z0-9]*[A-Z][A-Za-z0-9]*(?![A-Za-z0-9_])", raw):
        if tok.lower() in cls.lower():
            continue
        if f"/{tok}" in raw or f"{tok}/" in raw:
            continue
        return False
    return True


def _unit_in_text(unit: str, file: str, text: str) -> bool:
    """CVE 描述是否精确提到这个方法；不能因为同文件别的 CVE 连坐。"""
    key = unit.split(".")[-1].split("#")[0].strip().lower()
    stem = Path(file).stem.lower() if file else ""
    t = (text or "").lower()
    # 必须按标识符边界匹配：CVE JSON 里的 "VulDB entry created" 曾把
    # `create` 误判成命中（M327）。子串匹配会让 created/creator 连坐。
    if key and len(key) > 3 and re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(key)}(?![A-Za-z0-9_])", t):
        return True
    if _class_wide_match(unit, file, text):
        return True
    return bool(not key and stem and len(stem) > 3 and re.search(
        rf"(?<![A-Za-z0-9_]){re.escape(stem)}(?![A-Za-z0-9_])", t))


# M317：泛化方法名 / 通用控制器 —— 这类组合全网搜只会烧配额，跳过。
_GENERIC_METHODS = frozenset({
    "apply", "test", "index", "login", "logout", "list", "page", "get",
    "create", "update", "delete", "save", "upload", "download", "export",
    "import", "query", "run", "execute", "handle", "main", "init", "info",
    "detail", "edit", "add", "remove", "search", "select",
})
_GENERIC_CLASSES = frozenset({
    "BaseController", "CommonController", "IndexController",
    "ApiController", "TestController",
})


def _is_distinctive(class_name: str, method_name: str) -> bool:
    """类名 + 方法名是否足够独特，值得发一次全网 Issue 搜索（M317）。"""
    cls = (class_name or "").strip()
    meth = (method_name or "").strip()
    if not cls or not meth or len(meth) < 6:
        return False
    if meth.lower() in _GENERIC_METHODS:
        return False
    if cls in _GENERIC_CLASSES:
        return False
    return True


def dedup(slug: str, category: str, unit: str, *,
          file: str = "", aliases: list[str] | None = None,
          allow_online: bool = True, use_cache: bool = True,
          repo_root: str | Path | None = None,
          class_name: str = "") -> dict:
    """四态查重。allow_online=False 时最多只能判 DUPLICATE_*，绝不 FRESH。"""
    aliases = list(aliases or [])
    # M314：二开仓自动挂上游主仓别名（cn.iocoder.yudao → ruoyi-vue-pro …）
    if repo_root:
        aliases += detect_upstream_aliases(repo_root)
    aliases = list(dict.fromkeys(a for a in aliases if a))
    cpath = _cache_path(slug, category, unit)
    # 离线模式绝不读在线缓存：缓存里可能是上次联网查到的 FRESH，
    # 直接复用会把“这次没查”伪装成“这次查过且 0 命中”。
    if use_cache and allow_online:
        cached = _cache_get(cpath)
        if cached and cached.get("status") in ALL_STATUSES:
            cached["from_cache"] = True
            return cached

    local = _local_match(slug, aliases, category, unit)
    if local:
        ids = [s.get("id") for s in local if s.get("id")]
        kind_cve = any(str(s.get("kind")) == "cve" for s in local)
        status = STATUS_CVE if kind_cve else STATUS_ISSUE
        rec = {
            "status": status, "matched_ids": ids,
            "sources": {"local_seed": {"ok": True, "total": len(local),
                                       "ids": ids}},
            "evidence_urls": [s.get("url") for s in local if s.get("url")],
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "coverage": {"local_seed": "checked", "online": "not_needed"},
        }
        if use_cache:
            _cache_put(cpath, rec)
        return rec

    if not allow_online:
        rec = {
            "status": STATUS_UNKNOWN, "matched_ids": [],
            "sources": {"local_seed": {"ok": True, "total": 0, "ids": []}},
            "evidence_urls": [],
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "coverage": {"local_seed": "checked", "online": "skipped"},
            "reason": "online_disabled: freshness cannot be claimed offline",
        }
        return rec

    nvd = query_nvd(f"{slug} {unit}" if unit else f"{slug} {category}")
    circl: dict = {"ok": False, "total": 0, "ids": [], "url": "",
                   "error": "not_needed"}
    cve_src = nvd
    if not nvd.get("ok"):
        circl = query_circl(slug)
        cve_src = circl
    issues = query_github_issues(slug, unit, category)
    ghsa = query_github_advisories(slug)
    _cls = class_name or (unit.split(".")[0] if "." in unit else "")
    _meth = unit.split(".")[-1].split("#")[0] if unit else ""

    matched: list[str] = []
    evidence: list[str] = []
    status = ""
    rec_reason = ""
    cve_hit = False
    circl_hit = False
    if cve_src.get("ok") and cve_src.get("total", 0) > 0:
        if cve_src is circl:
            # CIRCL 是“仓级”搜索，不能因为仓库有别的 CVE 就把每个端点都
            # 判重复；只在 CVE 描述里真的出现该方法/文件名时才命中。
            hits = [x for x in (circl.get("items") or [])
                    if _unit_in_text(unit, file, x.get("text", ""))]
            if hits:
                cve_hit = circl_hit = True
                matched += [x["id"] for x in hits]
                evidence.append(cve_src.get("url", ""))
        else:
            cve_hit = True
            matched += cve_src.get("ids") or []
            evidence.append(cve_src.get("url", ""))
    gh_hits = [x for x in (ghsa.get("items") or [])
               if x.get("id") and _unit_in_text(unit, file, x.get("text", ""))]

    if cve_hit:
        status = STATUS_CVE
    elif gh_hits:
        status = STATUS_ISSUE
        matched += [x["id"] for x in gh_hits]
        evidence.append(ghsa.get("url", ""))
    elif issues.get("ok") and issues.get("total", 0) > 0:
        status = STATUS_ISSUE
        matched += issues.get("ids") or []
        evidence.append(issues.get("url", ""))
    elif ghsa.get("ok") and ghsa.get("total", 0) > 0:
        # M290：仓库级公告列表不能连坐——只有公告文本真的命中方法/文件名
        # 才判重复；否则转 UNKNOWN 并注明"仓有公告但无方法级命中"。
        status = STATUS_UNKNOWN
        rec_reason = ("repo_advisories_no_unit_match: 仓库存在安全公告，"
                      "但均未命中本方法/文件，需人工查重后定性")

    # M317 短路早退：前面任一来源已命中 DUPLICATE_*，不再发全网查询；
    # 泛化类名/方法名也跳过（不记为 failed，仅 coverage 标 skipped）。
    global_issues: dict = {"ok": True, "total": 0, "ids": [], "url": "",
                           "error": "skipped_short_circuit"}
    global_adv: dict = {"ok": True, "total": 0, "ids": [], "url": "",
                        "error": "skipped_short_circuit"}
    if not status:
        global_adv = query_github_global_advisories(slug, unit, file)
        if _is_distinctive(_cls, _meth):
            global_issues = query_github_issues_global(
                _cls, _meth,
                repo_name=(slug.split("/")[-1] if slug else ""))
        else:
            global_issues = {"ok": True, "total": 0, "ids": [], "url": "",
                             "error": "skipped_generic"}
        _gadv_items = [x for x in (global_adv.get("items") or []) if x.get("id")]
        _gadv_cve = [x for x in _gadv_items
                     if str(x.get("id", "")).upper().startswith("CVE-")]
        _gissue_hit = bool(global_issues.get("ok")
                           and global_issues.get("total", 0) > 0)
        if _gadv_cve:
            status = STATUS_CVE
            matched += [x["id"] for x in _gadv_cve]
            evidence.append(global_adv.get("url", ""))
        elif _gadv_items:
            status = STATUS_ISSUE
            matched += [x["id"] for x in _gadv_items]
            evidence.append(global_adv.get("url", ""))
        elif _gissue_hit:
            status = STATUS_ISSUE
            matched += global_issues.get("ids") or []
            evidence.append(global_issues.get("url", ""))
        elif not (cve_src.get("ok") and issues.get("ok") and ghsa.get("ok")
                  and global_issues.get("ok") and global_adv.get("ok")):
            status = STATUS_UNKNOWN
        else:
            status = STATUS_FRESH

    sources = {"nvd": nvd, "circl": circl, "github_issues": issues,
               "github_advisories": ghsa,
               "github_global_issues": global_issues,
               "github_global_advisories": global_adv,
               "cve_org": {"ok": nvd.get("ok", False) or circl.get("ok", False),
                           "note": "CVE.org records via NVD/CIRCL"}}

    rec = {
        "status": status, "matched_ids": [x for x in matched if x],
        "sources": sources,
        "evidence_urls": [x for x in evidence if x],
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "coverage": {
            "local_seed": "checked",
            "nvd": "checked" if nvd.get("ok") else "failed",
            "circl": ("checked" if circl.get("ok") and not circl_hit
                      else "checked_hit" if circl_hit
                      else "skipped" if nvd.get("ok") else "failed"),
            "github_issues": "checked" if issues.get("ok") else "failed",
            "github_advisories": ("checked" if ghsa.get("ok")
                                  else "failed"),
            "github_global_issues": (
                "skipped" if str(global_issues.get("error", "")).startswith("skipped")
                else "checked" if global_issues.get("ok") else "failed"),
            "github_global_advisories": (
                "skipped" if str(global_adv.get("error", "")).startswith("skipped")
                else "checked" if global_adv.get("ok") else "failed"),
            "cve_org": "via_nvd" if nvd.get("ok") else
                       "via_circl" if circl.get("ok") else "unchecked",
        },
    }
    if status == STATUS_UNKNOWN:
        rec["reason"] = (rec_reason if rec_reason else
                         "one_or_more_sources_failed: freshness not claimed")
    if use_cache:
        _cache_put(cpath, rec)
    return rec
