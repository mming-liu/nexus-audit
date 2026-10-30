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


def query_circl(slug: str) -> dict:
    """CIRCL CVE Search（NVD 在此网络被 TLS 阻断时的只读兜底）。"""
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
    for url in urls:
        ok, data, err = _get_json(url)
        if not ok or not isinstance(data, dict):
            last_err = err
            continue
        total = int(data.get("total_count") or 0)
        ids: list[str] = []
        items: list[dict] = []
        results = data.get("results") or {}
        for key in ("nvd", "cvelistv5"):
            for item in (results.get(key) or [])[:20]:
                if isinstance(item, list) and item:
                    cid = str(item[0]).upper()
                    ids.append(cid)
                    items.append({"id": cid,
                                  "text": json.dumps(item[1],
                                                     ensure_ascii=False)[:6000]})
        res = {"ok": True, "total": total, "ids": ids[:5], "items": items,
               "url": url, "error": ""}
        _REPO_MEMO[memo_key] = res
        return res
    res = {"ok": False, "total": 0, "ids": [],
           "url": urls[0] if urls else "", "error": last_err or "no_url"}
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


def _unit_in_text(unit: str, file: str, text: str) -> bool:
    """CVE 描述是否精确提到这个方法；不能因为同文件别的 CVE 连坐。"""
    key = unit.split(".")[-1].split("#")[0].strip().lower()
    stem = Path(file).stem.lower() if file else ""
    t = (text or "").lower()
    if key and len(key) > 3:
        return key in t
    return bool(stem and len(stem) > 3 and stem in t)


def dedup(slug: str, category: str, unit: str, *,
          file: str = "", aliases: list[str] | None = None,
          allow_online: bool = True, use_cache: bool = True) -> dict:
    """四态查重。allow_online=False 时最多只能判 DUPLICATE_*，绝不 FRESH。"""
    aliases = aliases or []
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
    sources = {"nvd": nvd, "circl": circl, "github_issues": issues,
               "github_advisories": ghsa,
               "cve_org": {"ok": nvd.get("ok", False) or circl.get("ok", False),
                           "note": "CVE.org records via NVD/CIRCL"}}
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
    if cve_hit:
        status = STATUS_CVE
    elif ghsa.get("ok") and ghsa.get("total", 0) > 0:
        # M290：仓库级公告列表不能连坐——只有公告文本真的命中方法/文件名
        # 才判重复；否则转 UNKNOWN 并注明"仓有公告但无方法级命中"。
        gh_hits = [x for x in (ghsa.get("items") or [])
                   if x.get("id") and _unit_in_text(unit, file,
                                                    x.get("text", ""))]
        if gh_hits:
            status = STATUS_ISSUE
            matched += [x["id"] for x in gh_hits]
            evidence.append(ghsa.get("url", ""))
        else:
            status = STATUS_UNKNOWN
            rec_reason = ("repo_advisories_no_unit_match: 仓库存在安全公告，"
                          "但均未命中本方法/文件，需人工查重后定性")
    elif issues.get("ok") and issues.get("total", 0) > 0:
        status = STATUS_ISSUE
        matched += issues.get("ids") or []
        evidence.append(issues.get("url", ""))
    elif not (cve_src.get("ok") and issues.get("ok") and ghsa.get("ok")):
        status = STATUS_UNKNOWN
    else:
        status = STATUS_FRESH

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
