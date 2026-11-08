"""M347：组织矿脉深扫（Organization Vein Hunting）。

只负责拉取组织下的业务仓并复用 daily_hunt.process_repo 做大深度扫描；
不做新的规则判定。CLI 入口：python cli.py org-hunt --orgs ...
"""
from __future__ import annotations

import json
from pathlib import Path

from core.context import target_scout
from core.context import daily_hunt


def list_org_repos(org: str, languages: list[str] | None = None,
                   allow_online: bool = True, per_page: int = 100) -> list[dict]:
    """拉取 GitHub 组织/用户的非归档、非 fork 业务仓。"""
    org = str(org or "").strip().strip("/")
    if not org:
        return []
    langs = {x.lower() for x in (languages or []) if x}
    urls = [
        f"https://api.github.com/orgs/{org}/repos?per_page={per_page}&sort=pushed",
        f"https://api.github.com/users/{org}/repos?per_page={per_page}&sort=pushed",
    ]
    data = None
    for url in urls:
        ok, payload, _err = target_scout._get(url)
        if ok and isinstance(payload, list):
            data = payload
            break
    if data is None:
        return []
    out: list[dict] = []
    for it in data:
        if not isinstance(it, dict) or it.get("archived") or it.get("fork"):
            continue
        slug = str(it.get("full_name") or "")
        if not slug:
            continue
        lang = str(it.get("language") or "")
        if langs and lang.lower() not in langs:
            continue
        desc = str(it.get("description") or "")
        topics = [t for t in (it.get("topics") or []) if isinstance(t, str)]
        if target_scout.is_tutorial(slug, desc, topics):
            continue
        if target_scout.is_tool_lib(slug, desc, topics):
            continue
        out.append({"slug": slug, "stars": int(it.get("stargazers_count") or 0),
                    "language": lang, "pushed_at": it.get("pushed_at") or "",
                    "description": desc})
    out.sort(key=lambda x: x.get("pushed_at") or "", reverse=True)
    return out


def run(*, orgs: list[str], languages: list[str] | None = None,
        max_roots: int = 25, min_units: int = 5, limit: int = 0,
        report: Path | str | None = None,
        json_path: Path | str | None = None,
        packs_dir: Path | str | None = None,
        offline: bool = False, dedup_online: bool = True,
        evict_cache: bool = False, repo_timeout: int = 300) -> dict:
    """扫描多个组织；返回结构化摘要并写 Markdown/JSON。"""
    langs = [str(x) for x in (languages or ["java", "python"]) if str(x)]
    repos: list[dict] = []
    seen: set[str] = set()
    for org in orgs:
        for r in list_org_repos(org, langs, allow_online=not offline):
            if r["slug"] not in seen:
                seen.add(r["slug"])
                repos.append(r)
    report_path = Path(report) if report else Path("ORG_HUNT_REPORT.md")
    json_file = Path(json_path) if json_path else Path("benchmarks/results/org_hunt.json")
    packs = Path(packs_dir) if packs_dir else Path("benchmarks/results/org_hunt_packs")
    if not repos:
        return {"ok": False, "error": "no repos", "repos": [], "records": [],
                "report": str(report_path), "json": str(json_file)}
    cap = int(limit) if int(limit) > 0 else len(repos)
    items = repos[:cap]
    res = daily_hunt.run(
        languages=langs, days=3650, limit=len(items), min_stars=0,
        max_stars=1_000_000, max_roots=max_roots,
        state_path=Path(".tmp") / "org_hunt_state.json",
        report=report_path, json_path=json_file, packs_dir=packs,
        evict_cache=evict_cache, offline=offline, dedup_online=dedup_online,
        cooldown_days=0, min_units=min_units, repo_timeout=repo_timeout,
        scout_fn=lambda **kw: {"ok": True, "source": "org_hunt",
                               "items": [{"slug": x["slug"]} for x in items]},
    )
    records = list(res.get("records") or [])
    summary = {
        "ok": True,
        "orgs": list(orgs),
        "repos": [x["slug"] for x in items],
        "scanned": int((res.get("daily") or {}).get("scanned") or 0),
        "new_roots": int((res.get("daily") or {}).get("new_roots") or 0),
        "board_a": int((res.get("daily") or {}).get("board_a") or 0),
        "records": records,
        "report": str(report_path),
        "json": str(json_file),
    }
    return summary
