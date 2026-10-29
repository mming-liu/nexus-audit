"""M271：live-hunt 流水线（拉 HEAD → 规则扫描 → 存活 → 查重 → 大盘）。"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from core.context import authz_guard, cve_dedup, upstream_sync
from core.context.live_hunt_report import (CVE_FORM, _advisory_url,
                                           _issue_url, write_outputs)

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "cli.py"
TRIAGE = ROOT / "benchmarks" / "results" / "llm_root_triage.json"
SKIP_CATEGORIES = {"cors"}
MAX_HEAD_AGE_DAYS = 180
_TRIAGE_CACHE: dict | None = None


def slug_from_repo(repo: Path, explicit: str | None = None) -> str:
    if explicit:
        return upstream_sync.normalize_slug(explicit) or explicit
    rc, out = upstream_sync._git(["remote", "get-url", "origin"], cwd=repo,
                                 timeout=15)
    if rc == 0:
        slug = upstream_sync.normalize_slug(out)
        if slug:
            return slug
    return repo.name


def scan_roots(repo: Path, timeout: int = 900) -> tuple[list[dict], str]:
    """调现有 scan --auto --offline，返回 root_causes 与临时日志。

    临时目录必须落在工作区：DSH 沙箱下系统 %TEMP% 的 mkdtemp 目录带
    0o700 ACL，子进程再写会被 WinError 5 拒绝。
    """
    td = ROOT / ".cache" / "live_hunt_tmp" / uuid.uuid4().hex
    td.mkdir(parents=True, exist_ok=True)
    try:
        out = td / "summary.json"
        rep = td / "report.md"
        cmd = [sys.executable, str(CLI), "scan", str(repo), "--auto",
               "--offline", "--summary-json", str(out), "--output", str(rep)]
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        if not out.is_file():
            raise RuntimeError(f"scan failed rc={p.returncode}: "
                               f"{(p.stdout + p.stderr)[-500:]}")
        data = json.loads(out.read_text(encoding="utf-8"))
        return data.get("root_causes") or [], (p.stdout + p.stderr)
    finally:
        shutil.rmtree(td, ignore_errors=True)


def _triage_index() -> dict:
    global _TRIAGE_CACHE
    if _TRIAGE_CACHE is not None:
        return _TRIAGE_CACHE
    out: dict = {}
    if TRIAGE.is_file():
        try:
            data = json.loads(TRIAGE.read_text(encoding="utf-8"))
            for r in data.get("roots") or []:
                out[(r.get("repo", ""), r.get("category", ""),
                     r.get("representative", ""))] = r.get("verdict", "")
        except json.JSONDecodeError:
            out = {}
    _TRIAGE_CACHE = out
    return out


def _triage_verdict(slug: str, category: str, unit: str) -> str:
    name = slug.split("/")[-1]
    return _triage_index().get((name, category, unit), "")


def _rel(repo: Path, file: str) -> str:
    try:
        return Path(file).resolve().relative_to(repo.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(file).name


def run_one(repo: Path, *, slug: str | None = None, offline: bool = False,
            limit: int = 0, dedup_online: bool = True,
            max_head_age_days: int = MAX_HEAD_AGE_DAYS,
            roots: list[dict] | None = None,
            dedup_fn=None) -> list[dict]:
    repo = Path(repo).resolve()
    slug = slug_from_repo(repo, slug)
    head = upstream_sync.local_head(repo)
    if head.get("status") != "OK":
        head = {"status": "UNKNOWN", "head_sha": "", "reason":
                head.get("reason", "not_a_git_repo")}
    roots = roots if roots is not None else scan_roots(repo)[0]
    roots = [r for r in roots if r.get("category") not in SKIP_CATEGORIES]
    if limit:
        roots = roots[:limit]
    out: list[dict] = []
    for rc in roots:
        cat = rc.get("category", "")
        unit = rc.get("unit_name") or rc.get("representative") or ""
        file = rc.get("file", "")
        line = int(rc.get("line") or 0)
        rel = _rel(repo, file)
        rec = {
            "repo": slug.split("/")[-1] if "/" in slug else slug,
            "slug": slug, "category": cat, "unit": unit,
            "file": rel, "line": line,
            "affected_routes": int(rc.get("affected_routes") or 1),
            "head_sha": head.get("head_sha", ""),
            "head_commit_date": head.get("head_commit_date", ""),
            "head_age_days": head.get("head_age_days", 999999.0),
            "max_head_age_days": max_head_age_days,
            "stale": False,
            "permalink": "", "status": cve_dedup.STATUS_UNKNOWN,
            "matched_ids": [], "sources": {}, "evidence_urls": [],
            "checked_at": "",
            "reason": "", "version_evidence": "",
            "triage": _triage_verdict(slug, cat, unit),
            "advisory_url": _advisory_url(slug),
            "issue_url": _issue_url(slug), "cve_form_url": CVE_FORM,
        }
        if not rec["head_sha"]:
            rec["reason"] = f"head_unavailable: {head.get('reason', '')}"
            out.append(rec)
            continue
        if not rec["head_commit_date"]:
            rec["status"] = cve_dedup.STATUS_UNKNOWN
            rec["reason"] = "head_date_unknown: 无法证明仓库仍活跃"
            out.append(rec)
            continue
        # M286：HEAD 提交就在今天时 head_age_days == 0.0，`or 999999`
        # 会把“刚提交”误判成“停更”；必须只把 None/空串当未知。
        raw_age = rec.get("head_age_days")
        try:
            age = float(raw_age) if raw_age not in (None, "") else 999999.0
        except (TypeError, ValueError):
            age = 999999.0
        rec["stale"] = age > float(max_head_age_days)
        if rec["stale"]:
            rec["status"] = cve_dedup.STATUS_STALE
            rec["reason"] = (f"stale_repo: HEAD {rec['head_commit_date']} "
                             f"({age:.0f}d > {max_head_age_days}d)")
            rec["permalink"] = upstream_sync.head_permalink(
                slug, rec["head_sha"], rel, line)
            out.append(rec)
            continue
        if cat == "authz":
            guard = authz_guard.verify_service_guard(repo, unit, rel)
            if guard.get("guarded"):
                rec["status"] = cve_dedup.STATUS_UNKNOWN
                rec["reason"] = (f"service_guard: {guard.get('evidence', '')} "
                                 f"({guard.get('method', '')})")
                rec["permalink"] = upstream_sync.head_permalink(
                    slug, rec["head_sha"], rel, line)
                out.append(rec)
                continue
        if rec["triage"] in ("LIKELY_FP_GUARDED", "NEEDS_HUMAN"):
            rec["status"] = cve_dedup.STATUS_UNKNOWN
            rec["reason"] = f"llm_triage_{rec['triage'].lower()}: 不进入首杀板块"
            rec["permalink"] = upstream_sync.head_permalink(
                slug, rec["head_sha"], rel, line)
            out.append(rec)
            continue
        alive = upstream_sync.verify_unit_alive_on_head(
            repo, rel, unit, rec["head_sha"])
        if alive.get("status") != "ALIVE":
            rec["status"] = cve_dedup.STATUS_PATCHED
            rec["reason"] = alive.get("reason", "patched_upstream")
            rec["evidence_urls"] = [upstream_sync.head_permalink(
                slug, rec["head_sha"], rel, max(1, alive.get("line") or line))]
            out.append(rec)
            continue
        rec["line"] = int(alive.get("line") or line)
        rec["permalink"] = upstream_sync.head_permalink(
            slug, rec["head_sha"], rel, rec["line"])
        dd = (dedup_fn or cve_dedup.dedup)(
            slug, cat, unit, file=rel,
            aliases=[rec["repo"], Path(repo).name],
            allow_online=(not offline) and dedup_online)
        rec.update({k: dd.get(k, rec.get(k)) for k in
                    ("status", "matched_ids", "sources", "evidence_urls",
                     "checked_at", "coverage")})
        rec["reason"] = dd.get("reason", "")
        out.append(rec)
    return out


def run(repos: list[str], *, offline: bool = False, limit: int = 0,
        report: Path | None = None, json_path: Path | None = None,
        packs_dir: Path | None = None, slug: str | None = None,
        max_head_age_days: int = MAX_HEAD_AGE_DAYS,
        dry_run: bool = False) -> dict:
    report = report or (ROOT / "LIVE_HUNT_REPORT.md")
    json_path = json_path or (ROOT / "benchmarks" / "results" /
                              "live_hunt.json")
    packs_dir = packs_dir or (ROOT / "benchmarks" / "results" /
                              "live_hunt_packs")
    all_records: list[dict] = []
    for raw in repos:
        slug_val = upstream_sync.normalize_slug(raw) if "/" in raw and \
            not Path(raw).exists() else None
        if slug_val and not offline:
            sync = upstream_sync.sync_repo(slug_val)
            if sync.get("status") != "OK":
                all_records.append({
                    "repo": slug_val.split("/")[-1], "slug": slug_val,
                    "category": "", "unit": "", "file": "", "line": 0,
                    "head_sha": "", "permalink": "",
                    "status": cve_dedup.STATUS_UNKNOWN,
                    "reason": f"upstream_sync_failed: {sync.get('reason', '')}",
                    "matched_ids": [], "evidence_urls": [],
                    "checked_at": "",
                })
                continue
            repo = Path(sync["path"])
        else:
            repo = Path(raw).resolve()
            if not repo.exists() and slug_val:
                cached = (upstream_sync.CACHE_ROOT /
                          upstream_sync.safe_dirname(slug_val))
                if cached.is_dir():
                    repo = cached
            if not repo.exists():
                all_records.append({
                    "repo": raw, "slug": slug_val or raw, "category": "",
                    "unit": "", "file": "", "line": 0, "head_sha": "",
                    "permalink": "", "status": cve_dedup.STATUS_UNKNOWN,
                    "reason": "repo_not_found", "matched_ids": [],
                    "evidence_urls": [], "checked_at": "",
                })
                continue
        try:
            all_records += run_one(repo, slug=slug_val or slug,
                                   offline=offline, limit=limit,
                                   max_head_age_days=max_head_age_days)
        except Exception as e:                                # noqa: BLE001
            all_records.append({
                "repo": repo.name, "slug": slug_val or repo.name,
                "category": "", "unit": "", "file": "", "line": 0,
                "head_sha": "", "permalink": "",
                "status": cve_dedup.STATUS_UNKNOWN,
                "reason": f"pipeline_error: {type(e).__name__}: {e}"[:400],
                "matched_ids": [], "evidence_urls": [], "checked_at": "",
            })
    if dry_run:
        return {"summary": {"total": len(all_records)}, "records": all_records}
    return {"summary": write_outputs(all_records, report, json_path,
                                     packs_dir),
            "records": all_records}
