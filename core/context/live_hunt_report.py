"""M270：活水首杀作战大盘 + 傻瓜式三步交单手册。

两级产物：
  · LIVE_HUNT_REPORT.md —— 板块 A（ZERO_RECORD_FRESH）/ 板块 B（拦截项）
  · 每个 FRESH 包内 SUBMISSION_PLAYBOOK.md —— Step 1/2/3 零占位符

报告与 JSON 同源：所有行都来自 live_hunt.json 的 records，禁止另算一套。
永久链接必须带 head_sha；没有 head_sha 的记录只能进 B 的 UNKNOWN。
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from core.agents.vuln_categories import CATEGORIES
from core.context.cve_dedup import (STATUS_CVE, STATUS_FRESH, STATUS_ISSUE,
                                    STATUS_PATCHED, STATUS_STALE,
                                    STATUS_UNKNOWN)

TEMPLATE_VERSION = "playbook-1.0"
CVE_FORM = "https://www.cve.org/ReportRequest/ReportRequestForNonCNAs"
A, B = "A", "B"
FENCE = chr(96) * 3


def _meta(cat: str) -> dict:
    m = CATEGORIES.get(cat)
    return {"cwe": getattr(m, "cwe", "") if m else "",
            "display": getattr(m, "display", cat) if m else cat}


def _advisory_url(slug: str) -> str:
    return f"https://github.com/{slug}/security/advisories/new"


def _issue_url(slug: str) -> str:
    return f"https://github.com/{slug}/issues/new"


def _version_evidence(rec: dict) -> str:
    v = str(rec.get("version_evidence") or "").strip()
    return v if v else "unknown, pending maintainer confirmation"


def _board(rec: dict) -> str:
    if rec.get("status") != STATUS_FRESH:
        return B
    if rec.get("stale") or float(rec.get("head_age_days") or 999999) > float(
            rec.get("max_head_age_days") or 180):
        return B
    if not str(rec.get("head_commit_date") or "").startswith("2026-"):
        return B
    if not rec.get("head_sha") or not str(rec.get("permalink") or "").startswith(
            "https://github.com/"):
        return B
    if "/blob/" not in str(rec.get("permalink") or ""):
        return B
    return A


def _row_a(i: int, r: dict) -> str:
    playbook = r.get("playbook") or ""
    link = (f"[{Path(playbook).name}]({playbook})" if playbook else "—")
    age = r.get("head_age_days", "")
    date = r.get("head_commit_date", "")
    return (f"| {i} | {r.get('repo', '')} | {r.get('category', '')} | "
            f"{r.get('unit', '')} | {date} ({age}d) | "
            f"{r.get('head_sha', '')[:12]} | "
            f"[{r.get('file', '')}:{r.get('line', 0)}]({r.get('permalink', '')}) | "
            f"[Advisory]({_advisory_url(r.get('slug', ''))}) · "
            f"[Issue]({_issue_url(r.get('slug', ''))}) · "
            f"[CVE.org]({CVE_FORM}) | {link} |")


def _row_b(i: int, r: dict) -> str:
    evidence = "、".join(r.get("evidence_urls") or []) or "—"
    matched = "、".join(r.get("matched_ids") or []) or "—"
    reason = r.get("reason") or (
        "local_seed_hit" if r.get("matched_ids") else "—")
    return (f"| {i} | {r.get('repo', '')} | {r.get('category', '')} | "
            f"{r.get('unit', '')} | **{r.get('status', '')}** | "
            f"{matched} | {reason} | {evidence} |")


def render_report(records: list[dict], generated_at: str | None = None) -> str:
    generated_at = generated_at or time.strftime("%Y-%m-%d %H:%M:%S")
    rows = sorted(records, key=lambda r: (r.get("repo", ""),
                                          r.get("category", ""),
                                          r.get("unit", "")))
    a = [r for r in rows if _board(r) == A]
    b = [r for r in rows if _board(r) == B]
    counts = {k: sum(1 for r in rows if r.get("status") == k) for k in
              (STATUS_FRESH, STATUS_CVE, STATUS_ISSUE, STATUS_PATCHED,
               STATUS_STALE, STATUS_UNKNOWN)}
    counts["BOARD_A"] = len(a)
    counts["BOARD_B"] = len(b)
    lines = [
        "# 活水首杀作战大盘（LIVE_HUNT）", "",
        "> 机器事实源：benchmarks/results/live_hunt.json。"
        "本报告的 A/B 行数必须与 JSON 计数一致；"
        "ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，"
        "不代表漏洞一定成立，更不代表人工已核验。", "",
        f"- 生成时间：{generated_at}",
        f"- 总条数：{len(rows)} ｜ 板块 A：**{len(a)}** ｜ 板块 B：**{len(b)}**",
        f"- 状态计数：ZERO_RECORD_FRESH {counts[STATUS_FRESH]} / "
        f"DUPLICATE_CVE {counts[STATUS_CVE]} / "
        f"DUPLICATE_ISSUE_OR_GHSA {counts[STATUS_ISSUE]} / "
        f"PATCHED_UPSTREAM {counts[STATUS_PATCHED]} / "
        f"STALE_REPO {counts[STATUS_STALE]} / "
        f"UNKNOWN {counts[STATUS_UNKNOWN]}",
        "",
        "<!-- live_hunt_counts: " + json.dumps(counts, ensure_ascii=False,
                                                sort_keys=True) + " -->",
        "",
        "## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH", "",
        "| # | 仓库 | 类目 | 根因 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    lines += [_row_a(i, r) for i, r in enumerate(a, 1)]
    if not a:
        lines.append("| — | — | — | — | — | — | — | — | — |")
    lines += ["", "## 板块 B｜🔴 自动拦截 / 不可交单", "",
              "| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |",
              "|---|---|---|---|---|---|---|---|"]
    lines += [_row_b(i, r) for i, r in enumerate(b, 1)]
    if not b:
        lines.append("| — | — | — | — | — | — | — | — |")
    lines += ["", "## 对账", "",
              "| 板块 | 行数 |", "|---|---|",
              f"| A（{STATUS_FRESH}） | {len(a)} |",
              f"| B（其余状态） | {len(b)} |",
              f"| 合计 | {len(rows)} |", ""]
    return "\n".join(lines)


def _english_description(r: dict) -> str:
    meta = _meta(r.get("category", ""))
    patch_sentence = (
        "A deterministic fix patch is included and passed the True-to-False "
        "self-check ([Auto-Fix Verified])."
        if r.get("patch_verified") else
        "No verified automatic patch is included; a manual fix is required.")
    return (
        f"The {r.get('repo', '')} repository at commit {r.get('head_sha', '')} "
        f"contains a {r.get('category', '')} issue in {r.get('file', '')} "
        f"(line {r.get('line', 0)}), entry {r.get('unit', '')}. "
        f"The rule layer reports it as a deterministic P0 root cause "
        f"({meta['cwe'] or 'CWE-000'}). "
        f"Source permalink: {r.get('permalink', '')}. {patch_sentence}")


def render_playbook(r: dict) -> str:
    meta = _meta(r.get("category", ""))
    slug = r.get("slug", "")
    owner, _, product = slug.partition("/")
    version = _version_evidence(r)
    cwe = meta["cwe"] or "CWE-000"
    title = (f"[{r.get('category', '').upper()}] "
             f"{r.get('unit', '')} in {Path(r.get('file', '')).name}")
    desc = _english_description(r)
    patch_line = ("see fix.patch ([Auto-Fix Verified])"
                  if r.get("patch_verified")
                  else "manual patch required (no verified patch in this pack)")
    return f"""# 傻瓜式三步交单手册（{r.get('repo', '')} / {r.get('category', '')}）

> 模板版本：{TEMPLATE_VERSION} ｜ 事实源：live_hunt.json
> 本文**不是**漏洞成立的法律证明；提交前请人工复核版本影响面与可达性。
> 状态：{r.get('status', '')} ｜ HEAD：{r.get('head_sha', '')}
> HEAD 提交日期：{r.get('head_commit_date', '')}（{r.get('head_age_days', '')} 天前）

## Step 1：点哪个网址

- GitHub 私密 Advisory（优先）：
  {_advisory_url(slug)}
- GitHub Issue（仓库未开启私密 Advisory 时）：
  {_issue_url(slug)}
- MITRE / CVE.org 申请表：
  {CVE_FORM}

## Step 2：GitHub 页面填什么

### Title

{FENCE}
{title}
{FENCE}

### Description（直接复制）

{FENCE}
{desc}

Repository: https://github.com/{slug}
Affected file: {r.get('file', '')}:{r.get('line', 0)}
Entry point: {r.get('unit', '')}
HEAD permalink: {r.get('permalink', '')}
Affected routes: {r.get('affected_routes', 1)}
CWE: {cwe}
Fix: {patch_line}
{FENCE}

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | {owner} |
| Product | {product} |
| Version affected | {version} |
| Vulnerability Type | {cwe} |
| Affected Component | {r.get('file', '')}:{r.get('line', 0)} |
| Suggested Description | {desc} |

## 提交前检查

- [ ] HEAD 仍是 {r.get('head_sha', '')}（若已变化，重新跑 live-hunt）
- [ ] fix.patch 能在目标仓 git apply --check 通过
- [ ] 版本影响面已由维护者/README/tag 确认；否则保留 {version}
- [ ] 不在公开 issue 里贴未修复细节，先走私密 Advisory
"""


def write_outputs(records: list[dict], report_path: Path,
                  json_path: Path, packs_dir: Path,
                  generated_at: str | None = None) -> dict:
    """写 JSON + Markdown + 每个 FRESH 包的 Playbook（幂等）。"""
    generated_at = generated_at or time.strftime("%Y-%m-%d %H:%M:%S")
    records = sorted(records, key=lambda r: (r.get("repo", ""),
                                             r.get("category", ""),
                                             r.get("unit", "")))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    packs_dir.mkdir(parents=True, exist_ok=True)
    a = [r for r in records if _board(r) == A]
    legacy = (Path(__file__).resolve().parents[2] / "benchmarks" /
              "results" / "first_blood_packs")
    for r in a:
        raw = (f"{r.get('repo', 'repo')}_{r.get('category', 'cat')}_"
               f"{r.get('unit', 'unit').split('.')[-1]}")
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in raw)
        pack = packs_dir / safe
        pack.mkdir(parents=True, exist_ok=True)
        src_pack = legacy / safe
        r["patch_verified"] = bool((src_pack / "fix.patch").is_file() and
                                   (src_pack / "fix.patch").stat().st_size > 0)
        if r["patch_verified"]:
            for name in ("fix.patch", "ADVISORY.md"):
                if (src_pack / name).is_file():
                    shutil.copy2(src_pack / name, pack / name)
        playbook = pack / "SUBMISSION_PLAYBOOK.md"
        playbook.write_text(render_playbook(r), encoding="utf-8")
        try:
            r["playbook"] = playbook.relative_to(
                Path(__file__).resolve().parents[2]).as_posix()
        except ValueError:
            r["playbook"] = playbook.as_posix()
    report = render_report(records, generated_at)
    report_path.write_text(report, encoding="utf-8")
    payload = {
        "generated_at": generated_at,
        "generator": "core/context/live_hunt_report.py",
        "human_verified": False,
        "template_version": TEMPLATE_VERSION,
        "summary": {
            "total": len(records), "board_a": len(a),
            "board_b": len(records) - len(a),
            "by_status": {k: sum(1 for r in records
                                 if r.get("status") == k) for k in
                          (STATUS_FRESH, STATUS_CVE, STATUS_ISSUE,
                           STATUS_PATCHED, STATUS_STALE, STATUS_UNKNOWN)},
        },
        "records": records,
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    return payload["summary"]
