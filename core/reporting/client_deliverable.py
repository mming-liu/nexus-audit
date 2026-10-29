"""M274：客户离线交付五件套。

不重新实现扫描器：调用现有 scan --auto --offline，把 summary.json /
fix_report_auto.md / PoC 目录整理成商业交付格式。默认零出网。
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "cli.py"
FENCE = chr(96) * 3
LANG_BY_EXT = {".java": "Java", ".py": "Python", ".sol": "Solidity",
               ".js": "JavaScript", ".ts": "TypeScript", ".go": "Go",
               ".php": "PHP", ".rb": "Ruby", ".kt": "Kotlin"}
SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", ".idea",
             "__pycache__", ".venv", "venv", "vendor", "coverage"}


def loc_stats(target: Path) -> dict:
    by_lang: dict[str, dict] = {}
    total_files = total_lines = 0
    for p in target.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.parts):
            continue
        lang = LANG_BY_EXT.get(p.suffix.lower())
        if not lang:
            continue
        try:
            if p.stat().st_size > 2_000_000:
                continue
            n = p.read_text(encoding="utf-8", errors="ignore").count("\n") + 1
        except OSError:
            continue
        rec = by_lang.setdefault(lang, {"files": 0, "lines": 0})
        rec["files"] += 1
        rec["lines"] += n
        total_files += 1
        total_lines += n
    return {"by_language": by_lang, "files": total_files, "lines": total_lines}


def price_table(loc: int) -> list[dict]:
    if loc <= 5_000:
        lo, hi = 8_000, 15_000
    elif loc <= 20_000:
        lo, hi = 15_000, 45_000
    elif loc <= 100_000:
        lo, hi = 45_000, 120_000
    else:
        lo, hi = 120_000, 300_000
    return [{"tier": "基础规则层交付", "loc": f"0-{max(loc, 5000):,}",
             "price": f"¥{lo:,} - ¥{hi:,}",
             "note": "规则层 + 确定性补丁；不含人工渗透与业务逻辑深挖"}]


def run_scan(target: Path, work: Path, with_fix: bool = True,
             with_poc: bool = True) -> tuple[dict, str, str]:
    work.mkdir(parents=True, exist_ok=True)
    summary_p = work / "summary.json"
    report_p = work / "report.md"
    fix_p = work / "fix_report_auto.md"
    poc_dir = work / "poc"
    cmd = [sys.executable, str(CLI), "scan", str(target), "--auto",
           "--offline", "--summary-json", str(summary_p),
           "--output", str(report_p)]
    if with_fix:
        cmd.append("--fix")
    if with_poc:
        cmd += ["--emit-poc", str(poc_dir)]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=1800)
    if not summary_p.is_file():
        raise RuntimeError(f"scan failed rc={p.returncode}: "
                           f"{(p.stdout + p.stderr)[-800:]}")
    summary = json.loads(summary_p.read_text(encoding="utf-8"))
    fix_text = fix_p.read_text(encoding="utf-8") if fix_p.is_file() else ""
    return summary, (p.stdout + p.stderr), fix_text


def _diff_blocks(fix_text: str) -> list[str]:
    """从 fix_report_auto.md 提取统一 diff（报告用 ---/+++，没有 diff --git）。"""
    lines = fix_text.splitlines()
    out: list[str] = []
    seen: set[str] = set()
    i = 0
    while i < len(lines):
        if not lines[i].startswith("--- a/"):
            i += 1
            continue
        block = [lines[i]]
        i += 1
        while i < len(lines):
            ln = lines[i]
            if ln.startswith(("--- a/", "## ", "> ", FENCE)):
                break
            block.append(ln)
            i += 1
        text = "\n".join(block).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text + "\n")
    return out


def _root_rows(summary: dict) -> list[dict]:
    return summary.get("root_causes") or []


def _baseline_keys(path: Path | None) -> set[tuple[str, str]]:
    if not path or not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    roots = data.get("root_causes") if isinstance(data, dict) else None
    if roots is None and isinstance(data, dict):
        roots = []
    out = set()
    for rc in roots or []:
        out.add((str(rc.get("category") or ""),
                 str(rc.get("representative") or rc.get("unit_name") or "")))
    return out

def _presale_lines(project_name: str, target: Path, loc: dict,
                   summary: dict, roots: list[dict], generated: str) -> list[str]:
    """M290：售前免费试扫预览单（一页纸，不含补丁/PoC 细节）。"""
    cats: dict[str, int] = {}
    for rc in roots:
        cat = str(rc.get("category") or "")
        cats[cat] = cats.get(cat, 0) + 1
    top = sorted(cats.items(), key=lambda x: (-x[1], x[0]))[:6]
    lines = [
        f"# 售前免费试扫预览单 —— {project_name}", "",
        f"- 项目：{target}",
        f"- 生成时间：{generated}",
        "- 模式：100% 离线规则层试扫（不出网、不调用外部模型，源码不离开本机）",
        f"- 代码规模：**{loc['files']} 个源码文件 / {loc['lines']:,} 行**",
        "",
        "## 一、本次试扫信号", "",
        f"- 入口单元：{summary.get('total_units', 0)}",
        f"- 路由级 P0：{summary.get('p0_route_level_hits', 0)}",
        f"- 独立根因：{len(roots)}",
        "",
        "| 类目 | 根因数 |", "|---|---:|",
    ]
    lines += [f"| {c or 'unknown'} | {n} |" for c, n in top] or [
        "| — | 0 |"]
    lines += ["", "## 二、样例（最多 5 条，只到文件:行）", ""]
    for rc in roots[:5]:
        lines.append(
            f"- [{rc.get('category', '')}] {rc.get('representative', '')} — "
            f"`{Path(str(rc.get('file', ''))).name}:{rc.get('line', 0)}`")
    if not roots:
        lines.append("- 本次规则层未发现确定性 P0。")
    lines += [
        "", "## 三、正式交付包含", "",
        "| 项目 | 售前预览 | 正式交付 |", "|---|---|---|",
        "| 根因清单 | 类目计数 + 5 条样例 | 全量根因 + 影响路由 |",
        "| 补丁 | — | 每个根因一份已验证 fix.patch |",
        "| 回归 PoC | — | 按语言接入 CI 的 PoC 集合 |",
        "| 复测销账 | — | 整改前后差异报告 |",
        "| 报价 | — | 按 LOC 区间的交付报价 |",
        "", "## 四、边界", "",
        "- 本预览单是规则层确定性结论的**抽样**，不是完整审计报告；",
        "- 单文件/片段模式缺全局装配证据，authz 类只进待复核队列；",
        "- 正式交付前需在客户环境复跑全量扫描并人工复核可达性。", "",
    ]
    return lines


def build(target: Path, outdir: Path, project_name: str,
          baseline_report: Path | None = None, presale: bool = False) -> dict:
    target = Path(target).resolve()
    outdir = Path(outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    loc = loc_stats(target)
    work = ROOT / ".cache" / "client_audit" / (project_name or "client")
    summary, log, fix_text = run_scan(target, work,
                                      with_fix=not presale,
                                      with_poc=not presale)
    roots = _root_rows(summary)
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    cats: dict[str, int] = {}
    for rc in roots:
        cats[rc["category"]] = cats.get(rc["category"], 0) + 1
    top = sorted(cats.items(), key=lambda x: -x[1])[:8]

    lines = [
        f"# 代码安全审计管理层摘要 —— {project_name}", "",
        f"- 项目路径：{target}",
        f"- 生成时间：{generated}",
        "- 交付模式：100% 离线规则层（默认不调用任何外部模型/网络）",
        f"- 代码规模：**{loc['files']} 个源码文件 / {loc['lines']:,} 行**", "",
        "## 一、代码规模与语言分布", "",
        "| 语言 | 文件数 | 行数 |", "|---|---:|---:|",
    ]
    for lang, rec in sorted(loc["by_language"].items()):
        lines.append(f"| {lang} | {rec['files']} | {rec['lines']:,} |")
    lines += ["", "## 二、规则层发现", "",
              f"- 入口单元：{summary.get('total_units', 0)}",
              f"- 路由级 P0：{summary.get('p0_route_level_hits', 0)}",
              f"- 独立根因：{summary.get('p0_unique_root_causes', 0)}",
              f"- 已生成并验证的补丁：{len(_diff_blocks(fix_text))} 个", "",
              "| 类目 | 根因数 |", "|---|---:|"]
    lines += [f"| {c} | {n} |" for c, n in top]
    lines += ["", "## 三、报价参考（按 LOC 区间，最终以人工复核范围为准）", "",
              "| 档位 | 代码行数 | 参考价 | 说明 |", "|---|---:|---|---|"]
    for row in price_table(loc["lines"]):
        lines.append(f"| {row['tier']} | {row['loc']} | {row['price']} | {row['note']} |")
    lines += ["", "## 四、边界与免责", "",
              "- 本报告是规则层确定性结论，不是人工渗透测试报告；",
              "- 单文件/片段模式缺少全局装配证据，authz 类只能标 NEEDS_HUMAN；",
              "- 补丁已通过 True→False 自检，但合入前仍需在客户 CI 复跑；",
              "- 默认离线：客户源码不离开本机，不调用外部模型。", ""]
    (outdir / "01_EXECUTIVE_SUMMARY.md").write_text("\n".join(lines),
                                                    encoding="utf-8")

    if presale:
        # M290：售前预览只交一页纸 + 管理层摘要，不生成补丁/PoC/复测。
        (outdir / "00_PRESALE_PREVIEW.md").write_text(
            "\n".join(_presale_lines(project_name, target, loc, summary,
                                     roots, generated)), encoding="utf-8")
        manifest = {"project": project_name, "target": str(target),
                    "generated_at": generated, "offline": True,
                    "presale": True, "loc": loc,
                    "units": summary.get("total_units", 0),
                    "root_causes": len(roots), "patches": 0,
                    "baseline": "",
                    "files": ["00_PRESALE_PREVIEW.md",
                              "01_EXECUTIVE_SUMMARY.md"]}
        (outdir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8")
        return manifest

    det = [f"# 详细审计与源码整改手册 —— {project_name}", "",
           f"- 入口：{summary.get('total_units', 0)} ｜ "
           f"独立根因：{len(roots)} ｜ 生成：{generated}", "",
           "## 根因清单", ""]
    for i, rc in enumerate(roots, 1):
        det += [f"### {i}. [{rc['category']}] {rc.get('representative', '')}", "",
                f"- 文件：{rc.get('file', '')}:{rc.get('line', 0)}",
                f"- 影响路由：{rc.get('affected_routes', 1)}",
                f"- 根因签名：{rc.get('signature', '')}", ""]
    if not roots:
        det.append("- 本次规则层未发现确定性 P0。")
    raw_report = work / "report.md"
    det += ["", "## 附：原始扫描报告", "",
            raw_report.read_text(encoding="utf-8") if raw_report.is_file()
            else "（无）"]
    (outdir / "02_DETAILED_AUDIT_REPORT.md").write_text("\n".join(det),
                                                        encoding="utf-8")

    patch_dir = outdir / "03_PATCH_BUNDLE"
    patch_dir.mkdir(exist_ok=True)
    blocks = _diff_blocks(fix_text)
    (patch_dir / "fix.patch").write_text("".join(blocks), encoding="utf-8")
    for i, b in enumerate(blocks, 1):
        (patch_dir / f"{i:02d}_fix.patch").write_text(b, encoding="utf-8")
    (patch_dir / "README.md").write_text(
        f"# 补丁包\n\n共 {len(blocks)} 个已验证 diff。合入前请先 "
        "git apply --check。\n", encoding="utf-8")

    reg_dir = outdir / "04_REGRESSION_TESTS"
    reg_dir.mkdir(exist_ok=True)
    poc_src = work / "poc"
    root_keys = []
    for rc in roots:
        unit = str(rc.get("representative") or "")
        if unit:
            root_keys.append(unit.replace(".", "_"))
            root_keys.append(unit.split(".")[-1])
    copied = 0
    if poc_src.is_dir():
        for p in sorted(poc_src.iterdir()):
            if not p.is_file():
                continue
            if root_keys and not any(k and k in p.name for k in root_keys):
                continue
            shutil.copy2(p, reg_dir / p.name)
            copied += 1
            if copied >= 20:
                break
    (reg_dir / "README.md").write_text(
        "# 回归测试\n\n将本目录 PoC 按语言接入客户 CI；"
        "补丁合入后应全部从 fail 转为 pass。\n", encoding="utf-8")

    base = _baseline_keys(baseline_report)
    cur = {(str(rc.get("category") or ""),
            str(rc.get("representative") or "")) for rc in roots}
    fixed = sorted(base - cur)
    opened = sorted(base & cur)
    new = sorted(cur - base)
    retest = [f"# 整改后复测销账报告 —— {project_name}", "",
              f"- 基线：{baseline_report if baseline_report else '未提供'}",
              f"- 本次：{generated}", "",
              "| 状态 | 数量 |", "|---|---:|",
              f"| 已修复 | {len(fixed)} |",
              f"| 仍存在 | {len(opened)} |",
              f"| 新增 | {len(new)} |", "",
              "## 已修复", ""]
    retest += [f"- [{c}] {u}" for c, u in fixed] or ["- 无"]
    retest += ["", "## 仍存在", ""]
    retest += [f"- [{c}] {u}" for c, u in opened] or ["- 无"]
    retest += ["", "## 新增", ""]
    retest += [f"- [{c}] {u}" for c, u in new] or ["- 无"]
    (outdir / "05_RETEST_VERIFICATION.md").write_text("\n".join(retest),
                                                      encoding="utf-8")

    manifest = {"project": project_name, "target": str(target),
                "generated_at": generated, "offline": True,
                "loc": loc, "units": summary.get("total_units", 0),
                "root_causes": len(roots), "patches": len(blocks),
                "baseline": str(baseline_report or ""),
                "files": ["01_EXECUTIVE_SUMMARY.md",
                          "02_DETAILED_AUDIT_REPORT.md",
                          "03_PATCH_BUNDLE/", "04_REGRESSION_TESTS/",
                          "05_RETEST_VERIFICATION.md"]}
    (outdir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest

