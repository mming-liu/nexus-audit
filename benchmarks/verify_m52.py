"""M52 反查真值：验证新早退分支在三个 Solidity 靶场 **0 判反 0 误报**。

判反（vul 判 False）比退回恶劣得多 —— 宁可一条都不收。

用法：python benchmarks/verify_m52.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "benchmarks"))

from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.agents.rule_detectors import (                        # noqa: E402
    _sol_bilateral_conserving, _sol_implicit_view)


def smartbugs_check() -> tuple[int, list, list]:
    """smartbugs：官方 vulnerabilities.json（按类目过滤）+ 全量函数扫。

    DISPUTED 口径与 benchmark_smartbugs.py 完全一致：parity_wallet_bug_1/2
    的 `kill` 代码逐字相同、官方真值一处标一处不标 —— 剔除计分，
    不为分数改判据。
    """
    from core.slicer.web3_slither import SoliditySlicer
    from benchmark_smartbugs import DISPUTED
    repo = ROOT / "reference_repos" / "smartbugs-curated-main"
    meta = {Path(x["path"]).name: x
            for x in json.loads((repo / "vulnerabilities.json")
                                .read_text(encoding="utf-8"))}
    slicer = SoliditySlicer(repo)
    wrong, rev, n = [], [], 0
    for cat in ("access_control", "reentrancy", "unchecked_low_level_calls"):
        for u in slicer.extract_entry_units(repo / "dataset" / cat):
            entry = meta.get(Path(u.file_path).name)
            if not entry:
                continue
            vul_lines = {l for v in entry["vulnerabilities"]
                         if v["category"] == cat for l in v["lines"]}
            if not vul_lines:
                continue
            if (Path(u.file_path).name, u.unit_name) in DISPUTED:
                continue
            n += 1
            truth = any(u.start_line <= l <= u.end_line for l in vul_lines)
            rv = rule_verdict(cat, u.source_code)
            if rv is True and not truth:
                wrong.append((cat, Path(u.file_path).name, u.unit_name, rv))
            elif rv is False and truth:
                rev.append((cat, Path(u.file_path).name, u.unit_name,
                            u.start_line, u.end_line))
    return n, wrong, rev


def defivulnlabs_check() -> tuple[int, list, list]:
    """DeFiVulnLabs：手写 TRUTH 表（9 条，含成对修复样本）。"""
    from core.slicer.web3_slither import SoliditySlicer
    from benchmark_defivulnlabs import TRUTH
    repo = ROOT / "reference_repos" / "DeFiVulnLabs-main"
    slicer = SoliditySlicer(repo)
    units = slicer.extract_entry_units(repo)
    index: dict = {}
    for u in units:
        index.setdefault((Path(u.file_path).name, u.start_line), []).append(u)
    wrong, rev, n = [], [], 0
    for fname, line, func, cat, is_vul, _why in TRUTH:
        cands = [u for u in index.get((fname, line), []) if u.unit_name == func]
        if not cands:
            print(f"  ! 真值与源码不同步：{fname}:{line} {func}")
            continue
        u = cands[0]
        n += 1
        rv = rule_verdict(cat, u.source_code)
        if rv is True and not is_vul:
            wrong.append((cat, fname, func, rv))
        elif rv is False and is_vul:
            rev.append((cat, fname, func, u.start_line, u.end_line))
    return n, wrong, rev


def nssc_check() -> tuple[int, list, list]:
    """nssc：手写 TRUTH 表（8 条）。"""
    from core.slicer.web3_slither import SoliditySlicer
    from benchmark_nssc import TRUTH
    repo = ROOT / "reference_repos" / "not-so-smart-contracts-master"
    slicer = SoliditySlicer(repo)
    units = slicer.extract_entry_units(repo)
    index: dict = {}
    for u in units:
        index.setdefault((str(Path(u.file_path).as_posix()), u.start_line), []).append(u)
    wrong, rev, n = [], [], 0
    for rel, line, func, cat, is_vul, _why in TRUTH:
        # 真值表给的是相对路径片段
        cands = []
        for u in units:
            uposix = Path(u.file_path).as_posix()
            if rel in uposix and u.start_line == line and u.unit_name == func:
                cands.append(u)
        if not cands:
            print(f"  ! 真值与源码不同步：{rel}:{line} {func}")
            continue
        u = cands[0]
        n += 1
        rv = rule_verdict(cat, u.source_code)
        if rv is True and not is_vul:
            wrong.append((cat, rel, func, rv))
        elif rv is False and is_vul:
            rev.append((cat, rel, func, u.start_line, u.end_line))
    return n, wrong, rev


def main() -> int:
    print("=" * 72)
    print("M52 反查真值：新早退分支的判反/误报核对")
    print("=" * 72)
    total_n = 0
    all_wrong, all_rev = [], []
    for name, fn in (("smartbugs", smartbugs_check),
                     ("DeFiVulnLabs", defivulnlabs_check),
                     ("nssc", nssc_check)):
        n, wrong, rev = fn()
        total_n += n
        all_wrong += [(name,) + w for w in wrong]
        all_rev += [(name,) + r for r in rev]
        print(f"  {name:14} 真值 {n:3} 条  误报 {len(wrong)}  判反 {len(rev)}")
        for w in wrong:
            print(f"      [误报] {w}")
        for r in rev:
            print(f"      [判反] {r}")

    # 新分支单独统计：判 False 且真值是 vul 的（双保险）
    print()
    print("新分支单独口径（只看 _sol_implicit_view / _sol_bilateral_conserving）：")
    from core.slicer.web3_slither import SoliditySlicer
    from benchmark_smartbugs import DISPUTED
    repo = ROOT / "reference_repos" / "smartbugs-curated-main"
    meta = {Path(x["path"]).name: x
            for x in json.loads((repo / "vulnerabilities.json")
                                .read_text(encoding="utf-8"))}
    slicer = SoliditySlicer(repo)
    hit_true = 0
    for cat in ("access_control",):
        for u in slicer.extract_entry_units(repo / "dataset" / cat):
            entry = meta.get(Path(u.file_path).name)
            if not entry:
                continue
            vul_lines = {l for v in entry["vulnerabilities"]
                         if v["category"] == cat for l in v["lines"]}
            if not vul_lines:
                continue
            if (Path(u.file_path).name, u.unit_name) in DISPUTED:
                continue
            truth = any(u.start_line <= l <= u.end_line for l in vul_lines)
            if truth and (_sol_implicit_view(u.source_code)
                          or _sol_bilateral_conserving(u.source_code)):
                hit_true += 1
                print(f"      !! 新分支命中官方 vul："
                      f"{Path(u.file_path).name}:{u.unit_name} "
                      f"L{u.start_line}-{u.end_line} "
                      f"view={_sol_implicit_view(u.source_code)} "
                      f"bil={_sol_bilateral_conserving(u.source_code)}")
    print(f"  新分支命中官方 vul 的样本数：{hit_true}（必须为 0）")

    print()
    print("=" * 72)
    print(f"合计真值 {total_n} 条；误报 {len(all_wrong)}；判反 {len(all_rev)}")
    if all_wrong or all_rev or hit_true:
        print("! 存在方向错误 —— 不得合入")
        return 1
    print("✔ 0 误报 / 0 判反 / 新分支 0 命中官方 vul")
    return 0


if __name__ == "__main__":
    sys.exit(main())
