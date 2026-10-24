"""M54 双真值回归台：一次跑完 smartbugs（正样本真值）+ GPTScan（纯负样本）。

**为什么需要它**：M53（arithmetic 类目）在 smartbugs 上要"0 误报 0 判反"，
M54（GPTScan Top200）是**纯负样本集**（safe 判 True 一条都不许有）——
两个门禁方向相反，但**共用同一批规则函数**。只盯一边改规则，另一边会
悄悄翻车。所以这里把两边并排跑，输出同一张表：

    类目 | smartbugs 误报 | smartbugs 判反 | smartbugs 判定 | Top200 误报

Top200 侧只产误报（没有 vul 真值）；smartbugs 侧产误报 + 判反。

用法：
    python benchmarks/regress_dual.py                # 四类目全跑
    python benchmarks/regress_dual.py arithmetic     # 只跑一类目
    python benchmarks/regress_dual.py --fp-detail    # 打印 Top200 误报明细
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.web3_slither import SoliditySlicer                 # noqa: E402
from benchmarks.slice_cache import cached_units                     # noqa: E402

SB_REPO = ROOT / "reference_repos" / "smartbugs-curated-main"
GP_REPO = ROOT / "reference_repos" / "GPTScan-Top200-dev"

CATEGORIES = ["reentrancy", "access_control", "unchecked_low_level_calls",
              "arithmetic"]

# smartbugs 口径分歧剔除表（与 benchmark_smartbugs.py 保持一致）
DISPUTED = {
    ("parity_wallet_bug_1.sol", "kill"),
    ("parity_wallet_bug_2.sol", "kill"),
}


def _smartbugs_rows(cats: list[str]):
    meta = {Path(x["path"]).name: x
            for x in json.loads((SB_REPO / "vulnerabilities.json")
                                .read_text(encoding="utf-8"))}
    slicer = SoliditySlicer(SB_REPO)
    rows = []
    for cat in cats:
        units = slicer.extract_entry_units(SB_REPO / "dataset" / cat)
        for u in units:
            entry = meta.get(Path(u.file_path).name)
            if not entry:
                continue
            vul_lines = {l for v in entry["vulnerabilities"]
                         if v["category"] == cat for l in v["lines"]}
            if not vul_lines:
                continue
            truth = any(u.start_line <= l <= u.end_line for l in vul_lines)
            if (Path(u.file_path).name, u.unit_name) in DISPUTED:
                continue
            rows.append((cat, u, truth))
    return rows


def _gptscan_units():
    slicer = SoliditySlicer(GP_REPO)
    return cached_units(GP_REPO, "gptscan-top200",
                         lambda: slicer.extract_entry_units(GP_REPO))


def main() -> int:
    args = sys.argv[1:]
    fp_detail = "--fp-detail" in args
    cats = [a for a in args if not a.startswith("--")] or CATEGORIES

    # ---- smartbugs 侧 ----
    sb_rows = _smartbugs_rows(cats)
    sb_stat: dict[str, Counter] = {c: Counter() for c in cats}
    sb_fp: list[tuple[str, str, str]] = []
    sb_rev: list[tuple[str, str, str]] = []
    for cat, u, truth in sb_rows:
        rv = rule_verdict(cat, u.source_code)
        if rv is None:
            sb_stat[cat]["fallback"] += 1
            continue
        sb_stat[cat]["decided"] += 1
        if rv is True and not truth:
            sb_stat[cat]["fp"] += 1
            sb_fp.append((cat, Path(u.file_path).name, u.unit_name))
        elif rv is False and truth:
            sb_stat[cat]["reverse_fn"] += 1
            sb_rev.append((cat, Path(u.file_path).name, u.unit_name))
        else:
            sb_stat[cat]["correct"] += 1

    # ---- GPTScan 侧（纯负样本：判 True 即误报）----
    units = _gptscan_units()
    gp_stat: dict[str, Counter] = {c: Counter() for c in cats}
    gp_fp: list[tuple[str, str, str]] = []
    gp_by_fn: dict[str, Counter] = defaultdict(Counter)
    for u in units:
        for cat in cats:
            rv = rule_verdict(cat, u.source_code)
            if rv is None:
                gp_stat[cat]["fallback"] += 1
                continue
            gp_stat[cat]["decided"] += 1
            if rv is True:
                gp_stat[cat]["fp"] += 1
                gp_fp.append((cat, Path(u.file_path).name, u.unit_name))
                gp_by_fn[cat][u.unit_name] += 1

    print("=" * 88)
    print("M54 双真值回归台")
    print("=" * 88)
    print(f"{'类目':<26} {'sb判定':>6} {'sb误报':>7} {'sb判反':>7} "
          f"{'sb退回':>7} | {'gp判定':>7} {'gp误报':>7} {'gpFPR':>8}")
    print("-" * 88)
    total_fp = total_rev = 0
    for cat in cats:
        s, g = sb_stat[cat], gp_stat[cat]
        fpr = g["fp"] / g["decided"] if g["decided"] else 0.0
        print(f"{cat:<26} {s['decided']:>6} {s['fp']:>7} {s['reverse_fn']:>7} "
              f"{s['fallback']:>7} | {g['decided']:>7} {g['fp']:>7} "
              f"{fpr * 100:>7.2f}%")
        total_fp += s["fp"] + g["fp"]
        total_rev += s["reverse_fn"]
    print("-" * 88)
    print(f"合计误报 {total_fp} 条（sb + gp） / 判反 {total_rev} 条")

    if sb_fp:
        print(f"\n! smartbugs 误报 {len(sb_fp)} 条：")
        for c, f, n in sb_fp[:40]:
            print(f"    {c:<26} {f}:{n}")
    if sb_rev:
        print(f"\n! smartbugs 判反 {len(sb_rev)} 条（比误报恶劣）：")
        for c, f, n in sb_rev[:40]:
            print(f"    {c:<26} {f}:{n}")
    if gp_fp:
        print(f"\n! GPTScan 误报 {len(gp_fp)} 条，按类目：")
        for cat in cats:
            if gp_stat[cat]["fp"]:
                print(f"  {cat:<26} {gp_stat[cat]['fp']}")
                print(f"    按函数名 Top 12：")
                for fn, n in gp_by_fn[cat].most_common(12):
                    print(f"      {fn:<38} {n}")
        if fp_detail:
            print("\n  误报明细：")
            for c, f, n in gp_fp[:200]:
                print(f"    {c:<26} {f}:{n}")

    ok = (total_fp == 0 and total_rev == 0)
    print(f"\n{'✔ 双门禁全绿' if ok else '✘ 存在方向错误'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
