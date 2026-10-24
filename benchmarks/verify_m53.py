"""M53 反查真值：arithmetic 类目在 smartbugs 上 0 误报 / 0 判反。

真值来源：smartbugs-curated `vulnerabilities.json` 的 **arithmetic** 类目
标注（15 个合约、@vulnerable_at_lines），按 (file, start_line) 精确匹配。

用法：python benchmarks/verify_m53.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.slicer.web3_slither import SoliditySlicer               # noqa: E402

REPO = ROOT / "reference_repos" / "smartbugs-curated-main"


def main() -> int:
    meta = {Path(x["path"]).name: x
            for x in json.loads((REPO / "vulnerabilities.json")
                                .read_text(encoding="utf-8"))}
    slicer = SoliditySlicer(REPO)
    units = slicer.extract_entry_units(REPO / "dataset" / "arithmetic")

    rows = []
    for u in units:
        entry = meta.get(Path(u.file_path).name)
        if not entry:
            continue
        vul_lines = {l for v in entry["vulnerabilities"]
                     if v["category"] == "arithmetic" for l in v["lines"]}
        if not vul_lines:
            continue
        truth = any(u.start_line <= l <= u.end_line for l in vul_lines)
        rv = rule_verdict("arithmetic", u.source_code)
        rows.append((Path(u.file_path).name, u.unit_name, u.start_line,
                     u.end_line, truth, rv))

    wrong = [r for r in rows if r[5] is True and not r[4]]
    rev = [r for r in rows if r[5] is False and r[4]]
    fb = [r for r in rows if r[5] is None]
    judged = len(rows) - len(fb)
    right = judged - len(wrong) - len(rev)
    vul_n = sum(1 for r in rows if r[4])

    print("=" * 72)
    print("M53 arithmetic 反查真值（smartbugs dataset/arithmetic）")
    print("=" * 72)
    print(f"登记样本 {len(rows)}（vul {vul_n} / safe {len(rows) - vul_n}）")
    print(f"规则确定性判定 {judged}/{len(rows)}（退回 {len(fb)}）")
    print(f"判定正确 {right}/{judged}")
    if wrong:
        print("\n! 误报（safe 判 True）—— 必须为 0：")
        for r in wrong:
            print(f"  {r[0]}:{r[1]} L{r[2]}-{r[3]}")
    if rev:
        print("\n! 判反（vul 判 False）—— 比退回恶劣，必须为 0：")
        for r in rev:
            print(f"  {r[0]}:{r[1]} L{r[2]}-{r[3]}")
    if fb:
        print(f"\n退回 None {len(fb)} 条：")
        for r in fb:
            print(f"  {r[0]}:{r[1]} L{r[2]}-{r[3]} truth={r[4]}")

    print("\n逐条明细：")
    for r in sorted(rows, key=lambda x: (x[0], x[2])):
        mark = {True: "VUL", False: "safe", None: "None"}[r[5]]
        t = "VUL" if r[4] else "safe"
        flag = "  <-- 误报" if (r[5] is True and not r[4]) else \
               ("  <-- 判反" if (r[5] is False and r[4]) else "")
        print(f"  {r[0]:48} {r[1]:26} L{r[2]:<4} 真值={t:4} 判定={mark}{flag}")

    if wrong or rev:
        print("\n! 存在方向错误 —— 不得合入")
        return 1
    print("\n✔ 0 误报 / 0 判反")
    return 0


if __name__ == "__main__":
    sys.exit(main())
