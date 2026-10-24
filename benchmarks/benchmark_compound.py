"""compound-protocol（compound-finance）—— 第 26 个靶场，M73 生产级 DeFi 零误报试金石。

## 为什么选它

Compound 是经过百亿美元锁仓量实战检验的顶级 DeFi 协议，Solidity 0.5/0.6
混合、`ErrorReporter` 错误码模式、`admin/pendingAdmin` 两段式权限、`nonReentrant`
修饰符、SafeMath/Exponential 定点数。它**不是漏洞靶场**：没有任何 expectedresults，
真值就是"生产代码在规则层不应出现 True 误报"。

## 门禁（--strict）

- 切片 ≥300 个合约入口（实测 450）；
- 四类 Solidity 判据（reentrancy / access_control / arithmetic /
  unchecked_low_level_calls）在全库 **0 条 True**；
- 三条已知安全锚点必须判 False：
  · `Timelock.setPendingAdmin` 的 `require(msg.sender == admin)`
  · `CToken` 的 `nonReentrant` / 权限校验
  · `ExponentialNoError` 的定点数运算
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.slicer.web3_slither import SoliditySlicer             # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "compound-protocol" / "contracts"
CATS = ("reentrancy", "access_control", "arithmetic",
        "unchecked_low_level_calls")
MIN_UNITS = 300
ANCHORS = [
    ("Timelock.sol", "setPendingAdmin", "access_control"),
    ("CToken.sol", "transfer", "reentrancy"),
    ("ExponentialNoError.sol", "mul_ScalarTruncate", "arithmetic"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="compound-protocol 生产协议零误报基准")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥300 单元 + 全库四类 0 True + 三个安全锚点 False")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "compound.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/compound-finance/compound-protocol.git）")
        return 2

    units = list(SoliditySlicer(repo).extract_entry_units(repo))
    print(f"靶场：{repo}")
    print(f"      合约入口 {len(units)} 个（生产 contracts/，不含 tests/）")

    true_rows, decided = [], 0
    decided_units = 0
    for u in units:
        unit_decided = False
        for c in CATS:
            v = rule_verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            unit_decided = True
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))
        if unit_decided:
            decided_units += 1

    anchors = []
    for fname, name, cat in ANCHORS:
        hit = next((u for u in units
                    if Path(u.file_path).name == fname
                    and u.unit_name.split("#")[0] == name), None)
        if hit is None:
            anchors.append((f"{fname}:{name}", cat, None))
        else:
            anchors.append((f"{fname}:{name}", cat,
                            rule_verdict(cat, hit.source_code)))

    print("=" * 72)
    print("compound-protocol 结果（生产级 DeFi 零误报）")
    print("=" * 72)
    print(f"  合约入口              ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True（误报）   ：{len(true_rows)}")
    for r in true_rows[:20]:
        print(f"    [FP] {r[0]}:{r[1]} [{r[2]}]")
    print("  安全锚点：")
    for label, cat, v in anchors:
        print(f"    {label:32} [{cat:20}] -> {v}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"规则层 True {len(true_rows)} 条")
    if any(v is not False for _, _, v in anchors):
        bad.append("安全锚点未全部判 False")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（生产协议 0 True / 锚点全 False）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "compound", "units": len(units), "total_units": len(units),
        "decided": decided_units, "correct": decided_units - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0,
        "rule_evaluations": decided,
        "anchors": [{"unit": a, "category": c, "verdict": v}
                    for a, c, v in anchors],
        "true_rows": [{"file": f, "unit": u, "category": c}
                      for f, u, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
