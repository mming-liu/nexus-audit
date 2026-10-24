"""compound-finance/comet（Compound V3）—— 第 12 野战仓，M87 现代 Solidity 语法拼图。

## 为什么选它

Compound V3 是 0.8.x 时代的旗舰借贷协议：`pragma solidity 0.8.15` 占了生产合约
的绝大多数，全库大量使用 **`unchecked { ... }`**（Solidity 官方推荐的省 gas
写法）与 **自定义错误**（`revert NotOwner();` / `revert InsufficientBalance(...)`，
0.8.4 起的标准守卫语法）。它是 M53 那套"0.4.x 溢出词表"的**反面样本**：
判据如果不认 unchecked 语义与自定义错误中止，就会在这类现代合约上要么
大量误报、要么整片退回。

它**不是漏洞靶场**：没有 expectedresults，真值就是"生产代码在规则层不应
出现 True 误报"。

## 门禁（--strict）

- 切片 ≥380 个合约入口（`contracts/`，不含 `contracts/test/`）；
- 四类 Solidity 判据（reentrancy / access_control / arithmetic /
  unchecked_low_level_calls）在全库 **0 条 True**；
- 四个已知安全锚点必须判 False：
  · `CometWithExtendedAssetList.getAssetInfoByAddress` —— 循环里
    `unchecked { i++; }`（循环游标，M87 分区的核心锚点）
  · `Configurator.updateAsset` —— `revert ConfigurationError(...)` 自定义错误守卫
  · `CometWithExtendedAssetList.transferInternal` —— 状态先写后外部调用（CEI）
  · `BaseBulker.invoke` —— 底层调用返回值被消费
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

DEFAULT_TARGET = ROOT / "reference_repos" / "comet" / "contracts"
CATS = ("reentrancy", "access_control", "arithmetic",
        "unchecked_low_level_calls")
MIN_UNITS = 380
ANCHORS = [
    ("CometWithExtendedAssetList.sol", "getAssetInfoByAddress", "arithmetic"),
    ("Configurator.sol", "updateAsset", "access_control"),
    ("CometWithExtendedAssetList.sol", "transferInternal", "reentrancy"),
    ("BaseBulker.sol", "invoke", "unchecked_low_level_calls"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="compound-finance/comet 0.8.x 零误报基准")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥380 单元 + 全库四类 0 True + 四个安全锚点 False")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "comet.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/compound-finance/comet.git，扫其 contracts/）")
        return 2

    units = list(SoliditySlicer(repo).extract_entry_units(repo))
    print(f"靶场：{repo}")
    print(f"      合约入口 {len(units)} 个（生产 contracts/，不含 contracts/test/）")

    true_rows, decided = [], 0
    decided_units = 0
    n_unchecked_units = 0
    n_custom_error_units = 0
    for u in units:
        unit_decided = False
        if "unchecked" in u.source_code:
            n_unchecked_units += 1
        if "revert " in u.source_code:
            n_custom_error_units += 1
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
    print("comet（Compound V3，0.8.15 + unchecked + 自定义错误）")
    print("=" * 72)
    print(f"  合约入口              ：{len(units)}")
    print(f"  含 unchecked 的单元   ：{n_unchecked_units}")
    print(f"  含 revert 的单元      ：{n_custom_error_units}")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True（误报）   ：{len(true_rows)}")
    for r in true_rows[:20]:
        print(f"    [FP] {r[0]}:{r[1]} [{r[2]}]")
    print("  安全锚点：")
    for label, cat, v in anchors:
        print(f"    {label:56} [{cat:26}] -> {v}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"规则层 True {len(true_rows)} 条")
    if any(v is not False for _, _, v in anchors):
        bad.append("安全锚点未全部判 False")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（0.8.x 生产合约 0 True / 锚点全 False）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "comet", "units": len(units), "total_units": len(units),
        "decided": decided_units, "correct": decided_units - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0,
        "rule_evaluations": decided,
        "unchecked_units": n_unchecked_units,
        "custom_error_units": n_custom_error_units,
        "anchors": [{"unit": a, "category": c, "verdict": v}
                    for a, c, v in anchors],
        "true_rows": [{"file": f, "unit": u, "category": c}
                      for f, u, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
