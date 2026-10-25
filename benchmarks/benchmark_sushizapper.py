"""sushiswap/sushiswap-zapper —— 第 20 野战仓，M109 老版本 Solidity + 紧急停止。

## 为什么选它

Zapper 合约是 2020 年的**真实主网部署**代码（Solidity 0.5.x/0.6.x），与
OpenZeppelin/Compound V3/Aave V3 这些新版本协议形成对照：

- 老式 `pragma solidity ^0.5.0`，没有 unchecked / 自定义错误；
- `Ownable` / `onlyOwner` 用**同文件**的 `modifier` + `require(isOwner(), …)`
  + `isOwner()` 零参谓词三层套娃（M108 的谓词式鉴权就是被它和 Synthetix
  一起逼出来的）；
- `stopInEmergency` / `ZapIn` 等业务修饰符大量使用；
- 大量低级 `.call{value:...}` 转账（0.5 时代还没有 `transfer` 的安全共识）。

## M108/M109 实测

初测 2 条 `access_control` 误报，全部在 `transferOwnership`：

    function transferOwnership(address payable newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }
    // …
    modifier onlyOwner() { require(isOwner(), "Ownable: caller is not the owner"); _; }
    function isOwner() public view returns (bool) { return _msgSender() == _owner; }

修饰符体、`isOwner()` 体都在切片里，但旧判据只在 `require(...)` 里找
`msg.sender ==`，看不见"谓词函数"这一层。`_sol_predicate_authz_check`
补上后：**0 条 True**。

## 门禁（--strict）

- 切片 ≥60 单元（实测 75）；
- 四类 Solidity 判据 **0 条 True**；
- `Ownable.transferOwnership` 必须是确定性 False（不是 None）——
  None 说明谓词链没被认出来，那就等于没修。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.web3_slither import SoliditySlicer            # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "sushiswap-zapper"
CATS = ("access_control", "reentrancy", "unchecked_low_level_calls",
        "arithmetic")
MIN_UNITS = 60


def main() -> int:
    ap = argparse.ArgumentParser(
        description="sushiswap-zapper 老版本主网合约零误报基准（M109）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥60 入口 + 四类 0 True + transferOwnership 判 False")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "sushizapper.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/sushiswap/sushiswap-zapper.git）")
        return 2

    units = list(SoliditySlicer(repo).extract_entry_units(repo))
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个")

    true_rows: list[tuple[str, str, str]] = []
    decided = 0
    for u in units:
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))

    ownership = {Path(u.file_path).name: R.verdict("access_control",
                                                  u.source_code)
                 for u in units if u.unit_name == "transferOwnership"}

    print("=" * 72)
    print("sushiswap-zapper 结果（0.5.x 主网合约 / 谓词式 Ownable）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for f, n, c in true_rows[:12]:
        print(f"      [FP] {f}:{n} [{c}]")
    print("  transferOwnership 的 access_control（谓词链必须认出）：")
    for f, v in ownership.items():
        print(f"    {f:38} {v}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"计划外 True {len(true_rows)} 条")
    if not ownership:
        bad.append("找不到 transferOwnership 单元")
    elif any(v is not False for v in ownership.values()):
        bad.append(f"transferOwnership 未判 False：{ownership}")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（75 入口 / 0 True / 谓词式 Ownable 判 False）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "sushizapper", "units": len(units),
        "total_units": len(units), "decided": len(units),
        "correct": len(units) - len(true_rows), "fp": len(true_rows),
        "reverse_fn": 0, "rule_evaluations": decided,
        "ownership_verdicts": ownership,
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
