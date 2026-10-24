"""uniswap/v3-core — 第 27 个靶场，M79 自定义状态互斥锁试金石。

## 为什么选它

Uniswap V3 是 DEX 的黄金标杆，`UniswapV3Pool` 不使用 OpenZeppelin 的
`nonReentrant` 名字，而是自定义：

    modifier lock() {
        require(slot0.unlocked, 'LOK');
        slot0.unlocked = false;
        _;
        slot0.unlocked = true;
    }

如果只认 `nonReentrant` 名字，`mint`/`burn`/`swap`/`flash` 会被误判为
可重入。规则按 **modifier 体结构**识别：`require/if` 前检 + `_;` 前把同一
状态位置 false/0 + `_;` 后置 true/1 才算锁；只有赋值没有前检不算。

## 门禁（--strict）

- 生产 `contracts/`（排除 `contracts/test/`）≥60 入口；
- 四类 Solididty 判据 0 条 True；
- `mint/burn/swap/flash/collect` 全部确定性 False；
- `FullMath.mulDiv` / `TickMath.getSqrtRatioAtTick` 等库锚点不误报。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "uniswap-v3-core" / "contracts"
CATS = ("reentrancy", "access_control", "arithmetic",
        "unchecked_low_level_calls")
LOCK_FUNCS = ("mint", "burn", "swap", "flash", "collect")
MIN_UNITS = 60


def _is_test(path: str) -> bool:
    return any(p.lower() in {"test", "tests", "mock", "mocks"}
               for p in Path(path).parts)


def main() -> int:
    ap = argparse.ArgumentParser(description="uniswap/v3-core 状态互斥锁基准")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="生产 contracts/ 0 True + lock 函数全 False")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "uniswapv3.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/uniswap/v3-core.git）")
        return 2

    units = [u for u in SoliditySlicer(repo).extract_entry_units(repo)
             if not _is_test(u.file_path)]
    print(f"靶场：{repo}")
    print(f"      生产入口 {len(units)} 个（已排除 contracts/test/）")

    true_rows, decided, decided_units = [], 0, 0
    for u in units:
        one = False
        for c in CATS:
            v = rule_verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            one = True
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))
        decided_units += 1 if one else 0

    locks = {}
    for name in LOCK_FUNCS:
        hit = next((u for u in units
                    if Path(u.file_path).name == "UniswapV3Pool.sol"
                    and u.unit_name.split("#")[0] == name), None)
        locks[name] = (rule_verdict("reentrancy", hit.source_code)
                       if hit else None)

    print("=" * 72)
    print("uniswap/v3-core 结果（生产合约状态互斥锁）")
    print("=" * 72)
    print(f"  生产入口              ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True（误报）   ：{len(true_rows)}")
    print(f"  锁保护函数 reentrancy ：{locks}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"生产入口 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"规则层 True {len(true_rows)} 条")
    if any(v is not False for v in locks.values()):
        bad.append("lock 函数未全部判 False")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（生产 0 True / lock 函数全 False）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "uniswapv3", "units": len(units),
        "total_units": len(units), "decided": decided_units,
        "correct": decided_units - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0,
        "rule_evaluations": decided,
        "lock_functions": {k: v for k, v in locks.items()},
        "true_rows": [{"file": f, "unit": u, "category": c}
                      for f, u, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
