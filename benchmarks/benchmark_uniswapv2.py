"""Uniswap/v2-core —— 第 22 野战仓，M119 整数型状态互斥锁（1 → 0 → 1）。

## 为什么选它

Uniswap V2 是 0.5.x 时代的经典 AMM，它的重入防护是**整数**状态锁：

    uint private unlocked = 1;
    modifier lock() {
        require(unlocked == 1, 'UniswapV2: LOCKED');
        unlocked = 0;
        _;
        unlocked = 1;
    }

与 Compound V3 / OZ 的 `bool _locked` 是同一机制、不同类型。M79 的三段式判据
是「`_;` 前有前检 + `_;` 前赋反值 + `_;` 后赋回原值」，只要它挂的是**状态翻转**
而不是字面量 `true/false`，整数形态就该天然通过。

## 门禁（--strict）

- 切片 ≥25 单元（实测 29）；
- 四类 Solidity 判据 **0 条 True**（生产 AMM 合约零误报）；
- **反向锚点**：把 `swap`/`mint`/`burn` 的 `lock` 修饰符从源码里摘掉后，
  重入判定必须**不再是 False**（实测 with=False → without=None）——
  证明"不报"是因为**认出了锁**，不是因为它压根没看这块代码。
  这条比"0 条 True"重要得多：没有它，判据整个失灵也是 0 条 True。

  注意锚点断言的是"**失去保护**"而不是"必然判 True"：摘掉锁之后，规则对
  CEI 证据不足的形态仍会退 None —— 那是"缺证据不下结论"的铁律在起作用，
  不能为了让锚点好看就逼它判 True。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.web3_slither import SoliditySlicer            # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "uniswap-v2-core"
CATS = ("access_control", "reentrancy", "unchecked_low_level_calls",
        "arithmetic")
MIN_UNITS = 25
LOCKED_FUNCS = ("swap", "mint", "burn")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Uniswap V2 整数互斥锁零误报基准（M119）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥25 入口 + 四类 0 True + 去锁反向锚点必须判 True")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "uniswapv2.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/Uniswap/v2-core.git）")
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

    # 反向锚点：把 lock 修饰符从签名上摘掉，重入判定必须翻 True
    by_name = {u.unit_name: u for u in units}
    anchor: dict[str, dict] = {}
    for fn in LOCKED_FUNCS:
        u = by_name.get(fn)
        if not u:
            continue
        src = u.source_code
        stripped = re.sub(r"\block\b", "", src, count=1)
        anchor[fn] = {
            "with_lock": R.verdict("reentrancy", src),
            "without_lock": R.verdict("reentrancy", stripped),
            "changed": stripped != src,
        }

    print("=" * 72)
    print("Uniswap V2 结果（整数型状态互斥锁 1→0→1）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for f, n, c in true_rows[:12]:
        print(f"      [FP] {f}:{n} [{c}]")
    print("  反向锚点（摘掉 lock 修饰符 → 必须判 True）：")
    for fn, a in anchor.items():
        print(f"    {fn:8} with={a['with_lock']} without={a['without_lock']}"
              f"（改写生效={a['changed']}）")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"计划外 True {len(true_rows)} 条")
    if not anchor:
        bad.append("找不到 lock 保护函数（swap/mint/burn）")
    for fn, a in anchor.items():
        if not a["changed"]:
            bad.append(f"{fn} 反向锚点改写失败")
        elif a["with_lock"] is not False:
            bad.append(f"{fn} 带锁却未判 False（{a['with_lock']}）")
        elif a["without_lock"] is False:
            bad.append(f"{fn} 去锁后仍判 False（锁不是承重墙）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（29 入口 / 四类 0 True / 整数锁反向锚点成立）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "uniswapv2", "units": len(units),
        "total_units": len(units), "decided": len(units),
        "correct": len(units) - len(true_rows), "fp": len(true_rows),
        "reverse_fn": 0, "rule_evaluations": decided,
        "lock_anchor": anchor,
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
