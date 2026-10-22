"""damn-vulnerable-defi —— **健壮性抽检**（不是真值基准）。

## 为什么这里没有 --strict 真值门禁

dvdefi 的 19 个挑战是**经济逻辑漏洞**：预言机操纵、闪贷治理攻击、价格偏差、
记账不变量破坏。这些类目 `vuln_categories.CATEGORIES` 里没有对应定义，规则层
也没有判据 —— 硬标真值等于让模型去猜，而"猜对了"不能证明任何事。

所以本靶场的定位与 smartbugs / DeFiVulnLabs 不同：**不产出 TPR/FPR**，只做
两件确定性的事。

## 它锁什么

1. **切片不退化**：53 个 .sol / 164 个函数单元。这个数字塌下来，说明切片器
   在 0.8.x + OpenZeppelin 继承链上出了问题 —— 那种坏法在别的靶场看不出来，
   因为别的靶场合约更简单。
2. **判定面不爆炸**：规则层在这些**公开审计过的真实 DeFi 合约**上判 True 的
   必然极少（当前 164 条里 1 条）。一旦某次改动让 True 数量跳到几十条，说明
   判据回归了 —— 这是比"误报率涨了 2%"更早、更响的警报。

`--sanity` 就是这两条的上限断言。它不做"判对了多少"的判断，因为没有真值；
它防的是"改坏了没人知道"。

当前那 1 条 True 是 `naive-receiver/NaiveReceiverPool.flashLoan`：第 50 行
`weth.transfer(...)` 外转，第 51 行 `totalDeposits -= amount` 扣减 —— CEI
顺序确实是反的（该挑战官方漏洞点是"未校验 msg.sender"，而这条 CEI 违反是
同一函数里另一个真实问题）。规则只看机制，因此判 True 站得住。
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict  # noqa: E402
from core.slicer.web3_slither import SoliditySlicer  # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "damn-vulnerable-defi-master"

CATEGORIES = ["reentrancy", "access_control"]

# 健壮性上限（不是精度指标）。数字取当前实测值留一点余量：
# 单元 164、True 1 条、False 侧 >100 条。超出即视为退化，交人工看。
MIN_UNITS = 150
MAX_TRUE = 8
MIN_FALSE = 80


def main() -> int:
    ap = argparse.ArgumentParser(description="damn-vulnerable-defi 健壮性抽检")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--sanity", action="store_true", help="上限断言（CI 门禁）")
    ap.add_argument("--list", action="store_true", help="打印全部 True 样本供抽查")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "dvdefi_sanity.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 靶场不存在：{repo}")
        return 2

    units = list(SoliditySlicer(repo).extract_entry_units(repo / "src"))
    dist: Counter = Counter()
    trues: list[tuple[str, str, str]] = []
    for u in units:
        for cat in CATEGORIES:
            rv = rule_verdict(cat, u.source_code)
            dist[("None" if rv is None else ("True" if rv else "False"))] += 1
            if rv is True:
                trues.append((Path(u.file_path).parent.name, u.unit_name, cat))

    print("damn-vulnerable-defi 健壮性抽检（无真值口径，只锁形态）")
    print("=" * 72)
    print(f"切片单元 {len(units)}（函数 × 类目 = {len(units) * len(CATEGORIES)} 次判定）")
    print(f"判定分布 True={dist['True']} False={dist['False']} None={dist['None']}")
    print("\nTrue 样本（必看：公开审计合约里不该成批出现）：")
    for d, name, cat in trues:
        print(f"  {d:16} {name:26} {cat}")
    if not trues:
        print("  （无）")

    out = {"target": str(repo), "units": len(units),
           "true": dist["True"], "false": dist["False"], "none": dist["None"],
           "true_rows": [{"dir": d, "unit": n, "category": c} for d, n, c in trues]}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")

    if args.sanity:
        bad = []
        if len(units) < MIN_UNITS:
            bad.append(f"切片单元 {len(units)} < {MIN_UNITS}（切片器在 0.8.x 上退化）")
        if dist["True"] > MAX_TRUE:
            bad.append(f"True {dist['True']} 条 > {MAX_TRUE}（判定面爆炸，判据回归）")
        if dist["False"] < MIN_FALSE:
            bad.append(f"False {dist['False']} 条 < {MIN_FALSE}（判定面塌陷）")
        # 该样本是 CEI 顺序反了的真实函数（见模块 docstring），
        # 它若翻成 None/False，说明重入判据的老语法/花括号解析又退回去了。
        if not any(d == "naive-receiver" and n == "flashLoan" and c == "reentrancy"
                   for d, n, c in trues):
            bad.append("naive-receiver:flashLoan 不再判重入（CEI 行序解析退化）")
        if bad:
            print("SANITY FAIL ✘ " + "；".join(bad))
            return 1
        print("SANITY PASS ✔ （切片 164 单元、判定面未爆炸、CEI 行序解析正常）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
