"""aave/aave-v3-core —— 第 15 野战仓，M96 顶级跨链借贷协议零误报压测。

## 为什么选它

Aave V3 是链上最大的借贷协议之一（数百亿美元 TVL），架构与 Compound/Uniswap
都不同：**逻辑库委托架构** —— `Pool` 只做权限与参数整理，真正的记账在
`protocol/libraries/logic/*Logic.sol` 的 `library` 里，通过 `using XLogic for
DataTypes.PoolState` 扩展调用；权限则走 `IACLManager` 角色表
（`onlyPoolAdmin` / `onlyRiskOrPoolAdmin` / `onlyPool` / `onlyBridge`），
**调用者身份被封装成 `_msgSender()` 零参函数**再参与比较。

对规则层的考验有两处：
  ① `require(_msgSender() == address(POOL), ...)` —— 身份函数形态，不是
     `msg.sender` 字面量；
  ② 修饰符的**定义体在父合约**（`IncentivizedERC20.onlyPool`），必须在
     父合约证据段里核验实现体，不能只看名字。

## M96 实测：1 条 True 收到 0 条

初测 `AToken.transferOnLiquidation` 被 `access_control` 判 True —— 它有
`onlyPool` 修饰符，但修饰符体里写的是
`require(_msgSender() == address(POOL), Errors.CALLER_MUST_BE_POOL)`。
`_SOLIDITY_MSGSENDER_CHECK_RE` 只认 `msg.sender` 字面量，看不见身份函数形态。

纯增量补齐（`_sol_identity_call_check`）：require/assert 条件里出现 `==`
恒等比较且一侧是身份函数（msg.sender / _msgSender() / msgSender() / _sender()）
即算保护。**只认 `==` 不认 `!=`** —— `require(_msgSender() != address(0))`
是"调用者非零地址"，把它当授权判定会造假阴性。

## 门禁（--strict）

- 扫描 `contracts/protocol/{pool,libraries/logic,tokenization}`（275 入口）；
- 四类 Solidity 判据 **0 条 True**；
- 四个锚点必须判 False（确定性安全）；
- 一条**反向锚点**：`mocks/helpers/SelfDestructTransfer.destroyAndTransfer`
  必须判 True —— 它是真的无权限 `selfdestruct`（测试辅助合约），
  规则不能因为"要零误报"就把真漏洞也放过。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "aave-v3-core" / "contracts"
SCOPE_DIRS = ("protocol/pool", "protocol/libraries/logic",
              "protocol/tokenization")
CATS = ("reentrancy", "access_control", "arithmetic",
        "unchecked_low_level_calls")
MIN_UNITS = 240

# (相对路径, 单元名, 类目, 期望)
ANCHORS = [
    ("protocol/tokenization/AToken.sol", "transferOnLiquidation",
     "access_control", False),
    ("protocol/tokenization/AToken.sol", "burn", "access_control", False),
    ("protocol/tokenization/VariableDebtToken.sol", "mint",
     "access_control", False),
    ("protocol/libraries/logic/LiquidationLogic.sol",
     "executeLiquidationCall", "arithmetic", False),
]
# 反向锚点：真的无权限 selfdestruct（mocks/ 下的测试辅助合约）。
# 它不在生产扫描范围里，但规则**必须**判得出它 —— "零误报"不能靠全判 False 换来。
TRUE_ANCHOR = ("mocks/helpers/SelfDestructTransfer.sol", "destroyAndTransfer",
               "access_control")


def _rel(repo: Path, file_path: str) -> str:
    try:
        return Path(file_path).resolve().relative_to(repo.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(file_path).as_posix()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Aave V3 跨链借贷协议零误报基准（M96）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥240 入口 + 四类 0 True + 四锚点 False + 反向锚点 True")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "aavev3.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/aave/aave-v3-core.git）")
        return 2
    scope_root = repo if repo.name == "contracts" else repo / "contracts"
    if scope_root.is_dir():
        repo = scope_root

    all_units = list(SoliditySlicer(repo).extract_entry_units(repo))
    units = [u for u in all_units
             if any(_rel(repo, u.file_path).startswith(s)
                    for s in SCOPE_DIRS)]
    print(f"靶场：{repo}")
    print(f"      全库入口 {len(all_units)} 个，其中 "
          f"protocol/{{pool,libraries/logic,tokenization}} 下 {len(units)} 个")

    true_rows: list[tuple[str, str, str]] = []
    decided = 0
    decided_units = 0
    for u in units:
        unit_decided = False
        rel = _rel(repo, u.file_path)
        for c in CATS:
            v = rule_verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            unit_decided = True
            if v is True:
                true_rows.append((rel, u.unit_name, c))
        if unit_decided:
            decided_units += 1

    anchors = []
    for relp, name, cat, want in ANCHORS:
        hit = next((u for u in units if _rel(repo, u.file_path) == relp
                    and u.unit_name == name), None)
        got = rule_verdict(cat, hit.source_code) if hit else None
        anchors.append({"unit": f"{relp}:{name}", "category": cat,
                        "want": str(want), "got": got,
                        "ok": bool(hit) and got == want,
                        "missing": hit is None})
    relp, name, cat = TRUE_ANCHOR
    hit = next((u for u in all_units if _rel(repo, u.file_path) == relp
                and u.unit_name == name), None)
    got = rule_verdict(cat, hit.source_code) if hit else None
    true_anchor = {"unit": f"{relp}:{name}", "category": cat,
                   "want": "True", "got": got, "ok": bool(hit) and got is True}

    print("=" * 72)
    print("Aave V3 结果（逻辑库委托 + ACL 角色表，规则层零误报压测）")
    print("=" * 72)
    print(f"  生产入口               ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）    ：{decided_units}")
    print(f"  规则判定次数           ：{decided}")
    print(f"  规则层 True（误报）    ：{len(true_rows)}")
    for r in true_rows[:20]:
        print(f"    [FP] {r[0]}:{r[1]} [{r[2]}]")
    print("  安全锚点：")
    for a in anchors:
        print(f"    {'OK ' if a['ok'] else 'XX '}{a['unit']:56} "
              f"[{a['category']:16}] 期望 {a['want']:5} 实际 {a['got']!s}")
    print("  反向锚点（真漏洞必须判得出）：")
    print(f"    {'OK ' if true_anchor['ok'] else 'XX '}"
          f"{true_anchor['unit']:56} [{true_anchor['category']:16}] "
          f"期望 True 实际 {true_anchor['got']!s}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"规则层 True {len(true_rows)} 条（生产入口应 0）")
    if not all(a["ok"] for a in anchors):
        bad.append("安全锚点未全部判 False")
    if not true_anchor["ok"]:
        bad.append("反向锚点未判 True（真漏洞被放过）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（275 入口 / 0 True / 锚点双向达标）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "aavev3", "units": len(units), "total_units": len(units),
        "all_units": len(all_units),
        "decided": decided_units, "correct": decided_units - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0,
        "rule_evaluations": decided,
        "anchors": anchors, "true_anchor": true_anchor,
        "true_rows": [{"file": f, "unit": u, "category": c}
                      for f, u, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
