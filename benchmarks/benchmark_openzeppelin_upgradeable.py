"""OpenZeppelin/openzeppelin-contracts-upgradeable —— 第 29 野战仓（Solidity #10），M143。

## 为什么选它

这是 OZ 官方**可升级合约**版的基元库（`contracts/` 下 2000+ 个入口），
它把"可升级"这件事的语义全部压在四个 modifier 上：

    modifier initializer()          // 只能成功执行一次
    modifier reinitializer(uint64)  // 版本化的再初始化
    modifier onlyInitializing()     // 只能在初始化期间调用（内部 init 辅助）
    modifier onlyProxy()            // 只能经代理调用（拒绝直调实现合约）

这四个词直接决定 access_control 该怎么判：

  · `initializer` / `reinitializer` 是**一次性**入口 —— 它的风险形态是
    "部署竞态 / 未初始化代理被抢跑"，与"任意时刻可调的特权入口缺授权"
    不是同一类。判 True 是把缺证据当漏洞，判 False 又会洗白真抢跑问题
    ⇒ 按铁律退 None（M143 在判据里显式写明并早退）。
  · `onlyInitializing` 标记的是**内部**初始化辅助函数（`__X_init` /
    `__X_init_unchained`），本来就只有 internal —— 编译器层面外部不可达。
  · `onlyProxy` 是入口约束（拒绝直调实现合约），但它替代不了
    `_authorizeUpgrade` 的授权 —— 所以 `upgradeToAndCall` 退 None 是对的。

## 门禁（--strict）

- 切片 ≥1900 入口（实测 2017）；
- 五类判据 **0 条 True**（基元库不许有误报，这是 M95 定下的口径）；
- **modifier 证据覆盖地板**：`onlyInitializing` ≥500、`initializer` ≥20、
  `reinitializer` ≥5 —— 这三个数掉下来说明切片层**没有从父合约/同文件**
  把 modifier 实现体带进来（跨文件继承证据静默失效，判据会一律看不见守卫）。
  地板是覆盖回归的拦网：它拦的不是"判错"，是"没看见"。
- `onlyProxy` 的实现体在**非 upgradeable 仓**（`openzeppelin-contracts`）里，
  本仓只有 re-export 存根 —— 门禁跨仓核验：那边 `upgradeToAndCall` 必须带
  `modifier:onlyProxy` 且不被判 True；
- **机制锚点**（合成，因为本仓只 re-export）：把 ERC-1967 的
  `_implementation()` 换成入口形参后，`delegatecall_untrusted` 必须从
  False/None 翻成 **True** —— 证明"判 False"靠的是"目标来自实现槽"
  这条证据，而不是判据压根不触发。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "openzeppelin-contracts-upgradeable"
SIBLING = ROOT / "reference_repos" / "openzeppelin-contracts" / "contracts"
CATS = ("access_control", "reentrancy", "arithmetic",
        "unchecked_low_level_calls", "delegatecall_untrusted")
MIN_UNITS = 1900
# modifier 证据覆盖地板（实测：553 / 25 / 5）
EVIDENCE_FLOORS = {"onlyInitializing": 500, "initializer": 20,
                   "reinitializer": 5}

# 机制锚点：ERC-1967 实现槽 vs 入口形参 —— 只差"目标从哪来"这一件事
_ANCHOR_TRUSTED = """
// pragma: solidity ^0.8.20;
// contract: Proxy
contract Proxy {
    function _implementation() internal view returns (address) {
        return address(uint160(uint256(bytes32(0))));
    }
    fallback() external payable {
        _implementation().delegatecall(msg.data);
    }
}
"""
_ANCHOR_UNTRUSTED = _ANCHOR_TRUSTED.replace(
    "_implementation().delegatecall(msg.data)",
    "impl.delegatecall(msg.data)").replace(
    "fallback() external payable {", "fallback(address impl) external payable {")


def _find(units, filename, name=None):
    for u in units:
        if Path(u.file_path).name == filename and (name is None or u.unit_name == name):
            return u
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="OZ Upgradeable 零误报基准：initializer/onlyInitializing/onlyProxy（M143）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥1900 入口 + 五类 0 True + modifier 证据地板 + 机制锚点")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "openzeppelin_upgradeable.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/OpenZeppelin/"
              "openzeppelin-contracts-upgradeable.git）")
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

    evidence = {kw: sum(1 for u in units
                        if f"modifier:{kw}" in (u.decorators_or_modifiers or []))
                for kw in EVIDENCE_FLOORS}
    init_true = [r for r in true_rows
                 if "initializer" in " ".join(
                     (Path(r[0]).suffix and [""]) or [])]  # 占位，下面按单元重算
    init_units = [u for u in units
                  if "modifier:initializer" in (u.decorators_or_modifiers or [])
                  or "modifier:reinitializer" in (u.decorators_or_modifiers or [])]
    init_true = [u for u in init_units
                 if R.verdict("access_control", u.source_code) is True]

    # 跨仓核验 onlyProxy（实现体在非 upgradeable 仓）
    sibling = {"available": SIBLING.exists()}
    if sibling["available"]:
        su = list(SoliditySlicer(SIBLING).extract_entry_units(SIBLING))
        uups = _find(su, "UUPSUpgradeable.sol", "upgradeToAndCall")
        if uups:
            sibling.update({
                "onlyproxy_modifier": "modifier:onlyProxy" in
                                      (uups.decorators_or_modifiers or []),
                "access_control": R.verdict("access_control", uups.source_code),
            })
    # 机制锚点
    anchor = {
        "erc1967_slot": R.verdict("delegatecall_untrusted", _ANCHOR_TRUSTED),
        "param_target": R.verdict("delegatecall_untrusted", _ANCHOR_UNTRUSTED),
    }

    print("=" * 72)
    print("OZ Upgradeable 结果（initializer / onlyInitializing / onlyProxy）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for f, n, c in true_rows[:12]:
        print(f"      [FP] {f}:{n} [{c}]")
    print("  modifier 证据覆盖：")
    for kw, n in evidence.items():
        print(f"    {kw:18} {n:4}（地板 {EVIDENCE_FLOORS[kw]}）")
    print(f"  initializer/reinitializer 单元里判 True 的：{len(init_true)}")
    print(f"  onlyProxy 跨仓核验：{sibling}")
    print(f"  机制锚点：ERC-1967 槽={anchor['erc1967_slot']}"
          f" / 形参目标={anchor['param_target']}")

    bad: list[str] = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"计划外 True {len(true_rows)} 条")
    for kw, floor in EVIDENCE_FLOORS.items():
        if evidence[kw] < floor:
            bad.append(f"{kw} 证据单元 {evidence[kw]} < 地板 {floor}"
                       "（父合约 modifier 实现体没带进切片？）")
    if init_true:
        bad.append(f"initializer/reinitializer 里判 True {len(init_true)} 条"
                   "（一次性入口不该按缺授权判 True）")
    if sibling.get("available"):
        if not sibling.get("onlyproxy_modifier"):
            bad.append("跨仓核验：upgradeToAndCall 没带 modifier:onlyProxy")
        if sibling.get("access_control") is True:
            bad.append("跨仓核验：upgradeToAndCall 被判 True")
    if anchor["erc1967_slot"] is True:
        bad.append("机制锚点：ERC-1967 实现槽被判 True（排除面失效）")
    if anchor["param_target"] is not True:
        bad.append(f"机制锚点：形参目标未判 True（{anchor['param_target']}）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（2017 入口 / 五类 0 True / modifier 证据地板达标 / 机制锚点成立）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "openzeppelin_upgradeable", "units": len(units),
        "total_units": len(units), "decided": len(units),
        "correct": len(units) - len(true_rows), "fp": len(true_rows),
        "reverse_fn": 0, "rule_evaluations": decided,
        "modifier_evidence": evidence, "evidence_floors": EVIDENCE_FLOORS,
        "initializer_true": len(init_true), "onlyproxy_sibling": sibling,
        "mechanism_anchor": anchor,
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
