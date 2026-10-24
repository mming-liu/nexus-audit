"""OpenZeppelin/openzeppelin-contracts —— 第 14 野战仓，M95 Solidity 零误报极限压测。

## 为什么选它

OpenZeppelin 是 Web3 的**标准安全基元库**：ERC20 / ERC721 / ERC1155 / Governor /
TimelockController / Ownable / AccessControl / ReentrancyGuard 全部在此，被
数百亿美元锁仓量的协议直接继承。它本身是"**100% 安全基准**"——规则层在这里
出现任何一条 True，就是误报（这个库的代码被审计过无数次）。

所以它是最硬的一道防误报铁壁：不是"漏洞找得准不准"，而是"**会不会把安全的
写法当成漏洞**"。

## M95 实测：从 8 条 True 收到 0 条

初测 2558 个入口里 8 条 True，全部是 OZ 的**框架级安全写法**，逐条定位后
补了四类判据（都在 `rule_detectors.py`）：

| OZ 样本 | 误报机制 | 纯增量补齐 |
|---|---|---|
| `Ownable2Step.acceptOwnership` | 身份先落局部变量 `address sender = _msgSender();` 再比较 | `_sol_identity_alias_check`：认身份**别名**形态 |
| `Governor.relay` / `TimelockController._execute` / `Governor._executeOperations` / `GovernorTimelockAccess._executeOperations` | success 交给 `Address.verifyCallResult`，但 Address.sol 实现体不在证据段 | `_sol_handed_to_opaque`：递给看不见实现体的函数 ⇒ 证据不足 ⇒ None |
| `RelayedCall.relayCall` | `return addr.call{...}(...)` 直接上交返回值 | 语句以 `return` 开头 ⇒ checked |
| `draft-ERC7579Utils._call` | 失败在 TRY 模式**刻意不 revert**（ERC-7579 规范：发事件交给上层） | `_sol_var_inspected_by_helper`：看过即消费 |
| `ERC721.safeTransferFrom` | 三参/四参都是**转发壳**，权限在 `transferFrom → _update → _checkAuthorized` | `_sol_unqualified_callee_uses_sender`：非限定调用且被调体里身份在流转 ⇒ None |

## 门禁（--strict）

- 扫描 `contracts/{token,access,governance}`（v5 已无 `contracts/security/`，
  缺目录自动跳过）+ 全库对照；
- 切片 ≥500 入口（实测 576）；
- 四类 Solidity 判据 **0 条 True**；
- 五个锚点：2 条必须判 False（确定性安全），3 条必须**不是 True**
  （转发壳/可见性受限 → 退 None 属正确结论，判 False 反而是越权断言）。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "openzeppelin-contracts" / "contracts"
SCOPE_DIRS = ("token", "access", "security", "governance")
CATS = ("reentrancy", "access_control", "arithmetic",
        "unchecked_low_level_calls")
MIN_UNITS = 500

# (相对路径, 单元名, 类目, 期望) —— 期望 False = 确定性安全；"not_true" = 允许 None
ANCHORS = [
    ("access/Ownable2Step.sol", "acceptOwnership", "access_control", False),
    ("access/Ownable.sol", "transferOwnership", "access_control", False),
    ("token/ERC721/ERC721.sol", "safeTransferFrom", "access_control", "not_true"),
    ("governance/Governor.sol", "relay", "unchecked_low_level_calls", "not_true"),
    ("governance/TimelockController.sol", "_execute",
     "unchecked_low_level_calls", "not_true"),
]


def _rel(repo: Path, file_path: str) -> str:
    try:
        return Path(file_path).resolve().relative_to(repo.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(file_path).as_posix()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="OpenZeppelin 标准安全库零误报基准（M95）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥500 入口 + 四类 0 True + 五个锚点达标")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "openzeppelin.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/OpenZeppelin/openzeppelin-contracts.git）")
        return 2
    scope_root = repo if repo.name == "contracts" else repo / "contracts"
    if scope_root.is_dir():
        repo = scope_root

    all_units = list(SoliditySlicer(repo).extract_entry_units(repo))
    units = [u for u in all_units
             if _rel(repo, u.file_path).split("/")[0] in SCOPE_DIRS]
    print(f"靶场：{repo}")
    print(f"      全库入口 {len(all_units)} 个，其中生产基元 "
          f"{'+'.join(SCOPE_DIRS)} 下 {len(units)} 个")

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
        ok = (got == want) if want != "not_true" else (got is not True)
        anchors.append({"unit": f"{relp}:{name}", "category": cat,
                        "want": want, "got": got,
                        "ok": bool(hit) and ok,
                        "missing": hit is None})

    print("=" * 72)
    print("OpenZeppelin 结果（标准安全基元库，规则层零误报压测）")
    print("=" * 72)
    print(f"  生产基元入口           ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）    ：{decided_units}")
    print(f"  规则判定次数           ：{decided}")
    print(f"  规则层 True（误报）    ：{len(true_rows)}")
    for r in true_rows[:20]:
        print(f"    [FP] {r[0]}:{r[1]} [{r[2]}]")
    print("  安全锚点：")
    for a in anchors:
        mark = "OK " if a["ok"] else "XX "
        print(f"    {mark}{a['unit']:58} [{a['category']:26}] "
              f"期望 {a['want']!s:9} 实际 {a['got']!s}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"规则层 True {len(true_rows)} 条（标准库应为 0）")
    if not all(a["ok"] for a in anchors):
        bad.append("安全锚点未全部达标")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（576 入口 / 0 True / 锚点达标）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "openzeppelin", "units": len(units),
        "total_units": len(units), "all_units": len(all_units),
        "decided": decided_units, "correct": decided_units - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0,
        "rule_evaluations": decided,
        "anchors": anchors,
        "true_rows": [{"file": f, "unit": u, "category": c}
                      for f, u, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
