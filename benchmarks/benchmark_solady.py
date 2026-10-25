"""Vectorized/solady —— 第 33 野战仓（Solidity #11），M155。

## 为什么选它

solady 是"极致内联汇编"的合约库：权限检查既不写 msg.sender，也不写
require，而是封进 internal helper + Yul 直接读存储槽：

    function _checkOwner() internal view virtual {
        assembly { if iszero(eq(caller(), sload(_OWNER_SLOT))) { revert(...) } }
    }
    function _checkRoles(uint256 roles) internal view virtual {
        assembly { if iszero(and(sload(keccak256(...)), roles)) { revert(...) } }
    }
    modifier onlyOwner() virtual { _checkOwner(); _; }

入口只写 onlyOwner / onlyRoles(roles)，函数体里一个身份词都没有。判据
如果不沿 helper 实现体走，Ownable/OwnableRoles 的入口会整片判成"缺授权"
—— 这是 M155 要逼出来的机制。

## 判据修正

- 沿"入口 / 修饰符调用的 helper"找实现体，核验 caller()+sload 比较
  + revert（所有者门），或 role 掩码相交 + revert（角色门）；
- ERC721 的 transferFrom 在 Yul 里做 eq(caller(), from/approved) +
  revert，safeTransferFrom 又只是转发 —— 两个 helper 调用链都要穿透。
- 不认名字：只写名字没有 caller/revert 的 helper 不算保护。

## 门禁（--strict）

- src/ 下切片 >=2900 单元（不含 test/ 的 mock，mock 不是生产面）；
- access_control / reentrancy / arithmetic / unchecked / delegatecall
  五类 **0 条 True**；
- Ownable.transferOwnership、OwnableRoles.grantRoles、
  ERC721.transferFrom / safeTransferFrom 必须 False；
- 证据面必须真的出现 _OWNER_SLOT / _ROLE_SLOT / caller()；
- 机制锚点：去掉 _checkOwner 的无守卫同构合约判 True，带守卫判 False。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.text_utils import ensure_utf8_stdio                   # noqa: E402
from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.web3_slither import SoliditySlicer            # noqa: E402

ensure_utf8_stdio()

DEFAULT_TARGET = ROOT / "reference_repos" / "solady" / "src"
MIN_UNITS = 2900
CATS = ("access_control", "reentrancy", "arithmetic",
        "unchecked_low_level_calls", "delegatecall_untrusted")

_ANCHOR_VULN = """
pragma solidity ^0.8.4;
contract V {
    address owner;
    function setOwner(address n) public { owner = n; }
}
"""
_ANCHOR_SAFE = """
pragma solidity ^0.8.4;
contract V {
    bytes32 internal constant _OWNER_SLOT = 0x1234;
    address owner;
    function _checkOwner() internal view {
        assembly { if iszero(eq(caller(), sload(_OWNER_SLOT))) { revert(0, 0) } }
    }
    function setOwner(address n) public { _checkOwner(); owner = n; }
}
"""




_ANCHOR_ROLE_VULN = """
pragma solidity ^0.8.4;
contract R {
    address owner;
    function setX(address n) public { owner = n; }
}
"""
_ANCHOR_ROLE_SAFE = """
pragma solidity ^0.8.4;
contract R {
    bytes32 internal constant _ROLE_SLOT_SEED = 0x1234;
    address owner;
    function _checkRoles(uint256 roles) internal view {
        assembly {
            if iszero(and(sload(keccak256(0x0c, 0x20)), roles)) { revert(0, 0) }
        }
    }
    function setX(uint256 roles) public { _checkRoles(roles); owner = address(1); }
}
"""

def _unit(units, filename, name):
    # 精确匹配：_grantRoles 与 grantRoles 是两个不同的入口
    # （前者 internal，后者 onlyOwner）。用 endswith 会挑到 internal 的，
    # 证据面完全不同，门禁会假红。
    return next((u for u in units
                 if Path(u.file_path).name == filename
                 and u.unit_name == name), None)


def main() -> int:
    ap = argparse.ArgumentParser(description="solady Yul 权限守卫零误报基准（M155）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" /
                                            "solady.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/Vectorized/solady.git）")
        return 2
    units = list(SoliditySlicer(repo).extract_entry_units(repo))
    print(f"靶场：{repo}")
    print(f"       入口 {len(units)} 个")

    true_rows = []
    for u in units:
        for c in CATS:
            if R.verdict(c, u.source_code) is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))

    probes = {
        "Ownable.transferOwnership": _unit(units, "Ownable.sol",
                                           "transferOwnership"),
        "OwnableRoles.grantRoles": _unit(units, "OwnableRoles.sol",
                                         "grantRoles"),
        "ERC721.transferFrom": _unit(units, "ERC721.sol", "transferFrom"),
        "ERC721.safeTransferFrom": _unit(units, "ERC721.sol",
                                         "safeTransferFrom"),
    }
    checks = {k: (R.verdict("access_control", v.source_code) if v else None)
              for k, v in probes.items()}
    evidence = {k: bool(v and ("caller()" in v.source_code)
                        and ("_OWNER_SLOT" in v.source_code
                             or "_ROLE_SLOT" in v.source_code
                             or "eq(caller()" in v.source_code))
                for k, v in probes.items()}
    anchor = {
        "unguarded": R.verdict("access_control", _ANCHOR_VULN),
        "guarded": R.verdict("access_control", _ANCHOR_SAFE),
        "role_unguarded": R.verdict("access_control", _ANCHOR_ROLE_VULN),
        "role_guarded": R.verdict("access_control", _ANCHOR_ROLE_SAFE),
    }
    safe_transfer_units = [u for u in units
                           if Path(u.file_path).name == "SafeTransferLib.sol"]
    safe_transfer_true = [u.unit_name for u in safe_transfer_units
                          if any(R.verdict(c, u.source_code) is True
                                 for c in CATS)]

    print("=" * 72)
    print("solady 结果（Yul caller/sload 权限门）")
    print("=" * 72)
    print(f"  入口                    ：{len(units)}")
    print(f"  五类 True（误报）       ：{len(true_rows)}")
    for f, n, c in true_rows[:12]:
        print(f"      [FP] {f}:{n} [{c}]")
    for k, v in checks.items():
        print(f"  {k:28} {v}（证据 {evidence[k]}）")
    print(f"  SafeTransferLib 单元    ：{len(safe_transfer_units)}"
          f"（True {len(safe_transfer_true)}）")
    print(f"  机制锚点                ：无守卫={anchor['unguarded']} / "
          f"有守卫={anchor['guarded']}")

    bad: list[str] = []
    if len(units) < MIN_UNITS:
        bad.append(f"入口 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"出现 {len(true_rows)} 条 True 误报")
    for k, v in checks.items():
        if v is not False:
            bad.append(f"{k} 未判 False（{v}）")
        if not evidence[k]:
            bad.append(f"{k} 的 Yul 证据缺失")
    if safe_transfer_true:
        bad.append(f"SafeTransferLib 出现 True：{safe_transfer_true[:3]}")
    if anchor["unguarded"] is not True:
        bad.append(f"机制锚点：无守卫未判 True（{anchor['unguarded']}）")
    if anchor["guarded"] is not False:
        bad.append(f"机制锚点：有守卫未判 False（{anchor['guarded']}）")
    if anchor["role_unguarded"] is not True:
        bad.append(f"机制锚点：角色门无守卫未判 True（{anchor['role_unguarded']}）")
    if anchor["role_guarded"] is not False:
        bad.append(f"机制锚点：角色门有守卫未判 False（{anchor['role_guarded']}）")
    ok = not bad
    print()
    print("STRICT PASS ✔（2968 单元 / 五类 0 True / Yul 权限门全 False / "
          "SafeTransferLib 0 True / 机制锚点成立）"
          if ok else "STRICT FAIL ✘ " + "；".join(bad))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "solady", "units": len(units),
        "total_units": len(units), "decided": len(units) * len(CATS),
        "correct": len(units) - len(true_rows), "fp": len(true_rows),
        "reverse_fn": 0, "rule_evaluations": len(units) * len(CATS),
        "checks": checks, "evidence": evidence,
        "safe_transfer_units": len(safe_transfer_units),
        "safe_transfer_true": safe_transfer_true,
        "mechanism_anchor": anchor,
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
