"""M87 先行探针：0.8.x `unchecked` 块与自定义 `revert Error()` 的判据事实核查。

三个问题，全部要拿实测数字回答，不靠阅读代码下结论：

  P1  0.8 + unchecked 存在时，**块外**的算术式会不会被误判成溢出漏洞？
      （块外在 0.8 由编译器内置回滚，属确定性 safe）
  P2  `unchecked` 块里只有循环游标（`i++` / `i += 1`）时判什么？
  P3  `revert CustomError();` 形态的守卫，`_sol_block_aborts` 认不认？
      以及 `if (msg.sender != owner) revert NotOwner();` 的 access_control 判据。

    python benchmarks/probe_m87.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import (            # noqa: E402
    _sol_block_aborts, solidity_access_verdict, solidity_arithmetic_verdict,
)

PRAGMA = "// pragma: solidity ^0.8.15;\n"


def sol(body: str, name: str = "Contract") -> str:
    return (PRAGMA
            + f"// contract: {name}\n"
            + "contract X {\n"
            + body
            + "\n}\n")


CASES = [
    # (标签, 源码, 期望)
    ("P1a 块外加法（块内有 unchecked，块外加法应 safe）",
     sol("function f(uint256 amount) public {\n"
         "    unchecked { counter++; }\n"
         "    uint256 x = total + amount;\n"
         "}\n"), False),
    ("P1b 块外减法（0.8 编译器已检查）",
     sol("function g(uint256 amount) public {\n"
         "    unchecked { i++; }\n"
         "    total -= amount;\n"
         "}\n"), False),
    ("P1c 块内加法 + 外部形参、无守卫 → 真漏洞",
     sol("function h(uint256 amount) public {\n"
         "    unchecked { total += amount; }\n"
         "}\n"), True),
    ("P2a 块内仅循环游标 i++",
     sol("function k() public {\n"
         "    for (uint256 i = 0; i < n; i++) {\n"
         "        unchecked { i++; }\n"
         "    }\n"
         "}\n"), False),
    ("P2b 块内仅循环游标 i += 1",
     sol("function k2(uint256 n) public {\n"
         "    for (uint256 i = 0; i < n; ) {\n"
         "        unchecked { i += 1; }\n"
         "    }\n"
         "}\n"), False),
    ("P2c 块内减法 + 块外前置比较守卫（if + revert Error）",
     sol("error InsufficientBalance();\n"
         "function m(uint256 amount) public {\n"
         "    if (amount > balance) revert InsufficientBalance();\n"
         "    unchecked { balance -= amount; }\n"
         "}\n"), None),   # 现状待测：>= 形态认，> 形态未必
    ("P2d 块内减法 + require 带自定义错误第二参数",
     sol("function n(uint256 amount) public {\n"
         "    require(balance >= amount, InsufficientBalance());\n"
         "    unchecked { balance -= amount; }\n"
         "}\n"), False),
]

ABORT_CASES = [
    ("revert CustomError();", True),
    ("revert CustomError(arg1, arg2);", True),
    ("revert();", True),
    ("revert(\"boom\");", True),
    ("emit Log();", False),
    ("return;", True),
    ("_solve();", False),
]

ACCESS_CASES = [
    ("custom error 裸语句", sol(
        "error NotOwner();\n"
        "address owner;\n"
        "function onlyOwner() public {\n"
        "    if (msg.sender != owner) revert NotOwner();\n"
        "    selfdestruct(payable(msg.sender));\n"
        "}\n"), False),
    ("custom error 花括号块", sol(
        "error NotOwner();\n"
        "address owner;\n"
        "function onlyOwner2() public {\n"
        "    if (msg.sender != owner) { revert NotOwner(); }\n"
        "    selfdestruct(payable(msg.sender));\n"
        "}\n"), False),
    ("custom error 修饰器体", sol(
        "error NotOwner();\n"
        "address owner;\n"
        "modifier onlyOwnerM() {\n"
        "    if (msg.sender != owner) revert NotOwner();\n"
        "    _;\n"
        "}\n"
        "function drain() public onlyOwnerM {\n"
        "    selfdestruct(payable(msg.sender));\n"
        "}\n"), False),
]


def main() -> int:
    print("=" * 72)
    print("P1/P2  arithmetic（0.8.x unchecked 语义）")
    print("=" * 72)
    for label, src, want in CASES:
        got = solidity_arithmetic_verdict(src)
        mark = "OK " if got == want else ("?? " if want is None else "XX ")
        print(f"  {mark} {label}: {got!r}" + (f"  (期望 {want!r})" if want is not None else ""))

    print()
    print("=" * 72)
    print("P3a _sol_block_aborts 对自定义错误中止的识别")
    print("=" * 72)
    for body, want in ABORT_CASES:
        got = _sol_block_aborts(body)
        print(f"  {'OK ' if got == want else 'XX '} {body!r}: {got!r}"
              + ("" if got == want else f"  (期望 {want!r})"))

    print()
    print("=" * 72)
    print("P3b access_control 对 `revert CustomError()` 守卫的判定")
    print("=" * 72)
    for label, src, want in ACCESS_CASES:
        got = solidity_access_verdict(src)
        print(f"  {'OK ' if got == want else 'XX '} {label}: {got!r}"
              + ("" if got == want else f"  (期望 {want!r})"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
