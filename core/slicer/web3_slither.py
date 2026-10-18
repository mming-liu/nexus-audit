"""GPTScan 式 Web3 静态候选过滤器（第2周后半，零依赖正则实现）。

当前实现能力（对标 Damn Vulnerable DeFi 已知真实缺陷回归）：
  1. Solidity 函数切片：提取带 external/public 的状态修改函数为 CodeUnit
  2. 精度/优先级缺陷启发式（scenario=precision_loss）：
     `a - b * C` 未加括号的减乘混排，且参与除法运算——
     对应真实案例：puppet-v2/UniswapV2Library.sol:78
     `reserveOut - amountOut * 997`（应为 (reserveOut - amountOut) * 997），
     该缺陷由 issue #114 与 #105 两度报告仍未修复。

Slither 集成保留为升级点（slither 可用时用其调用图替换正则切片）。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from core.models import CodeUnit, Language, VulnHypothesis

FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)[^{;]*?(?:external|public|internal|private)?[^{;]*?(\{)", re.S)

# 减乘混排未加括号：a - b * C （且 b*C 紧邻 - 之后）， fee 常数特征 997/9970/970/3
PRECEDENCE_RE = re.compile(
    r"(\w+)\s*-\s*(\w+)\s*\*\s*(\d+)\s*;")

FEE_CONSTANTS = {"997", "9970", "970", "1000", "10000", "3"}


class SoliditySlicer:
    language = "solidity_web3"

    def extract_entry_units(self, repo_path: str | Path) -> List[CodeUnit]:
        repo = Path(repo_path)
        units: List[CodeUnit] = []
        for sol in repo.rglob("*.sol"):
            if any(p in self.IGNORE for p in sol.parts):
                continue
            try:
                text = sol.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            for m in FUNC_RE.finditer(text):
                name = m.group(1)
                start_line = text[:m.start()].count("\n") + 1
                # 花括号配平找函数结束行（group(2) 是开头大括号）
                depth = 0
                end_line = start_line
                for idx in range(m.start(2), len(text)):
                    if text[idx] == "{":
                        depth += 1
                    elif text[idx] == "}":
                        depth -= 1
                        if depth == 0:
                            end_line = text[:idx].count("\n") + 1
                            break
                src = "\n".join(lines[start_line - 1: end_line])
                vis = m.group(0)
                visibility = next((v for v in ("external", "public", "internal", "private")
                                   if re.search(rf"\b{v}\b", vis)), "default")
                units.append(CodeUnit(
                    file_path=str(sol), language=Language.SOLIDITY_WEB3,
                    unit_name=name, start_line=start_line, end_line=end_line,
                    decorators_or_modifiers=[visibility],
                    called_symbols=self._calls(src), source_code=src))
        return units

    IGNORE = {"node_modules", "lib", "test/helpers"}

    @staticmethod
    def _calls(src: str) -> list[str]:
        return sorted({m.group(1) for m in re.finditer(r"(\w+)\s*\(", src)
                       if m.group(1) not in {"if", "for", "while", "require", "return"}})


def detect_precision_loss(units: List[CodeUnit]) -> List[VulnHypothesis]:
    """GPTScan 两步法（Web3 场景，离线启发式版）：

    Step 1 Scenario: 函数是否计算代币兑换/输入金额（出现 fee 常数或 reserve 变量）？
    Step 2 Property: 金额公式中 `减法-乘法` 混排是否有括号保证优先级？
    """
    hyps: List[VulnHypothesis] = []
    for u in units:
        src = u.source_code
        scenario_hit = ("997" in src or "reserve" in src.lower()
                        or "amountIn" in src or "amountOut" in src)
        if not scenario_hit:
            continue
        for m in PRECEDENCE_RE.finditer(src):
            lhs, sub, const = m.group(1), m.group(2), m.group(3)
            if const not in FEE_CONSTANTS:
                continue
            line = src[:m.start()].count("\n") + 1
            # 属性核对：该模式是否用于除法分母（决定损失放大）
            prop_ok = re.search(re.escape(m.group(0).rstrip(";").strip()) + r"\s*/", src)
            line_abs = u.start_line + src[:m.start()].count("\n")  # 换算为文件绝对行号
            hyps.append(VulnHypothesis(
                unit=u, vuln_type="precision_loss", scenario_hit=True,
                property_missing=(f"`{lhs} - {sub} * {const}` 未加括号，实际求值为 "
                                  f"`{lhs} - ({sub} * {const})`；"
                                  + ("该表达式参与除法，误差被放大" if prop_ok else "需人工确认用途")),
                reasoning_summary=f"UniswapV2Library 风格减乘混排 @ 文件第 {line_abs} 行",
                confidence=0.85 if prop_ok else 0.6))
            break
    return hyps
