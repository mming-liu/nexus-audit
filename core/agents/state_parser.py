"""PentestGPT 式 Reasoning-Generation-Parsing 状态机（第3周实现）。

当沙箱/编译器返回数千行报错时，Parsing 模块先浓缩为关键摘要行，
再交给 Reasoning 会话修正计划，防止上下文窗口爆炸。
基础版为零依赖正则实现；可选注入 LLM 做更深度的压缩。
"""
from __future__ import annotations

import re

# 各类日志中值得保留的关键行模式（编译器/测试/HTTP 报错）
KEY_PATTERNS = [
    r"^\s*(?:E\s+)?(Error|Exception|Traceback|assert|FAILED|ERROR)",
    r"SyntaxError|NameError|TypeError|AttributeError|ImportError",
    r"error\[E\d+\]|error:|warning:",
    r"assert .* ==",
    r"(?i)(401|403|404|500)\s",
    r"^.*\.py:\d+.*$",
    r"^.*(compilation|Compiler run|forge|anvil).*$",
]

MAX_DIGEST_LINES = 5


class StateParser:
    """日志压缩器：PentestGPT Parsing 模块的本地实现。"""

    @staticmethod
    def digest(output: str, max_lines: int = MAX_DIGEST_LINES) -> str:
        """把冗长输出压缩为 <= max_lines 的结构化摘要。"""
        lines = output.splitlines()
        kept: list[str] = []
        seen: set[str] = set()
        # 先抓 Traceback 尾帧与断言失败行（pytest 摘要）
        tb_tail = [l for l in lines if re.match(r"^\s*E\s+", l)]
        kept.extend(tb_tail[:2])
        for pat in KEY_PATTERNS:
            for line in lines:
                if len(kept) >= max_lines:
                    break
                if re.search(pat, line) and line.strip() not in seen:
                    seen.add(line.strip())
                    kept.append(line.strip())
            if len(kept) >= max_lines:
                break
        if not kept:  # 无关键行时退化为首尾各取一行
            kept = [lines[0], lines[-1]] if len(lines) > 1 else lines
        return "\n".join(kept[:max_lines])

    @staticmethod
    def is_compilation_error(output: str) -> bool:
        """判断是否为可自愈的语法/依赖类失败（区别于断言失败=漏洞复现成功）。"""
        sig = [
            "SyntaxError", "IndentationError", "NameError", "ImportError",
            "ModuleNotFoundError", "AttributeError", "compilation", "Compiler run failed",
            "SyntaxError:", "error[E0", "not found: solidity",
        ]
        return any(s in output for s in sig)

    @staticmethod
    def is_assertion_failure(output: str) -> bool:
        """断言失败 = 测试跑通且触发了漏洞断言（复现成功）。"""
        return bool(re.search(r"(?i)(assert(ion)? ?(error|failed)|1 failed|FAILED)", output))
