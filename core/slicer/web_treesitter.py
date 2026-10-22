"""Web 路由入口提取器（第1周实现，借鉴 vulnhuntr）。

当前实现：基于 SymbolIndexer 的零依赖路由提取，覆盖 Flask / FastAPI / DRF
的路由装饰器。升级点：tree_sitter 可用时用精确 AST 解析替换正则回退。

2026-10-21（Module 5）：补上与 Java 赛道对齐的**多跳展开** ——
入口调用的辅助函数/Service/DAO 方法体按 `[Hop N]` 段拼进切片，深度
`MAX_HOPS`，带 `_visited` 防环与段数预算（与 Java 侧
`MAX_HELPER_SEGMENTS` 同思路：深度与 token 同时管）。
没有这一层，Python 入口的 sink 藏在第 2/3 跳时，规则与模型都只能
看到第 1 跳的转发语句 —— 断链的表现是"静默退回"。

段头格式与 Java 对齐（`// 来自 文件:行 [Hop N]`），证据解析与
`entry_body()` 的截断逻辑可直接复用。辅助方法体**不加 `//` 前缀**：
它们是真实代码（可被引证核验），段头注释只负责分界。

用法：
    slicer = WebTreeSitterSlicer(repo_path)
    units = slicer.extract_entry_units(repo_path)   # -> List[CodeUnit]
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from core.context.symbol_indexer import SymbolIndexer
from core.models import CodeUnit

try:  # 可选增强：tree-sitter 就绪时切换精确解析
    import tree_sitter  # noqa: F401
    HAVE_TREE_SITTER = True
except ImportError:
    HAVE_TREE_SITTER = False

MAX_HOPS = 3                 # 与 Java 侧同深度：1 跳转发 + 2 跳实现
MAX_HELPER_SEGMENTS = 6      # 段数预算：防止单入口把切片撑爆

_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_CALL_EXCLUDE = {"if", "for", "while", "with", "range", "len", "str", "int",
                 "float", "bool", "print", "set", "dict", "list", "sorted",
                 "isinstance", "super", "enumerate", "zip", "open",
                 "getattr", "hasattr", "type", "id", "repr", "format"}


class WebTreeSitterSlicer:
    language = "python_web"

    def __init__(self, repo_path: str | Path):
        self.repo_path = repo_path

    def extract_entry_units(self, repo_path: str | Path | None = None) -> List[CodeUnit]:
        """提取带路由装饰器的入口函数为 CodeUnit。

        过滤策略（对齐计划书第一层契约）：
          - 仅保留带路由装饰器的符号
          - 剔除 GET-only 且无请求体读取的纯只读接口可在此扩展
        """
        indexer = SymbolIndexer(repo_path or self.repo_path)
        indexer.build()
        units = indexer.to_code_units()
        # 只保留真正带路由标记的（decorators 含 route/get/post 等）
        route_kw = ("route", "get", "post", "put", "patch", "delete", "api_view", "mapping")
        filtered = [u for u in units
                    if any(any(k in d.lower() for k in route_kw) for d in u.decorators_or_modifiers)]
        for u in filtered:
            self._expand_helpers(indexer, u)
        return filtered

    # ---------------- 多跳展开 ----------------

    @staticmethod
    def _called_names(source: str) -> list[str]:
        """源码里的调用名（保序去重）。与 SymbolIndexer._extract_called_symbols
        同口径但保留出现顺序 —— 展开顺序必须可复现，否则切片文本抖动。"""
        out: list[str] = []
        for m in _CALL_RE.finditer(source):
            n = m.group(1)
            if n not in _CALL_EXCLUDE and not n.isupper() and n not in out:
                out.append(n)
        return out

    def _expand_helpers(self, indexer: SymbolIndexer, u: CodeUnit) -> None:
        """把入口可达的辅助方法体按跳拼进切片（BFS，带防环与预算）。

        只展开"索引里真有定义"的符号 —— 内置名/未导入名直接跳过。
        `_visited` 防环：A→B→A 的循环依赖在真实项目里存在（service 与
        dao 互引），没有它 BFS 会把同一方法体贴进来两次。
        """
        visited = {u.unit_name}
        segments: list[tuple[str, int, int, str]] = []   # (file, line, hop, src)
        frontier = self._called_names(u.own_body or u.source_code)
        for hop in range(1, MAX_HOPS + 1):
            if not frontier or len(segments) >= MAX_HELPER_SEGMENTS:
                break
            nxt: list[str] = []
            for name in frontier:
                if len(segments) >= MAX_HELPER_SEGMENTS:
                    break
                if name in visited:
                    continue
                visited.add(name)
                code = indexer.get_symbol_code(name, prefer_file=u.file_path)
                if not code or not (code.get("source") or "").strip():
                    continue
                segments.append((code["file_path"], code["start_line"],
                                 hop, code["source"]))
                if len(segments) < MAX_HELPER_SEGMENTS:
                    nxt.extend(self._called_names(code["source"]))
            frontier = [n for n in dict.fromkeys(nxt) if n not in visited]
        if not segments:
            return
        block = ["", "// ---- 跨文件辅助方法实现（入口方法调用的外部方法，按跳展开）----"]
        for fp, line, hop, src in segments:
            block.append(f"// 来自 {Path(fp).name}:{line} [Hop {hop}]")
            block.extend(src.splitlines())
        u.source_code = (u.source_code or "") + "\n".join(block) + "\n"
        u.called_symbols = sorted({n for n in self._called_names(u.source_code)
                                   if n not in _CALL_EXCLUDE})
