"""Web 路由入口提取器（第1周实现，借鉴 vulnhuntr）。

当前实现：基于 SymbolIndexer 的零依赖路由提取，覆盖 Flask / FastAPI / DRF
的路由装饰器。升级点：tree_sitter 可用时用精确 AST 解析替换正则回退。

用法：
    slicer = WebTreeSitterSlicer(repo_path)
    units = slicer.extract_entry_units(repo_path)   # -> List[CodeUnit]
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from core.context.symbol_indexer import SymbolIndexer
from core.models import CodeUnit

try:  # 可选增强：tree-sitter 就绪时切换精确解析
    import tree_sitter  # noqa: F401
    HAVE_TREE_SITTER = True
except ImportError:
    HAVE_TREE_SITTER = False


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
        return filtered
