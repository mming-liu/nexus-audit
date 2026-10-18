"""第1层切片器统一接口契约（Protocol）。所有切片器输出 CodeUnit 列表。"""
from typing import List, Protocol

from core.models import CodeUnit


class BaseSlicer(Protocol):
    def extract_entry_units(self, repo_path: str) -> List[CodeUnit]:
        """
        Web 端：结合 Tree-sitter 与 Semgrep 规则，仅提取带有路由装饰器
        (@app.route / @PostMapping) 的入口函数。

        Web3 端：调用 Slither API (slither.contracts)，仅提取 visibility 为
        external/public 且修改状态变量或含外部调用的函数。

        共同要求：先筛掉无副作用的纯读取/视图函数，输出统一 CodeUnit。
        """
        ...
