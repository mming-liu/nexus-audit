"""按需跨文件上下文工具实现（第1周实现）。

复刻 vulnhuntr 的 Context Expansion Loop：向 LLM 暴露两个工具，最多 3 轮索取
被调用函数源码，直到污点链完整。

  - get_symbol_implementation(symbol_name, current_file)
  - get_global_middlewares(route_path)

本模块不依赖任何 LLM SDK：execute_tool() 供 router 层的 function-calling
结果分发；run_context_loop() 提供纯本地循环骨架，由上层注入 LLM 客户端。
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from core.context.symbol_indexer import SymbolIndexer
from core.models import CodeUnit

CONTEXT_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "get_symbol_implementation",
            "description": "当需要确认某个被调用的 Service/DAO 函数、权限检查函数或父合约修饰符的具体实现时调用此工具。",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {"type": "string", "description": "函数名、类名或修饰符名称，如 check_order_owner 或 onlyRole"},
                    "current_file": {"type": "string", "description": "当前正在审计的文件路径"},
                },
                "required": ["symbol_name", "current_file"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_global_middlewares",
            "description": "查询指定 Web 路由是否受到全局鉴权中间件（如 Django MIDDLEWARE / Spring Interceptor / FastAPI Depends）保护。",
            "parameters": {
                "type": "object",
                "properties": {
                    "route_path": {"type": "string", "description": "API 路由路径，如 /api/v1/orders/{order_id}"},
                },
                "required": ["route_path"],
            },
        },
    },
]


class ToolDispatcher:
    """把 LLM 的 function-call 结果分发到本地符号索引。"""

    def __init__(self, indexer: SymbolIndexer):
        self.indexer = indexer

    def execute_tool(self, name: str, arguments: dict) -> str:
        if name == "get_symbol_implementation":
            result = self.indexer.get_symbol_code(arguments["symbol_name"])
            if result is None:
                return f"未找到符号 {arguments['symbol_name']} 的定义，请尝试更短的方法名。"
            return result["source"]
        if name == "get_global_middlewares":
            hits = self.indexer.find_middleware(arguments["route_path"])
            if not hits:
                return f"未发现针对 {arguments['route_path']} 的全局中间件配置，该路由可能未受统一鉴权保护。"
            return "\n\n".join(f"[{h['file']}]\n{h['match']}" for h in hits)
        raise ValueError(f"未知工具: {name}")


def run_context_loop(
    units: list[CodeUnit],
    repo_path: str | Path,
    audit_prompt: Callable[[list[dict]], str] | None = None,
    max_rounds: int = 3,
) -> list[dict]:
    """vulnhuntr 式上下文扩展循环（本地骨架）。

    每轮：解析 unit 的 called_symbols -> 逐个拉取实现 -> 追加到上下文。
    audit_prompt: 可注入的 LLM 回调，接收已积累的上下文块列表并返回
    下一轮希望索取的 symbol 列表；不传则直接全量展开 called_symbols。

    返回：[{"unit": unit_name, "rounds": n, "context_blocks": [...]}]
    """
    indexer = SymbolIndexer(repo_path)
    indexer.build()
    dispatcher = ToolDispatcher(indexer)

    results: list[dict] = []
    # 框架噪声符号：出现在装饰器中或属常见 Flask/FastAPI 属性名，不值得跨文件索取
    noisy = {"route", "get", "post", "put", "patch", "delete", "jsonify", "request", "app", "run"}
    for unit in units:
        context_blocks: list[dict] = [{"role": "entry", "symbol": unit.unit_name, "source": unit.source_code}]
        pending = [s for s in unit.called_symbols if s not in noisy]
        rounds = 0
        while pending and rounds < max_rounds:
            rounds += 1
            symbol = pending.pop(0)
            source = dispatcher.execute_tool("get_symbol_implementation",
                                             {"symbol_name": symbol, "current_file": unit.file_path})
            context_blocks.append({"role": "expansion", "symbol": symbol,
                                   "round": rounds, "source": source})
            # 若成功取回实现且内部还有调用，继续按需展开（预算控制）
            if "未找到符号" not in source:
                for m in unit.called_symbols:
                    if m not in {b["symbol"] for b in context_blocks} and m not in pending:
                        pending.append(m)
        results.append({"unit": unit.unit_name, "file": unit.file_path,
                        "rounds": rounds, "context_blocks": context_blocks})
    return results
