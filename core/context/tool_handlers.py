"""vulnhuntr 式按需跨文件上下文工具实现。

暴露给 LLM 的标准工具定义（OpenAI function calling 格式）：
  - get_symbol_implementation(symbol_name, current_file)
  - get_global_middlewares(route_path)

TODO(第1周)：接入 symbol_indexer 实现最多 3 轮的 Context Expansion Loop。
"""

# 供 LLM 主动调用的工具 schema（计划书第三层接口）
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
