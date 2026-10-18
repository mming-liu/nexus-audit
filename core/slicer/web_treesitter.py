"""vulnhuntr 式 Tree-sitter 路由入口提取器。

职责：解析 Python/Java/Go Web 后端，提取带路由装饰器的入口函数为 CodeUnit，
并记录其 called_symbols 供第2层按需跨文件展开。
TODO(第1周)：实现 Tree-sitter 符号提取 + Semgrep 路由规则联动。
"""
from typing import List

from core.models import CodeUnit


class WebTreeSitterSlicer:
    language = "python_web"

    ROUTE_DECORATORS = {
        "@app.route", "@api.route", "@blueprint.route",       # Flask
        "@get", "@post", "@put", "@delete", "@patch", "@api_view",  # FastAPI/DRF
        "@RequestMapping", "@GetMapping", "@PostMapping", "@DeleteMapping",  # Spring
    }

    def extract_entry_units(self, repo_path: str) -> List[CodeUnit]:
        raise NotImplementedError("第1周实现：Tree-sitter 路由函数提取")
