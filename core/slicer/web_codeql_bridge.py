"""IRIS 式 CodeQL 污点流 Source/Sink 桥接器。

职责：企业内部框架与自定义 ORM 的敏感汇点自动识别——
让 LLM 阅读函数签名自动标注 Source / Sink，再喂回 CodeQL 查询。
TODO(第2周)：实现 CodeQL 查询模板 + LLM 标注回填。
"""
from typing import List

from core.models import CodeUnit


class CodeQLBridge:
    def extract_entry_units(self, repo_path: str) -> List[CodeUnit]:
        raise NotImplementedError("第2周实现：CodeQL Source/Sink 桥接")
