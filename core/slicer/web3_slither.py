"""GPTScan 式 Slither 静态候选过滤器。

职责：调用 Slither API 提取 external/public 且修改状态变量或含外部调用的
合约函数，筛掉纯视图函数，输出统一 CodeUnit。
TODO(第2周)：实现 Slither 集成与修饰符提取。
"""
from typing import List

from core.models import CodeUnit


class SlitherSlicer:
    language = "solidity_web3"

    def extract_entry_units(self, repo_path: str) -> List[CodeUnit]:
        raise NotImplementedError("第2周实现：Slither 状态修改函数提取")
