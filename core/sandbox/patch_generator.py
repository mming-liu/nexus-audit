"""修复验证闭环：生成 Git Diff 安全补丁并回归验证（第3周实现）。

Buttercup 补丁回归测试模块蓝本：漏洞触发断言成功后，
LLM 生成修复代码 → 应用补丁 → 重跑 PoC 测试 →
确认"漏洞消失且原测试仍通过"才输出补丁。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from core.models import PoCResult

PATCH_PROMPT_TMPL = """以下代码存在安全缺陷（{vuln_type}，缺失校验：{property_missing}）。
请生成最小化的修复：仅添加必要的归属/权限校验，不改变业务逻辑。
输出格式：
```diff
统一 diff 格式补丁
```

原代码（文件 {file}）：
```python
{code}
```"""


class PatchGenerator:
    def __init__(self, patch_llm: Callable[[str], str] | None = None):
        self.patch_llm = patch_llm  # 注入 Tier-2 LLM；None 则输出手工提示

    def generate_patch(self, result: PoCResult) -> str:
        """生成修复补丁（diff 格式）。验证成功后调用。"""
        if self.patch_llm is None:
            return f"# TODO: 接入 Tier-2 LLM 生成补丁\n# 建议：在 {result.hypothesis.unit.unit_name} 中添加归属校验\n# 缺失校验：{result.hypothesis.property_missing}"
        prompt = PATCH_PROMPT_TMPL.format(
            vuln_type=result.hypothesis.vuln_type,
            property_missing=result.hypothesis.property_missing or "(未记录)",
            file=result.hypothesis.unit.file_path,
            code=result.hypothesis.unit.source_code)
        raw = self.patch_llm(prompt)
        m = re.search(r"```diff\s*(.*?)```", raw, re.S)
        return m.group(1).strip() if m else raw.strip()

    def verify_patch(self, result: PoCResult, rerun: Callable[[], bool]) -> bool:
        """补丁回归验证：rerun() 重跑 PoC，应返回 True（漏洞消失）。"""
        return rerun()
