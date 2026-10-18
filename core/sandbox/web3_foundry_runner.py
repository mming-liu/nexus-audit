"""Foundry 测试合约生成与执行运行器（第3周实现）。

流程：Generation（生成 Solidity 测试合约）→ Execution（本地 forge test，
可选 Anvil 分叉链）→ Parsing & Self-Healing（编译报错最多 3 轮自愈，
复刻 OSS-Fuzz-Gen 循环）。需要本机安装 Foundry（forge / anvil）。
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from core.agents.state_parser import StateParser
from core.models import VulnHypothesis, PoCResult

FOUNDRY_POC_PROMPT_TMPL = """You are generating a Foundry regression test for a smart contract audit finding.
Vulnerability hypothesis: {vuln_type} (missing check: {property_missing})

Contract code:
```solidity
{code}
```

Requirements:
- Output a complete Solidity test contract compatible with forge-std/Test.
- The test MUST assert that an unauthorized caller is REVERTED when performing the action.
- If the vulnerability is real, the test will fail with the revert missing.
- Output only the Solidity source."""


def find_forge() -> str | None:
    return shutil.which("forge")


class FoundryRunner:
    """在 Foundry 项目中生成并执行 Solidity PoC（编译报错 3 轮自愈）。"""

    def __init__(self, poc_generator: Callable[[VulnHypothesis], str],
                 self_heal: Callable[[str, str], str] | None = None,
                 fork_url: str = "", max_retries: int = 3):
        self.poc_generator = poc_generator
        self.self_heal = self_heal
        self.fork_url = fork_url
        self.max_retries = max_retries

    def verify_finding(self, h: VulnHypothesis, project_dir: str | Path) -> PoCResult:
        forge = find_forge()
        result = PoCResult(hypothesis=h)
        if forge is None:
            result.output_digest = "SKIP: 未安装 Foundry（forge），无法执行 Web3 动态验证"
            return result

        project = Path(project_dir)
        test_file = project / "test" / "poc_generated.t.sol"
        test_file.parent.mkdir(exist_ok=True)

        code = self.poc_generator(h)
        for attempt in range(1, self.max_retries + 1):
            test_file.write_text(code, encoding="utf-8")
            cmd = [forge, "test", "--match-path", str(test_file), "-vvv"]
            if self.fork_url:
                cmd += ["--fork-url", self.fork_url]
            p = subprocess.run(cmd, cwd=project, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=600)
            output = p.stdout + "\n" + p.stderr
            result.self_heal_rounds = attempt - 1

            if StateParser.is_compilation_error(output) and self.self_heal:
                code = self.self_heal(code, StateParser.digest(output))
                continue
            result.verified = StateParser.is_assertion_failure(output)
            result.output_digest = StateParser.digest(output)
            result.poc_script_path = str(test_file)
            return result

        result.output_digest = f"自愈 {self.max_retries} 轮后编译仍失败"
        result.poc_script_path = str(test_file)
        return result
