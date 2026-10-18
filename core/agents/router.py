"""统一异步模型客户端 + 两级模型漏斗路由（第2周实现）。

漏斗设计（对齐计划书第三层接口）：
  - Tier-1（Qwen3-Coder / 本地 vLLM，高吞吐低成本）：执行 GPTScan 两步客观问答，
    过滤 85%+ 的安全函数
  - Tier-2（DeepSeek-R1 等推理模型）：仅对 Tier-1 高风险候选（10%~15%）深度复核，
    扫描总成本降低 85%+

兼容 OpenAI / DeepSeek / vLLM 的 OpenAI 兼容 API（/chat/completions）。
不依赖 openai SDK，直接用 httpx；LLM 客户端可注入（mock 测试用）。
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Protocol

try:
    import httpx
except ImportError:  # 允许在无 httpx 环境下仅做 mock 测试
    httpx = None


class LLMClient(Protocol):
    """最小客户端协议：chat(messages) -> str"""

    async def chat(self, messages: list[dict[str, str]], temperature: float = 0.0) -> str: ...


class OpenAICompatClient:
    """OpenAI 兼容 API 异步客户端。"""

    def __init__(self, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None, timeout: float = 120.0,
                 extra_headers: dict[str, str] | None = None):
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "http://localhost:8000/v1")).rstrip("/")
        self.model = model or os.getenv("LLM_MODEL", "qwen3-coder")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "EMPTY")
        self.timeout = timeout
        # OpenCode Go 平面要求：稳定会话头 + 真实 User-Agent（官方使用规范）
        self.extra_headers = extra_headers or {
            "x-opencode-session": os.getenv("LLM_SESSION_ID", "nexus-audit-fixed-session"),
            "User-Agent": os.getenv("LLM_USER_AGENT", "nexus-audit/1.0"),
        } if os.getenv("LLM_BASE_URL", "").endswith("/go/v1") or "opencode" in os.getenv("LLM_BASE_URL", "") else (extra_headers or {})

    async def chat(self, messages: list[dict[str, str]], temperature: float = 0.0) -> str:
        if httpx is None:
            raise RuntimeError("httpx 未安装：pip install httpx")
        headers = {"Authorization": f"Bearer {self.api_key}", **self.extra_headers}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={"model": self.model, "messages": messages,
                      "temperature": temperature, "max_tokens": 4096},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


def extract_json(text: str) -> Any:
    """从模型输出中稳健提取 JSON（容忍 markdown 代码块与前后噪声）。"""
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1).strip()
    # 找第一个平衡的 {...} 或 [...]
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise ValueError(f"无法从模型输出提取 JSON：{text[:200]!r}")


class TwoTierRouter:
    """两级模型漏斗路由器。

    用法：
        router = TwoTierRouter(tier1=OpenAICompatClient(...), tier2=OpenAICompatClient(...))
        # tier1/tier2 均可传任意实现了 LLMClient 协议的对象（含 mock）
    """

    def __init__(self, tier1: LLMClient | None = None, tier2: LLMClient | None = None):
        self.tier1 = tier1 or OpenAICompatClient()  # 初筛：本地 Qwen3-Coder
        self.tier2 = tier2                          # 复核：DeepSeek-R1（懒加载）

    def _deepseek(self) -> LLMClient:
        if self.tier2 is None:
            self.tier2 = OpenAICompatClient(
                base_url=os.getenv("LLM_TIER2_BASE_URL", "https://api.deepseek.com/v1"),
                model=os.getenv("LLM_TIER2_MODEL", "deepseek-reasoner"),
                api_key=os.getenv("LLM_TIER2_API_KEY", ""),
            )
        return self.tier2

    async def screen(self, messages: list[dict[str, str]]) -> str:
        """Tier-1 初筛调用。"""
        return await self.tier1.chat(messages)

    async def deep_review(self, messages: list[dict[str, str]]) -> str:
        """Tier-2 深度复核调用（Skeptic / PoC 生成等）。"""
        return await self._deepseek().chat(messages, temperature=0.2)
