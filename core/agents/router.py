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

import asyncio
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


class ModelCircuitOpen(RuntimeError):
    """连续超时触发熔断：本客户端在冷静期内拒绝再发请求。"""


def _is_timeout(err: Exception) -> bool:
    """区分「超时/挂起」与「其他失败」——只有前者喂熔断计数器。

    免费模型挂起时 httpx 抛 ReadTimeout（也可能是包成 RuntimeError 的
    transport 层超时），连接被拒/401 之类不算挂起，不该触发熔断。
    """
    if isinstance(err, httpx.TimeoutException) if httpx else False:
        return True
    return "timed out" in str(err).lower() or "timeout" in str(err).lower()


class OpenAICompatClient:
    """OpenAI 兼容 API 异步客户端（带 429/5xx 指数退避重试 + 超时熔断）。

    超时与重试预算（Module 9）：单次请求硬超时默认 45s、最多重试 1 次 ——
    此前 timeout=180 × 重试 6 次，一条挂起样本能把流水线拖 26 分钟。
    连续 3 次「整个 chat 都因超时失败」触发熔断：后续调用立刻抛
    ModelCircuitOpen，由调用方把样本标为 call_failed 剔除 —— 绝不无限
    挂起阻塞流水线。任何一次成功都会清零计数（熔断只针对持续挂起）。
    """

    # 可重试状态码：限流与上游瞬断，重试有意义
    RETRYABLE = {408, 429, 500, 502, 503, 504}

    def __init__(self, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None, timeout: float = 45.0,
                 extra_headers: dict[str, str] | None = None,
                 max_retries: int = 1, backoff_base: float = 2.0,
                 breaker_threshold: int = 3):
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "http://localhost:8000/v1")).rstrip("/")
        self.model = model or os.getenv("LLM_MODEL", "qwen3-coder")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "EMPTY")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.breaker_threshold = breaker_threshold
        self._consec_timeouts = 0
        # OpenCode Go 平面要求：稳定会话头 + 真实 User-Agent（官方使用规范）
        self.extra_headers = extra_headers or {
            "x-opencode-session": os.getenv("LLM_SESSION_ID", "nexus-audit-fixed-session"),
            "User-Agent": os.getenv("LLM_USER_AGENT", "nexus-audit/1.0"),
        } if os.getenv("LLM_BASE_URL", "").endswith("/go/v1") or "opencode" in os.getenv("LLM_BASE_URL", "") else (extra_headers or {})

    async def chat(self, messages: list[dict[str, str]], temperature: float = 0.0) -> str:
        if httpx is None:
            raise RuntimeError("httpx 未安装：pip install httpx")
        if self._consec_timeouts >= self.breaker_threshold:
            # 熔断快速失败：调用方据此把样本标 call_failed，不再等网络层超时
            raise ModelCircuitOpen(
                f"熔断触发：连续 {self._consec_timeouts} 次调用超时"
                f"（模型 {self.model}），已跳过本次请求")
        headers = {"Authorization": f"Bearer {self.api_key}", **self.extra_headers}
        payload = {"model": self.model, "messages": messages,
                   "temperature": temperature, "max_tokens": 4096}

        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            if attempt:
                # 指数退避 + 抖动，避免并发请求在同一时刻重试形成二次冲击
                await asyncio.sleep(min(30.0, self.backoff_base * (2 ** (attempt - 1)))
                                    * (0.7 + 0.6 * (attempt % 3) / 3))
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(f"{self.base_url}/chat/completions",
                                             headers=headers, json=payload)
            except Exception as e:      # 连接断开 / 超时
                last_err = e
                if _is_timeout(e):
                    self._consec_timeouts += 1
                continue

            if resp.status_code == 200:
                data = resp.json()
                choices = data.get("choices") or []
                if not choices:
                    last_err = RuntimeError(f"响应缺少 choices：{resp.text[:200]}")
                    continue
                content = choices[0].get("message", {}).get("content") or ""
                if not content.strip():
                    last_err = RuntimeError("模型返回空内容")
                    continue
                self._consec_timeouts = 0
                return content

            last_err = RuntimeError(self._diagnose(resp))
            if resp.status_code not in self.RETRYABLE:
                raise last_err      # 401/402 之类重试无意义，直接抛

        raise RuntimeError(f"重试 {self.max_retries} 次后仍失败：{last_err}")

    def _diagnose(self, resp) -> str:
        """调用失败时按需诊断：查询额度把根因（key 失效/额度耗尽/模型问题）带进异常。"""
        body = resp.text[:300]
        if resp.status_code == 401:
            return f"模型调用 401：key 已失效（可能被静默下线）。响应：{body}。请去 opencode.ai Console 换 key 并同步到 ~/.dsh/.credentials.yaml 与项目 .env"
        if resp.status_code in (402, 429):
            try:  # 额度相关：查一次 usage 给出精确余量
                from core.agents.model_selector import check_quota
                quota = check_quota()
                windows = {w: quota[w]["percent"] for w in ("rolling", "weekly", "monthly")}
                return f"模型调用 {resp.status_code}：额度受限，当前用量 {windows}。响应：{body}"
            except Exception as e:
                return f"模型调用 {resp.status_code}，且额度查询也失败（{e}）。响应：{body}"
        return f"模型调用 {resp.status_code}（模型 {self.model}）：{body}"


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
