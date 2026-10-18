"""统一异步模型客户端：兼容 OpenAI / DeepSeek / 本地 vLLM。

实现两级模型漏斗路由：
  - Tier-1（Qwen3-Coder，本地高吞吐）：GPTScan 两步客观问答初筛，过滤 85%+ 安全函数
  - Tier-2（DeepSeek-R1）：仅对 Tier-1 高风险候选（10%~15%）深度复核，成本降 85%+
TODO(第2周)：实现双模型路由与重试逻辑。
"""
