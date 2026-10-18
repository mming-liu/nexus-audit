"""Foundry 测试合约生成与执行运行器。

流程（Buttercup / OSS-Fuzz-Gen 蓝本）：
  1. Generation：根据漏洞假设生成 Solidity 测试合约
  2. Execution：在本地 Anvil 分叉链执行 forge test
  3. Parsing & Self-Healing：编译报错经 StateParser 提炼后回传模型自动修正，
     最多重试 3 轮（复刻 OSS-Fuzz-Gen 自愈循环）
TODO(第3周)。
"""
