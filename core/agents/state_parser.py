"""PentestGPT 式 Reasoning-Generation-Parsing 三模块状态机。

沙箱/编译器返回数千行报错时，由 Parsing 会话浓缩为 5 行结构化摘要，
再交 Reasoning 会话更新计划，防止上下文窗口爆炸。
TODO(第3周)：实现三会话协同与任务树（PTT）。
"""
