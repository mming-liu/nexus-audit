# STAGE REPORT · v1.3.2（M297 → M298）

> 日期：2026-10-30 ｜ 基线：v1.3.1（17f6820）
> 结论：**冒烟 PASS（1676 项断言）**；两处判据/选靶修正，未改任何 True/False 结论方向。

## 一、修了什么

| 编号 | 问题（2026-10-30 09:00 实盘暴露） | 修复 |
| --- | --- | --- |
| M297 | `unchecked_low_level_calls`（Solidity 专有类目）落到 SpiderPanel 的 `main.py` 上：切片里出现 `contract` 一词即被 `_looks_solidity()` 判成 Solidity | ① 引擎层：`_looks_solidity()` 先排除“有 `def` 且无 `pragma solidity`”的切片；② 报告层：`wild_noise` 新增 `RULE_LANGUAGE_MISMATCH`（reentrancy / unchecked_low_level_calls / tx_origin / delegatecall_untrusted 出现在非 `.sol` 文件 → 板块 B） |
| M298 | Python 限定词 `panel` 只捞到桌面/UI panel（holoviz-panel、nwg-panel、SpiderPanel、Amnezia-Web-Panel），10 个实扫里 6 个无关、一半扫出 0 | Python 词表换成 `fastapi/django/flask/admin/backend/cms/saas/erp` |

## 二、验证

| 项目 | 结果 |
| --- | --- |
| `python benchmarks/smoke_test_chains.py` | PASS ✔ 1676 项（新增 [285]–[286]） |
| 真实切片回归 | 用 SpiderPanel 实码（main.py:6390 起 50 行）跑 `verdict("unchecked_low_level_calls", …)` → `None`（修复前会产出根因） |
| Solidity 侧不回归 | 冒烟 [285] 内置 Solidity 片段仍判 `True`；smartbugs / DeFiVulnLabs / solmate 等靶场段全绿 |

## 三、影响面

- 引擎改动只影响“看起来像 Python 的切片”，Solidity 靶场（`.sol`）没有 `def`，判定路径不变。
- `RULE_LANGUAGE_MISMATCH` 只作用于 daily-hunt 报告层，不改变 `scan` 的原始输出。
