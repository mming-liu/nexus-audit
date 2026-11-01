# STAGE REPORT · v1.3.12（M317：查重省流）

> 日期：2026-11-01 ｜ 基线：v1.3.11（94e6a04）
> 结论：未配 `GITHUB_TOKEN` 时，一轮 10 仓巡猎的查重 API 消耗从
> "每单元 3 页 advisory + 每单元一次全网 Issue 搜索"降到 **1–2 次 advisory + 少量高辨识度搜索**。

## 一、三项改动

| 项 | 旧 | 新 |
| --- | --- | --- |
| 全局 advisory | 每个单元翻 3 页（同仓 5 单元 = 15 次重复请求） | `load_global_advisories()` 整轮共用，24h 落盘缓存；无 Token 1 页、有 Token 2 页 |
| 短路 | 先发全网查询再判状态 | local/NVD/CIRCL/仓内 Issue/仓内 Advisory 命中即返回；未命中才发全网 |
| 泛化词 | 所有单元都发 `"类名" "方法名"` 搜索 | 泛化方法名（apply/test/index/list/get/...）或长度 < 6、或通用控制器类名 → 跳过（coverage 标 skipped） |

顺带修了一个 memo 连坐 bug：全局 advisory 的 memo 之前只按 slug 缓存，
同仓不同方法会拿到上一个方法的结果；现在 key 带 `unit + file`。

## 二、消耗对比（无 Token）

| 场景 | 旧 | 新 |
| --- | --- | --- |
| 10 仓 × 平均 2–5 个单元 | advisory 60–150 次 + Issue 搜索 20–50 次 | advisory 1–2 次 + Issue 搜索仅高辨识度组合（通常 < 10 次） |

## 三、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,812 项**（新增 [301] 6 项） |
| cli.py doctor | PASS（12 段全绿） |

## 四、冒烟 [301] 覆盖

- 两个仓库查询只发 1 次 `/advisories` 请求（缓存复用）；
- local seed 命中后全网搜索调用数为 0（短路）；
- `IndexController.list` 泛化组合 → coverage `skipped` 且零调用；
- `CrmFlowController.deleteFlowStep` 高辨识度组合照常触发。
