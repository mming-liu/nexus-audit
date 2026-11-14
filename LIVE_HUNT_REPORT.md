# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-14 20:41:17
- 总条数：1 ｜ 板块 A：**0** ｜ 板块 B：**1**
- 状态计数：ZERO_RECORD_FRESH 0 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 1

<!-- live_hunt_counts: {"BOARD_A": 0, "BOARD_B": 1, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 1, "ZERO_RECORD_FRESH": 0} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 4 个缓存。

- 候选仓：6 ｜ 实扫：1 ｜ 跳过：2 ｜ 失败：3 ｜ 候选来源：github_search
- 本次新增根因：1 ｜ 板块 A：0 ｜ 拦截进 B：1
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| avansaber/erpclaw |  | FAILED | 0 |
| DjangoCRM/django-crm | f928e3ba7533 | SCANNED | 1 |
| SourByte05/Vulnerability-Wiki-PoC |  | FAILED | 0 |
| KoalixSwitzerland/koalixcrm | 883e6e51b042 | SKIPPED | 0 |
| yarsa/nepal-compliance |  | FAILED | 0 |
| Impertio-Studio/Frappe_Claude_Skill_Package | 36cfa807518f | SKIPPED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — | — |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | django-crm | authz | contact_form | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 0 |
| B（其余状态） | 1 |
| 合计 | 1 |
