# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-30 20:39:14
- 总条数：2 ｜ 板块 A：**1** ｜ 板块 B：**1**
- 状态计数：ZERO_RECORD_FRESH 1 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 1

<!-- live_hunt_counts: {"BOARD_A": 1, "BOARD_B": 1, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 1, "ZERO_RECORD_FRESH": 1} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 13 个缓存。

- 候选仓：13 ｜ 实扫：7 ｜ 跳过：6 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：2 ｜ 板块 A：1 ｜ 拦截进 B：1

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| OCA/account-financial-tools | 2cb90fc8fd99 | SCANNED | 0 |
| earthians/marley | 6e81d8f02d29 | SCANNED | 0 |
| OCA/stock-logistics-warehouse | 88805a59a4b0 | SKIPPED | 0 |
| frappe/frappe_docker | 61d35da827eb | SKIPPED | 0 |
| OCA/server-tools | 9c5abeed7828 | SKIPPED | 0 |
| OCA/l10n-spain | 4b2243ecd082 | SCANNED | 1 |
| OCA/reporting-engine | 3aecc71449fb | SCANNED | 0 |
| YunaiV/yudao-cloud | d5e455d98af8 | SKIPPED | 0 |
| SourByte05/Vulnerability-Wiki-PoC | 240643cbeb4c | SKIPPED | 0 |
| ivnvxd/mcp-server-odoo | 64b52df7ae3b | SCANNED | 0 |
| KoalixSwitzerland/koalixcrm | 883e6e51b042 | SCANNED | 1 |
| OCA/account-financial-reporting | f48b4ea777c4 | SKIPPED | 0 |
| OCA/rest-framework | ad1489d08be5 | SCANNED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | koalixcrm | log_injection | trigger_pdf_export | — | 2026-10-25 (5.2d) | 883e6e51b042 | [koalixcrm/core/signals/pdf_export_signals.py:16](https://github.com/KoalixSwitzerland/koalixcrm/blob/883e6e51b042a19c6bcf8e9448c467c821604b21/koalixcrm/core/signals/pdf_export_signals.py#L16) | [Advisory](https://github.com/KoalixSwitzerland/koalixcrm/security/advisories/new) · [Issue](https://github.com/KoalixSwitzerland/koalixcrm/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/koalixcrm_log_injection_trigger_pdf_export/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | l10n-spain | authz | mod347_reject | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 1 |
| B（其余状态） | 1 |
| 合计 | 2 |
