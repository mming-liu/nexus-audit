# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/live_hunt_huntr2_ls.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-30 23:54:07
- 总条数：22 ｜ 板块 A：**0** ｜ 板块 B：**22**
- 状态计数：ZERO_RECORD_FRESH 0 / DUPLICATE_CVE 4 / DUPLICATE_ISSUE_OR_GHSA 18 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 0

<!-- live_hunt_counts: {"BOARD_A": 0, "BOARD_B": 22, "DUPLICATE_CVE": 4, "DUPLICATE_ISSUE_OR_GHSA": 18, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 0, "ZERO_RECORD_FRESH": 0} -->

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | label-studio | log_injection | DownloadStorageData.get | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 2 | label-studio | log_injection | ExportAPI.get | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 3 | label-studio | log_injection | OrganizationResetTokenAPI.post | **DUPLICATE_CVE** | CVE-2025-47783、CVE-2025-47783 | local_seed_hit | https://cve.circl.lu/api/search/HumanSignal/label-studio |
| 4 | label-studio | log_injection | UserHotkeysAPI.get | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 5 | label-studio | log_injection | UserHotkeysAPI.patch | **DUPLICATE_CVE** | CVE-2026-85179、CVE-2025-47783、CVE-2026-85179、CVE-2025-47783 | local_seed_hit | https://cve.circl.lu/api/search/HumanSignal/label-studio |
| 6 | label-studio | log_injection | UserResetTokenAPI.post | **DUPLICATE_CVE** | CVE-2025-47783、CVE-2025-47783 | local_seed_hit | https://cve.circl.lu/api/search/HumanSignal/label-studio |
| 7 | label-studio | log_injection | delete_annotation_from_azure_storages | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 8 | label-studio | log_injection | delete_annotation_from_gcs_storages | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 9 | label-studio | log_injection | delete_annotation_from_local_files | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 10 | label-studio | log_injection | delete_annotation_from_s3_storages | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 11 | label-studio | log_injection | delete_draft | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 12 | label-studio | log_injection | delete_export_file_on_commit | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 13 | label-studio | log_injection | export_annotation_to_local_files | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 14 | label-studio | log_injection | export_annotation_to_redis_storages | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 15 | label-studio | log_injection | remove_predictions_from_project | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 16 | label-studio | log_injection | save_predictions_to_project | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 17 | label-studio | log_injection | update_project_summary_annotations_and_is_labeled | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 18 | label-studio | mass_assignment | MLBackendPredictTestAPI.post | **DUPLICATE_CVE** | CVE-2025-47783、CVE-2025-47783 | local_seed_hit | https://cve.circl.lu/api/search/HumanSignal/label-studio |
| 19 | label-studio | sqli | delete_draft | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 20 | label-studio | sqli | feature_flags | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 21 | label-studio | sqli | update_task_counters_after_annotation_delete | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 22 | label-studio | ssrf | heidi_tips | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-j54x-2c45-gcqf、GHSA-qfjr-222q-5g56、GHSA-6437-7wc6-gmx5、GHSA-4qr5-8q67-qrm9、GHSA-pqf8-542r-76hg | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 0 |
| B（其余状态） | 22 |
| 合计 | 22 |
