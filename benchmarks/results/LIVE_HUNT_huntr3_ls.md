# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/live_hunt_huntr3_ls.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-31 00:00:27
- 总条数：22 ｜ 板块 A：**0** ｜ 板块 B：**22**
- 状态计数：ZERO_RECORD_FRESH 0 / DUPLICATE_CVE 4 / DUPLICATE_ISSUE_OR_GHSA 1 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 17

<!-- live_hunt_counts: {"BOARD_A": 0, "BOARD_B": 22, "DUPLICATE_CVE": 4, "DUPLICATE_ISSUE_OR_GHSA": 1, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 17, "ZERO_RECORD_FRESH": 0} -->

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | label-studio | log_injection | DownloadStorageData.get | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 2 | label-studio | log_injection | ExportAPI.get | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 3 | label-studio | log_injection | OrganizationResetTokenAPI.post | **DUPLICATE_CVE** | CVE-2025-47783、CVE-2025-47783 | local_seed_hit | https://cve.circl.lu/api/search/HumanSignal/label-studio |
| 4 | label-studio | log_injection | UserHotkeysAPI.get | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 5 | label-studio | log_injection | UserHotkeysAPI.patch | **DUPLICATE_CVE** | CVE-2026-85179、CVE-2025-47783、CVE-2026-85179、CVE-2025-47783 | local_seed_hit | https://cve.circl.lu/api/search/HumanSignal/label-studio |
| 6 | label-studio | log_injection | UserResetTokenAPI.post | **DUPLICATE_CVE** | CVE-2025-47783、CVE-2025-47783 | local_seed_hit | https://cve.circl.lu/api/search/HumanSignal/label-studio |
| 7 | label-studio | log_injection | delete_annotation_from_azure_storages | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 8 | label-studio | log_injection | delete_annotation_from_gcs_storages | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 9 | label-studio | log_injection | delete_annotation_from_local_files | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 10 | label-studio | log_injection | delete_annotation_from_s3_storages | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 11 | label-studio | log_injection | delete_draft | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 12 | label-studio | log_injection | delete_export_file_on_commit | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 13 | label-studio | log_injection | export_annotation_to_local_files | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 14 | label-studio | log_injection | export_annotation_to_redis_storages | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 15 | label-studio | log_injection | remove_predictions_from_project | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 16 | label-studio | log_injection | save_predictions_to_project | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 17 | label-studio | log_injection | update_project_summary_annotations_and_is_labeled | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 18 | label-studio | mass_assignment | MLBackendPredictTestAPI.post | **DUPLICATE_CVE** | CVE-2025-47783、CVE-2025-47783 | local_seed_hit | https://cve.circl.lu/api/search/HumanSignal/label-studio |
| 19 | label-studio | sqli | delete_draft | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 20 | label-studio | sqli | feature_flags | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-cpmr-mw4j-99r7 | local_seed_hit | https://api.github.com/repos/HumanSignal/label-studio/security-advisories |
| 21 | label-studio | sqli | update_task_counters_after_annotation_delete | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |
| 22 | label-studio | ssrf | heidi_tips | **UNKNOWN** | — | repo_advisories_no_unit_match: 仓库存在安全公告，但均未命中本方法/文件，需人工查重后定性 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 0 |
| B（其余状态） | 22 |
| 合计 | 22 |
