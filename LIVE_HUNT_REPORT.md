# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/live_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-28 08:03:41
- 总条数：6 ｜ 板块 A：**3** ｜ 板块 B：**3**
- 状态计数：ZERO_RECORD_FRESH 3 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 3 / PATCHED_UPSTREAM 0 / UNKNOWN 0

<!-- live_hunt_counts: {"BOARD_A": 3, "BOARD_B": 3, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 3, "PATCHED_UPSTREAM": 0, "UNKNOWN": 0, "ZERO_RECORD_FRESH": 3} -->

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|
| 1 | newbee-mall-api | unrestricted_upload | NewBeeAdminUploadAPI.upload | 0879d5a1fac0 | [src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java:49](https://github.com/newbee-ltd/newbee-mall-api/blob/0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4/src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java#L49) | [Advisory](https://github.com/newbee-ltd/newbee-mall-api/security/advisories/new) · [Issue](https://github.com/newbee-ltd/newbee-mall-api/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/live_hunt_packs/newbee-mall-api_unrestricted_upload_upload/SUBMISSION_PLAYBOOK.md) |
| 2 | newbee-mall-api | weakrand | NewBeeAdminUploadAPI.upload | 0879d5a1fac0 | [src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java:49](https://github.com/newbee-ltd/newbee-mall-api/blob/0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4/src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java#L49) | [Advisory](https://github.com/newbee-ltd/newbee-mall-api/security/advisories/new) · [Issue](https://github.com/newbee-ltd/newbee-mall-api/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/live_hunt_packs/newbee-mall-api_weakrand_upload/SUBMISSION_PLAYBOOK.md) |
| 3 | newbee-mall-api | xss | NewBeeAdminUploadAPI.upload | 0879d5a1fac0 | [src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java:49](https://github.com/newbee-ltd/newbee-mall-api/blob/0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4/src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java#L49) | [Advisory](https://github.com/newbee-ltd/newbee-mall-api/security/advisories/new) · [Issue](https://github.com/newbee-ltd/newbee-mall-api/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/live_hunt_packs/newbee-mall-api_xss_upload/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | newbee-mall | hash | AdminController.passwordUpdate | **DUPLICATE_ISSUE_OR_GHSA** | Issue #100 | local_seed_hit | https://github.com/newbee-ltd/newbee-mall/issues/100 |
| 2 | newbee-mall | unrestricted_upload | UploadController.upload | **DUPLICATE_ISSUE_OR_GHSA** | Issue #100 | local_seed_hit | https://github.com/newbee-ltd/newbee-mall/issues/100 |
| 3 | newbee-mall | weakrand | UploadController.upload | **DUPLICATE_ISSUE_OR_GHSA** | Issue #100 | local_seed_hit | https://github.com/newbee-ltd/newbee-mall/issues/100 |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 3 |
| B（其余状态） | 3 |
| 合计 | 6 |
