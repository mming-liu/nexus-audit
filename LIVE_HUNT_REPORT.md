# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-29 23:34:40
- 总条数：19 ｜ 板块 A：**11** ｜ 板块 B：**8**
- 状态计数：ZERO_RECORD_FRESH 11 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 8

<!-- live_hunt_counts: {"BOARD_A": 11, "BOARD_B": 8, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 8, "ZERO_RECORD_FRESH": 11} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 11 个缓存。

- 候选仓：12 ｜ 实扫：10 ｜ 跳过：0 ｜ 失败：2 ｜ 候选来源：github_search
- 本次新增根因：19 ｜ 板块 A：11 ｜ 拦截进 B：8

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| EpicStaff/EpicStaff | bca99d8522c9 | SCANNED | 0 |
| nysenate/OpenLegislation | ae0d0e85d75f | SCANNED | 5 |
| lablup/backend.ai | feebd783548a | SCANNED | 0 |
| metasfresh/metasfresh | a962d7769803 | SCANNED | 5 |
| dimagi/commcare-hq |  | FAILED | 0 |
| moj-analytical-services/splink | 5b719296d62b | SCANNED | 0 |
| getrebuild/rebuild | 4d64ea904bdb | SCANNED | 4 |
| aegra/aegra | 9012768f6e13 | SCANNED | 0 |
| 1Panel-dev/CordysCRM | 16ce39f7e90f | SCANNED | 0 |
| fastapi-practices/fastapi-best-architecture | 6edcadc7919c | SCANNED | 5 |
| mealie-recipes/mealie |  | FAILED | 0 |
| insistence/RuoYi-FastAPI | 7f7c66d373b6 | SCANNED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | OpenLegislation | xss | AdminAccountCtrl.changePassword | — | 2026-10-29 (0.0d) | ae0d0e85d75f | [src/main/java/gov/nysenate/openleg/api/admin/AdminAccountCtrl.java:167](https://github.com/nysenate/OpenLegislation/blob/ae0d0e85d75f84edeef9f4e319c07241ffc91771/src/main/java/gov/nysenate/openleg/api/admin/AdminAccountCtrl.java#L167) | [Advisory](https://github.com/nysenate/OpenLegislation/security/advisories/new) · [Issue](https://github.com/nysenate/OpenLegislation/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/OpenLegislation_xss_changePassword/SUBMISSION_PLAYBOOK.md) |
| 2 | OpenLegislation | xss | AdminAccountCtrl.createNewUser | — | 2026-10-29 (0.0d) | ae0d0e85d75f | [src/main/java/gov/nysenate/openleg/api/admin/AdminAccountCtrl.java:107](https://github.com/nysenate/OpenLegislation/blob/ae0d0e85d75f84edeef9f4e319c07241ffc91771/src/main/java/gov/nysenate/openleg/api/admin/AdminAccountCtrl.java#L107) | [Advisory](https://github.com/nysenate/OpenLegislation/security/advisories/new) · [Issue](https://github.com/nysenate/OpenLegislation/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/OpenLegislation_xss_createNewUser/SUBMISSION_PLAYBOOK.md) |
| 3 | fastapi-best-architecture | sqli | delete_all_login_logs | — | 2026-10-29 (0.3d) | 6edcadc7919c | [backend/app/admin/api/v1/log/login_log.py:57](https://github.com/fastapi-practices/fastapi-best-architecture/blob/6edcadc7919cd4e285079d506a23f665b64a344c/backend/app/admin/api/v1/log/login_log.py#L57) | [Advisory](https://github.com/fastapi-practices/fastapi-best-architecture/security/advisories/new) · [Issue](https://github.com/fastapi-practices/fastapi-best-architecture/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/fastapi-best-architecture_sqli_delete_all_login_logs/SUBMISSION_PLAYBOOK.md) |
| 4 | fastapi-best-architecture | sqli | delete_all_opera_logs | — | 2026-10-29 (0.3d) | 6edcadc7919c | [backend/app/admin/api/v1/log/opera_log.py:57](https://github.com/fastapi-practices/fastapi-best-architecture/blob/6edcadc7919cd4e285079d506a23f665b64a344c/backend/app/admin/api/v1/log/opera_log.py#L57) | [Advisory](https://github.com/fastapi-practices/fastapi-best-architecture/security/advisories/new) · [Issue](https://github.com/fastapi-practices/fastapi-best-architecture/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/fastapi-best-architecture_sqli_delete_all_opera_logs/SUBMISSION_PLAYBOOK.md) |
| 5 | fastapi-best-architecture | sqli | get_sessions | — | 2026-10-29 (0.3d) | 6edcadc7919c | [backend/app/admin/api/v1/monitor/online.py:22](https://github.com/fastapi-practices/fastapi-best-architecture/blob/6edcadc7919cd4e285079d506a23f665b64a344c/backend/app/admin/api/v1/monitor/online.py#L22) | [Advisory](https://github.com/fastapi-practices/fastapi-best-architecture/security/advisories/new) · [Issue](https://github.com/fastapi-practices/fastapi-best-architecture/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/fastapi-best-architecture_sqli_get_sessions/SUBMISSION_PLAYBOOK.md) |
| 6 | fastapi-best-architecture | sqli | import_table | — | 2026-10-29 (0.3d) | 6edcadc7919c | [backend/plugin/code_generator/api/v1/code_gen.py:35](https://github.com/fastapi-practices/fastapi-best-architecture/blob/6edcadc7919cd4e285079d506a23f665b64a344c/backend/plugin/code_generator/api/v1/code_gen.py#L35) | [Advisory](https://github.com/fastapi-practices/fastapi-best-architecture/security/advisories/new) · [Issue](https://github.com/fastapi-practices/fastapi-best-architecture/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/fastapi-best-architecture_sqli_import_table/SUBMISSION_PLAYBOOK.md) |
| 7 | metasfresh | sqli | DebugRestController.stressTest_massCacheInvalidation | — | 2026-10-29 (0.1d) | a962d7769803 | [backend/de.metas.ui.web.base/src/main/java/de/metas/ui/web/debug/DebugRestController.java:454](https://github.com/metasfresh/metasfresh/blob/a962d77698039c378ec457ac76fe7e64defffeac/backend/de.metas.ui.web.base/src/main/java/de/metas/ui/web/debug/DebugRestController.java#L454) | [Advisory](https://github.com/metasfresh/metasfresh/security/advisories/new) · [Issue](https://github.com/metasfresh/metasfresh/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/metasfresh_sqli_stressTest_massCacheInvalidation/SUBMISSION_PLAYBOOK.md) |
| 8 | rebuild | pathtraver | CommonPageView.txtSuffix | — | 2026-10-25 (4.2d) | 4d64ea904bdb | [src/main/java/com/rebuild/web/commons/CommonPageView.java:49](https://github.com/getrebuild/rebuild/blob/4d64ea904bdbcf0cf282cf007caf17293718981f/src/main/java/com/rebuild/web/commons/CommonPageView.java#L49) | [Advisory](https://github.com/getrebuild/rebuild/security/advisories/new) · [Issue](https://github.com/getrebuild/rebuild/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/rebuild_pathtraver_txtSuffix/SUBMISSION_PLAYBOOK.md) |
| 9 | rebuild | redir | BarCodeGeneratorController.generateAndRender | — | 2026-10-25 (4.2d) | 4d64ea904bdb | [src/main/java/com/rebuild/web/commons/BarCodeGeneratorController.java:43](https://github.com/getrebuild/rebuild/blob/4d64ea904bdbcf0cf282cf007caf17293718981f/src/main/java/com/rebuild/web/commons/BarCodeGeneratorController.java#L43) | [Advisory](https://github.com/getrebuild/rebuild/security/advisories/new) · [Issue](https://github.com/getrebuild/rebuild/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/rebuild_redir_generateAndRender/SUBMISSION_PLAYBOOK.md) |
| 10 | rebuild | redir | ErrorPageView.requestSupport | — | 2026-10-25 (4.2d) | 4d64ea904bdb | [src/main/java/com/rebuild/web/commons/ErrorPageView.java:139](https://github.com/getrebuild/rebuild/blob/4d64ea904bdbcf0cf282cf007caf17293718981f/src/main/java/com/rebuild/web/commons/ErrorPageView.java#L139) | [Advisory](https://github.com/getrebuild/rebuild/security/advisories/new) · [Issue](https://github.com/getrebuild/rebuild/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/rebuild_redir_requestSupport/SUBMISSION_PLAYBOOK.md) |
| 11 | rebuild | redir | FileDownloader.viewImg | — | 2026-10-25 (4.2d) | 4d64ea904bdb | [src/main/java/com/rebuild/web/commons/FileDownloader.java:56](https://github.com/getrebuild/rebuild/blob/4d64ea904bdbcf0cf282cf007caf17293718981f/src/main/java/com/rebuild/web/commons/FileDownloader.java#L56) | [Advisory](https://github.com/getrebuild/rebuild/security/advisories/new) · [Issue](https://github.com/getrebuild/rebuild/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/rebuild_redir_viewImg/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | OpenLegislation | authz | ApiUserEmailSubscriptionCtrl.currentSubscriptions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | OpenLegislation | authz | ApiUserEmailSubscriptionCtrl.updateEmail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | OpenLegislation | authz | ApiUserEmailSubscriptionCtrl.updateSubscriptions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | fastapi-best-architecture | authz | delete_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | metasfresh | authz | DebugRestController.changeJsonEngineConfiguration | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | metasfresh | authz | SessionRestController.resetUserPasswordConfirm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | metasfresh | authz | SessionRestController.resetUserPasswordRequest | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | metasfresh | authz | UserSyncRestEndpoint.forwardEventToRabbitMQ | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 11 |
| B（其余状态） | 8 |
| 合计 | 19 |
