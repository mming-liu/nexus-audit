# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-10 09:00:19
- 总条数：31 ｜ 板块 A：**13** ｜ 板块 B：**18**
- 状态计数：ZERO_RECORD_FRESH 13 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 18

<!-- live_hunt_counts: {"BOARD_A": 13, "BOARD_B": 18, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 18, "ZERO_RECORD_FRESH": 13} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 9 个缓存。

- 候选仓：9 ｜ 实扫：8 ｜ 跳过：1 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：31 ｜ 板块 A：13 ｜ 拦截进 B：18
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| agents-flex/agents-flex | 8bb2c6ec7a0d | SKIPPED | 0 |
| nageoffer/ragent | 2a84543cd33c | SCANNED | 2 |
| OtterMind/Nubase | 4b1fb453c3a5 | SCANNED | 4 |
| qifan777/dive-into-spring-ai | 2323b2edc356 | SCANNED | 5 |
| JackWang666666/my-rag | 5b8227e652b9 | SCANNED | 2 |
| qiantongtech/qKnow | 013b966dba4d | SCANNED | 4 |
| pengmoubuaixuexi/TAgent | fa367dfdfd0c | SCANNED | 4 |
| OWWZO/cute-agent | e4a51869736f | SCANNED | 10 |
| java-up-up/nexus-agent | 6359b737771d | SCANNED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Nubase | ssrf | AssetsPublicController.serve | — | 2026-11-07 (2.9d) | 4b1fb453c3a5 | [src/main/java/ai/nubase/assets/controller/AssetsPublicController.java:46](https://github.com/OtterMind/Nubase/blob/4b1fb453c3a5a25f31f6e951a41bb6102b2d6d77/src/main/java/ai/nubase/assets/controller/AssetsPublicController.java#L46) | [Advisory](https://github.com/OtterMind/Nubase/security/advisories/new) · [Issue](https://github.com/OtterMind/Nubase/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/Nubase_ssrf_serve/SUBMISSION_PLAYBOOK.md) |
| 2 | TAgent | pathtraver | SiteStatsController.stats | — | 2026-10-30 (10.8d) | fa367dfdfd0c | [ai-agent-station-study-trigger/src/main/java/cn/bugstack/ai/trigger/http/SiteStatsController.java:42](https://github.com/pengmoubuaixuexi/TAgent/blob/fa367dfdfd0c8fe6c743b360368d623c674ce9f8/ai-agent-station-study-trigger/src/main/java/cn/bugstack/ai/trigger/http/SiteStatsController.java#L42) | [Advisory](https://github.com/pengmoubuaixuexi/TAgent/security/advisories/new) · [Issue](https://github.com/pengmoubuaixuexi/TAgent/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/TAgent_pathtraver_stats/SUBMISSION_PLAYBOOK.md) |
| 3 | TAgent | sqli | BackgroundTaskController.list | — | 2026-10-30 (10.8d) | fa367dfdfd0c | [ai-agent-station-study-trigger/src/main/java/cn/bugstack/ai/trigger/http/BackgroundTaskController.java:54](https://github.com/pengmoubuaixuexi/TAgent/blob/fa367dfdfd0c8fe6c743b360368d623c674ce9f8/ai-agent-station-study-trigger/src/main/java/cn/bugstack/ai/trigger/http/BackgroundTaskController.java#L54) | [Advisory](https://github.com/pengmoubuaixuexi/TAgent/security/advisories/new) · [Issue](https://github.com/pengmoubuaixuexi/TAgent/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/TAgent_sqli_list/SUBMISSION_PLAYBOOK.md) |
| 4 | dive-into-spring-ai | pathtraver | ChunkController.createNodes | — | 2026-11-05 (4.7d) | 2323b2edc356 | [src/main/java/io/github/qifan777/knowledge/graph/chunk/ChunkController.java:31](https://github.com/qifan777/dive-into-spring-ai/blob/2323b2edc356e4f40c5a87eb6cba7e1d90f3142c/src/main/java/io/github/qifan777/knowledge/graph/chunk/ChunkController.java#L31) | [Advisory](https://github.com/qifan777/dive-into-spring-ai/security/advisories/new) · [Issue](https://github.com/qifan777/dive-into-spring-ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dive-into-spring-ai_pathtraver_createNodes/SUBMISSION_PLAYBOOK.md) |
| 5 | dive-into-spring-ai | pathtraver | CompanyController.createNodes | — | 2026-11-05 (4.7d) | 2323b2edc356 | [src/main/java/io/github/qifan777/knowledge/graph/company/CompanyController.java:23](https://github.com/qifan777/dive-into-spring-ai/blob/2323b2edc356e4f40c5a87eb6cba7e1d90f3142c/src/main/java/io/github/qifan777/knowledge/graph/company/CompanyController.java#L23) | [Advisory](https://github.com/qifan777/dive-into-spring-ai/security/advisories/new) · [Issue](https://github.com/qifan777/dive-into-spring-ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dive-into-spring-ai_pathtraver_createNodes/SUBMISSION_PLAYBOOK.md) |
| 6 | dive-into-spring-ai | pathtraver | FormController.createNodes | — | 2026-11-05 (4.7d) | 2323b2edc356 | [src/main/java/io/github/qifan777/knowledge/graph/form/FormController.java:23](https://github.com/qifan777/dive-into-spring-ai/blob/2323b2edc356e4f40c5a87eb6cba7e1d90f3142c/src/main/java/io/github/qifan777/knowledge/graph/form/FormController.java#L23) | [Advisory](https://github.com/qifan777/dive-into-spring-ai/security/advisories/new) · [Issue](https://github.com/qifan777/dive-into-spring-ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dive-into-spring-ai_pathtraver_createNodes/SUBMISSION_PLAYBOOK.md) |
| 7 | my-rag | pathtraver | DocumentController.upload | — | 2026-11-05 (5.4d) | 5b8227e652b9 | [spring-ai-rag/src/main/java/com/rag/controller/DocumentController.java:67](https://github.com/JackWang666666/my-rag/blob/5b8227e652b998e1bc3cd65e1fd928e69f4c0458/spring-ai-rag/src/main/java/com/rag/controller/DocumentController.java#L67) | [Advisory](https://github.com/JackWang666666/my-rag/security/advisories/new) · [Issue](https://github.com/JackWang666666/my-rag/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/my-rag_pathtraver_upload/SUBMISSION_PLAYBOOK.md) |
| 8 | my-rag | unrestricted_upload | DocumentController.upload | — | 2026-11-05 (5.4d) | 5b8227e652b9 | [spring-ai-rag/src/main/java/com/rag/controller/DocumentController.java:67](https://github.com/JackWang666666/my-rag/blob/5b8227e652b998e1bc3cd65e1fd928e69f4c0458/spring-ai-rag/src/main/java/com/rag/controller/DocumentController.java#L67) | [Advisory](https://github.com/JackWang666666/my-rag/security/advisories/new) · [Issue](https://github.com/JackWang666666/my-rag/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/my-rag_unrestricted_upload_upload/SUBMISSION_PLAYBOOK.md) |
| 9 | qKnow | pathtraver | KgSyncController.fileList | — | 2026-11-03 (6.7d) | 013b966dba4d | [qknow-module-kg/qknow-module-kg-biz/src/main/java/tech/qiantong/qknow/module/kg/controller/admin/sync/KgSyncController.java:51](https://github.com/qiantongtech/qKnow/blob/013b966dba4dfba994c02a08d97881f5398131d7/qknow-module-kg/qknow-module-kg-biz/src/main/java/tech/qiantong/qknow/module/kg/controller/admin/sync/KgSyncController.java#L51) | [Advisory](https://github.com/qiantongtech/qKnow/security/advisories/new) · [Issue](https://github.com/qiantongtech/qKnow/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/qKnow_pathtraver_fileList/SUBMISSION_PLAYBOOK.md) |
| 10 | qKnow | pathtraver | KmcSyncController.fileList | — | 2026-11-03 (6.7d) | 013b966dba4d | [qknow-module-kmc/qknow-module-kmc-biz/src/main/java/tech/qiantong/qknow/module/kmc/controller/admin/sync/KmcSyncController.java:148](https://github.com/qiantongtech/qKnow/blob/013b966dba4dfba994c02a08d97881f5398131d7/qknow-module-kmc/qknow-module-kmc-biz/src/main/java/tech/qiantong/qknow/module/kmc/controller/admin/sync/KmcSyncController.java#L148) | [Advisory](https://github.com/qiantongtech/qKnow/security/advisories/new) · [Issue](https://github.com/qiantongtech/qKnow/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/qKnow_pathtraver_fileList/SUBMISSION_PLAYBOOK.md) |
| 11 | qKnow | ssrf | SysLoginController.login | — | 2026-11-03 (6.7d) | 013b966dba4d | [qknow-module-system/qknow-module-system-biz/src/main/java/tech/qiantong/qknow/module/system/controller/admin/system/SysLoginController.java:69](https://github.com/qiantongtech/qKnow/blob/013b966dba4dfba994c02a08d97881f5398131d7/qknow-module-system/qknow-module-system-biz/src/main/java/tech/qiantong/qknow/module/system/controller/admin/system/SysLoginController.java#L69) | [Advisory](https://github.com/qiantongtech/qKnow/security/advisories/new) · [Issue](https://github.com/qiantongtech/qKnow/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/qKnow_ssrf_login/SUBMISSION_PLAYBOOK.md) |
| 12 | qKnow | xss | CommonController.uploadFile | — | 2026-11-03 (6.7d) | 013b966dba4d | [qknow-module-system/qknow-module-system-biz/src/main/java/tech/qiantong/qknow/module/system/controller/admin/common/CommonController.java:93](https://github.com/qiantongtech/qKnow/blob/013b966dba4dfba994c02a08d97881f5398131d7/qknow-module-system/qknow-module-system-biz/src/main/java/tech/qiantong/qknow/module/system/controller/admin/common/CommonController.java#L93) | [Advisory](https://github.com/qiantongtech/qKnow/security/advisories/new) · [Issue](https://github.com/qiantongtech/qKnow/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/qKnow_xss_uploadFile/SUBMISSION_PLAYBOOK.md) |
| 13 | ragent | ssrf | KnowledgeDocumentController.file | — | 2026-11-08 (1.4d) | 2a84543cd33c | [rag/src/main/java/com/nageoffer/ai/ragent/knowledge/controller/KnowledgeDocumentController.java:187](https://github.com/nageoffer/ragent/blob/2a84543cd33c48b4c39bc8293c9b6c504c66c8cb/rag/src/main/java/com/nageoffer/ai/ragent/knowledge/controller/KnowledgeDocumentController.java#L187) | [Advisory](https://github.com/nageoffer/ragent/security/advisories/new) · [Issue](https://github.com/nageoffer/ragent/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/ragent_ssrf_file/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | Nubase | authz | AppWorkerPlatformController.deleteAppWorker | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | Nubase | authz | AppWorkerPlatformController.deployAppWorker | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | Nubase | authz | AppWorkerPlatformController.getAppWorker | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | TAgent | authz | output | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | TAgent | authz | status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | cute-agent | authz | AiAgentController.queryAgentStreamIncr | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | cute-agent | authz | AiClientApiAdminController.createAiClientApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | cute-agent | authz | InternalBrowserRpcController.rpc | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 9 | cute-agent | authz | download_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | cute-agent | authz | download_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | cute-agent | authz | preview_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | cute-agent | cmdi | InternalBrowserRpcController.rpc | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 13 | cute-agent | log_injection | download_file | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 14 | cute-agent | log_injection | post_web_fetch | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 15 | cute-agent | log_injection | upload_document | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 16 | dive-into-spring-ai | authz | AiSessionController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | dive-into-spring-ai | authz | OSSController.upload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | ragent | authz | AuthController.login | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 13 |
| B（其余状态） | 18 |
| 合计 | 31 |
