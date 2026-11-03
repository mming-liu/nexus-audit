# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-03 09:00:22
- 总条数：22 ｜ 板块 A：**7** ｜ 板块 B：**15**
- 状态计数：ZERO_RECORD_FRESH 7 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 15

<!-- live_hunt_counts: {"BOARD_A": 7, "BOARD_B": 15, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 15, "ZERO_RECORD_FRESH": 7} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 11 个缓存。

- 候选仓：22 ｜ 实扫：4 ｜ 跳过：18 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：22 ｜ 板块 A：7 ｜ 拦截进 B：15
- 冷却期免克隆：11 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| smallrye/smallrye-reactive-messaging | 189c5c5b62d9 | SKIPPED | 0 |
| DjangoCRM/django-crm | b1e9f2ea25bb | SCANNED | 3 |
| euler-xyz/euler-vault-kit | 93a1de491531 | SKIPPED | 0 |
| gtrxAC/discord-j2me | 7468c90afece | SKIPPED | 0 |
| KoalixSwitzerland/koalixcrm | 883e6e51b042 | SKIPPED | 0 |
| euler-xyz/ethereum-vault-connector | 6dc839ad9f58 | SCANNED | 0 |
| enonic/xp | f62672f6a226 | SKIPPED | 0 |
| Django-CRM/Django-CRM | f63fe8cf22bd | SCANNED | 0 |
| getrebuild/rebuild | 4d64ea904bdb | SKIPPED | 0 |
| SysAdminDoc/HushMessenger | c10013f003b4 | SKIPPED | 0 |
| mesibo/messenger-app-android | 9c2617006ff0 | SKIPPED | 0 |
| zengyunhua/Mestudy | 70c0029488d3 | SCANNED | 19 |
| SquirrelJME/SquirrelJME | e8d1e81e66a8 | SKIPPED | 0 |
| dromara/skyeye | b211328dbee6 | SKIPPED | 0 |
| spring-guides/gs-messaging-rabbitmq | df3d3a41db24 | SKIPPED | 0 |
| dromara/ujcms | d4aa397006c2 | SKIPPED | 0 |
| xnx3/wangmarket | c4cb414e2cc1 | SKIPPED | 0 |
| awslabs/amazon-sqs-java-messaging-lib | 1d9ceafa3aea | SKIPPED | 0 |
| LiuYuYang01/ThriveX-Server | 60b24e559a9a | SKIPPED | 0 |
| sunkaifei/FlyCms | 77c58e637b38 | SKIPPED | 0 |
| ilscipio/scipio-erp | ef67e214fd06 | SKIPPED | 0 |
| 201206030/novel-plus | 4a010cda28e0 | SKIPPED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Mestudy | deserial | DraftsController.getPersonMessage | — | 2026-11-02 (0.7d) | 70c0029488d3 | [NetworkOfficeService/src/main/java/com/tecsun/sisp/net/modules/controller/userNet/DraftsController.java:582](https://github.com/zengyunhua/Mestudy/blob/70c0029488d3db7e2f82b4edcfc1f3e2dea84f18/NetworkOfficeService/src/main/java/com/tecsun/sisp/net/modules/controller/userNet/DraftsController.java#L582) | [Advisory](https://github.com/zengyunhua/Mestudy/security/advisories/new) · [Issue](https://github.com/zengyunhua/Mestudy/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/Mestudy_deserial_getPersonMessage/SUBMISSION_PLAYBOOK.md) |
| 2 | Mestudy | sqli | NetUserInfoApplication.queryNetUserInfoList | — | 2026-11-02 (0.7d) | 70c0029488d3 | [NetPortalManagement/src/main/java/com/tecsun/sisp/npm/service/NetUserInfoApplication.java:40](https://github.com/zengyunhua/Mestudy/blob/70c0029488d3db7e2f82b4edcfc1f3e2dea84f18/NetPortalManagement/src/main/java/com/tecsun/sisp/npm/service/NetUserInfoApplication.java#L40) | [Advisory](https://github.com/zengyunhua/Mestudy/security/advisories/new) · [Issue](https://github.com/zengyunhua/Mestudy/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/Mestudy_sqli_queryNetUserInfoList/SUBMISSION_PLAYBOOK.md) |
| 3 | Mestudy | sqli | NetUserInfoApplication.updateNewsInfo | — | 2026-11-02 (0.7d) | 70c0029488d3 | [NetPortalManagement/src/main/java/com/tecsun/sisp/npm/service/NetUserInfoApplication.java:54](https://github.com/zengyunhua/Mestudy/blob/70c0029488d3db7e2f82b4edcfc1f3e2dea84f18/NetPortalManagement/src/main/java/com/tecsun/sisp/npm/service/NetUserInfoApplication.java#L54) | [Advisory](https://github.com/zengyunhua/Mestudy/security/advisories/new) · [Issue](https://github.com/zengyunhua/Mestudy/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/Mestudy_sqli_updateNewsInfo/SUBMISSION_PLAYBOOK.md) |
| 4 | Mestudy | sqli | PolicyApplication.getPolicyInfo | — | 2026-11-02 (0.7d) | 70c0029488d3 | [NetPortalManagement/src/main/java/com/tecsun/sisp/npm/service/PolicyApplication.java:50](https://github.com/zengyunhua/Mestudy/blob/70c0029488d3db7e2f82b4edcfc1f3e2dea84f18/NetPortalManagement/src/main/java/com/tecsun/sisp/npm/service/PolicyApplication.java#L50) | [Advisory](https://github.com/zengyunhua/Mestudy/security/advisories/new) · [Issue](https://github.com/zengyunhua/Mestudy/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/Mestudy_sqli_getPolicyInfo/SUBMISSION_PLAYBOOK.md) |
| 5 | Mestudy | sqli | WebConnectionApplication.getWebInfo | — | 2026-11-02 (0.7d) | 70c0029488d3 | [NetPortalManagement/src/main/java/com/tecsun/sisp/npm/service/WebConnectionApplication.java:31](https://github.com/zengyunhua/Mestudy/blob/70c0029488d3db7e2f82b4edcfc1f3e2dea84f18/NetPortalManagement/src/main/java/com/tecsun/sisp/npm/service/WebConnectionApplication.java#L31) | [Advisory](https://github.com/zengyunhua/Mestudy/security/advisories/new) · [Issue](https://github.com/zengyunhua/Mestudy/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/Mestudy_sqli_getWebInfo/SUBMISSION_PLAYBOOK.md) |
| 6 | django-crm | redir | email_subtask_completion | — | 2026-11-01 (1.2d) | b1e9f2ea25bb | [tasks/views/create_completed_subtask.py:61](https://github.com/DjangoCRM/django-crm/blob/b1e9f2ea25bb2c755302d661c2f12fa716774f3e/tasks/views/create_completed_subtask.py#L61) | [Advisory](https://github.com/DjangoCRM/django-crm/security/advisories/new) · [Issue](https://github.com/DjangoCRM/django-crm/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/django-crm_redir_email_subtask_completion/SUBMISSION_PLAYBOOK.md) |
| 7 | django-crm | ssrf | VoIPWebHook.post | — | 2026-11-01 (1.2d) | b1e9f2ea25bb | [voip/views/voipwebhook.py:29](https://github.com/DjangoCRM/django-crm/blob/b1e9f2ea25bb2c755302d661c2f12fa716774f3e/voip/views/voipwebhook.py#L29) | [Advisory](https://github.com/DjangoCRM/django-crm/security/advisories/new) · [Issue](https://github.com/DjangoCRM/django-crm/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/django-crm_ssrf_post/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | Mestudy | log_injection | DraftsController.findbyCurrentDetailedMessage | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 2 | Mestudy | log_injection | DraftsController.findbyCurrentMessage | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 3 | Mestudy | log_injection | DraftsController.findbyDraftsMessage | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 4 | Mestudy | log_injection | DraftsController.findbyFailDetailedMessage | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 5 | Mestudy | log_injection | DraftsController.findbyFailMessage | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 6 | Mestudy | log_injection | DraftsController.findbySuccessDetailedMessage | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 7 | Mestudy | log_injection | DraftsController.findbySuccessMessage | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 8 | Mestudy | log_injection | DraftsController.getImageFile | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 9 | Mestudy | log_injection | DraftsController.getImageInfo | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 10 | Mestudy | log_injection | DraftsController.getPersonMessage | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 11 | Mestudy | log_injection | DraftsController.queryByOfficeStatus | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 12 | Mestudy | log_injection | JobQueryController.addJobSeekerInfo | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 13 | Mestudy | log_injection | JobQueryController.modifyJobSeekerInfo | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 14 | Mestudy | log_injection | SecQueryController.getBirthInfo | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 15 | django-crm | authz | email_subtask_completion | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 7 |
| B（其余状态） | 15 |
| 合计 | 22 |
