# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-08 00:53:51
- 总条数：60 ｜ 板块 A：**5** ｜ 板块 B：**55**
- 状态计数：ZERO_RECORD_FRESH 5 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 55

<!-- live_hunt_counts: {"BOARD_A": 5, "BOARD_B": 55, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 55, "ZERO_RECORD_FRESH": 5} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 16 个缓存。

- 候选仓：17 ｜ 实扫：8 ｜ 跳过：9 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：60 ｜ 板块 A：5 ｜ 拦截进 B：55
- 冷却期免克隆：1 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| langgraph4j/langgraph4j | 23aef94c1755 | SKIPPED | 0 |
| microsoft/intelligence-toolkit | f6ee0f21e571 | SKIPPED | 0 |
| holdmyspot-com/cat | 1d282487738b | SKIPPED | 0 |
| Francis1998/scholar-rag-agent | d693d46b15bf | SCANNED | 4 |
| Swayingleaves/novanova-studio | 0269e4856fc0 | SCANNED | 4 |
| WenyuChiou/ai-research-skills | b649037b02b8 | SKIPPED | 0 |
| quarkiverse/quarkus-flow | dedd3568b556 | SKIPPED | 0 |
| xorbitsai/xagent | 7dc47a883769 | SCANNED | 41 |
| boommanpro/gaia-workflow-engine | c45955256913 | SCANNED | 3 |
| Zzz1phyrf/ComfyUI-H3-LongVideo | 2e12b50d8fdd | SCANNED | 0 |
| w8123/EnterpriseAgentFramework | 1f1230d50db0 | SKIPPED | 0 |
| willmiao/ComfyUI-Lora-Manager | f4ea2551a89c | SKIPPED | 0 |
| tmseidel/ai-git-bot | cdfd192ca8c6 | SCANNED | 1 |
| iha2/superlite | 9747f27e49ed | SKIPPED | 0 |
| taishan666/MaxKB4j | e008b2be340f | SCANNED | 4 |
| KbWen/agentic-os | 82203b5c0689 | SKIPPED | 0 |
| risesoft-y9/WorkFlow-Engine | e91293ca1db4 | SCANNED | 3 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | WorkFlow-Engine | sqli | DoingRestController.doingList4All | — | 2026-11-06 (1.4d) | e91293ca1db4 | [y9-module-flowableui/risenet-y9boot-support-flowableui/src/main/java/net/risesoft/controller/worklist/DoingRestController.java:51](https://github.com/risesoft-y9/WorkFlow-Engine/blob/e91293ca1db478fd4e692a23e9f263bbe61dd4d9/y9-module-flowableui/risenet-y9boot-support-flowableui/src/main/java/net/risesoft/controller/worklist/DoingRestController.java#L51) | [Advisory](https://github.com/risesoft-y9/WorkFlow-Engine/security/advisories/new) · [Issue](https://github.com/risesoft-y9/WorkFlow-Engine/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/WorkFlow-Engine_sqli_doingList4All/SUBMISSION_PLAYBOOK.md) |
| 2 | WorkFlow-Engine | sqli | DoingRestController.doingList4Dept | — | 2026-11-06 (1.4d) | e91293ca1db4 | [y9-module-flowableui/risenet-y9boot-support-flowableui/src/main/java/net/risesoft/controller/worklist/DoingRestController.java:66](https://github.com/risesoft-y9/WorkFlow-Engine/blob/e91293ca1db478fd4e692a23e9f263bbe61dd4d9/y9-module-flowableui/risenet-y9boot-support-flowableui/src/main/java/net/risesoft/controller/worklist/DoingRestController.java#L66) | [Advisory](https://github.com/risesoft-y9/WorkFlow-Engine/security/advisories/new) · [Issue](https://github.com/risesoft-y9/WorkFlow-Engine/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/WorkFlow-Engine_sqli_doingList4Dept/SUBMISSION_PLAYBOOK.md) |
| 3 | WorkFlow-Engine | sqli | DoingRestController.doingList4DuBan | — | 2026-11-06 (1.4d) | e91293ca1db4 | [y9-module-flowableui/risenet-y9boot-support-flowableui/src/main/java/net/risesoft/controller/worklist/DoingRestController.java:81](https://github.com/risesoft-y9/WorkFlow-Engine/blob/e91293ca1db478fd4e692a23e9f263bbe61dd4d9/y9-module-flowableui/risenet-y9boot-support-flowableui/src/main/java/net/risesoft/controller/worklist/DoingRestController.java#L81) | [Advisory](https://github.com/risesoft-y9/WorkFlow-Engine/security/advisories/new) · [Issue](https://github.com/risesoft-y9/WorkFlow-Engine/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/WorkFlow-Engine_sqli_doingList4DuBan/SUBMISSION_PLAYBOOK.md) |
| 4 | gaia-workflow-engine | deserial | AgentObservabilityController.asServiceSession | — | 2026-11-07 (0.2d) | c45955256913 | [apps/api/gaia-workflow/gaia-workflow-app/src/main/java/cn/boommanpro/gaia/workflow/app/controller/system/AgentObservabilityController.java:471](https://github.com/boommanpro/gaia-workflow-engine/blob/c45955256913faaeef643faac53d839632954070/apps/api/gaia-workflow/gaia-workflow-app/src/main/java/cn/boommanpro/gaia/workflow/app/controller/system/AgentObservabilityController.java#L471) | [Advisory](https://github.com/boommanpro/gaia-workflow-engine/security/advisories/new) · [Issue](https://github.com/boommanpro/gaia-workflow-engine/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/gaia-workflow-engine_deserial_asServiceSession/SUBMISSION_PLAYBOOK.md) |
| 5 | gaia-workflow-engine | sqli | ModelConfigController.setSessionModel | — | 2026-11-07 (0.2d) | c45955256913 | [apps/api/gaia-workflow/gaia-workflow-app/src/main/java/cn/boommanpro/gaia/workflow/app/controller/api/ModelConfigController.java:213](https://github.com/boommanpro/gaia-workflow-engine/blob/c45955256913faaeef643faac53d839632954070/apps/api/gaia-workflow/gaia-workflow-app/src/main/java/cn/boommanpro/gaia/workflow/app/controller/api/ModelConfigController.java#L213) | [Advisory](https://github.com/boommanpro/gaia-workflow-engine/security/advisories/new) · [Issue](https://github.com/boommanpro/gaia-workflow-engine/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/gaia-workflow-engine_sqli_setSessionModel/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | MaxKB4j | authz | ApplicationController.playDemoText | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 2 | MaxKB4j | authz | AuthController.login | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | MaxKB4j | authz | ChatApiController.auth | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | MaxKB4j | authz | ChatApiController.handleMcpRequest | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | ai-git-bot | authz | UsageController.usage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | gaia-workflow-engine | authz | AgentSessionRunController.run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | novanova-studio | authz | AdminCreditController.getCreditOverview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | novanova-studio | authz | AdminCreditController.listCreditCards | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | novanova-studio | authz | AdminCreditController.listCreditTransactions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | novanova-studio | authz | AdminCreditController.listTaskRecords | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | scholar-rag-agent | authz | create_annotation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | scholar-rag-agent | authz | explore_context | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 13 | scholar-rag-agent | authz | explore_document | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 14 | scholar-rag-agent | authz | list_reviews | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | xagent | authz | bind_agent_preview_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | xagent | authz | get_agent_preview_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | xagent | log_injection | connect_mcp_app | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 18 | xagent | log_injection | create_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 19 | xagent | log_injection | create_mcp_server | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 20 | xagent | log_injection | create_model | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 21 | xagent | log_injection | create_task | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 22 | xagent | log_injection | delete_chat_task | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 23 | xagent | log_injection | delete_installed | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 24 | xagent | log_injection | delete_task | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 25 | xagent | log_injection | demote_agent_to_personal | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 26 | xagent | log_injection | disable_agent_share_link | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 27 | xagent | log_injection | edit_installed | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 28 | xagent | log_injection | enable_agent_share_link | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 29 | xagent | log_injection | generate_agent_api_key | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 30 | xagent | log_injection | get_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 31 | xagent | log_injection | get_agent_api_key | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 32 | xagent | log_injection | get_agent_share_link | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 33 | xagent | log_injection | get_agent_widget_key | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 34 | xagent | log_injection | get_available_tools | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 35 | xagent | log_injection | get_task_output_files | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 36 | xagent | log_injection | get_task_progress | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 37 | xagent | log_injection | get_task_workspace_files | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 38 | xagent | log_injection | get_tasks | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 39 | xagent | log_injection | get_user_default_models | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 40 | xagent | log_injection | progress_websocket_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 41 | xagent | log_injection | promote_agent_to_team | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 42 | xagent | log_injection | publish_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 43 | xagent | log_injection | regenerate_agent_api_key | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 44 | xagent | log_injection | revoke_agent_api_key | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 45 | xagent | log_injection | rotate_agent_share_link | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 46 | xagent | log_injection | rotate_agent_widget_key | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 47 | xagent | log_injection | test_model_connection | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 48 | xagent | log_injection | unpublish_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 49 | xagent | log_injection | update_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 50 | xagent | log_injection | update_mcp_server | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 51 | xagent | log_injection | update_task | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 52 | xagent | log_injection | upload_agent_logo | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 53 | xagent | log_injection | websocket_build_preview_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 54 | xagent | log_injection | websocket_builder_chat_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 55 | xagent | log_injection | websocket_chat_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 5 |
| B（其余状态） | 55 |
| 合计 | 60 |
