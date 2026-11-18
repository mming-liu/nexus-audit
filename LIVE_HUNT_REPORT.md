# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-19 07:46:50
- 总条数：263 ｜ 板块 A：**2** ｜ 板块 B：**261**
- 状态计数：ZERO_RECORD_FRESH 2 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 261

<!-- live_hunt_counts: {"BOARD_A": 2, "BOARD_B": 261, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 261, "ZERO_RECORD_FRESH": 2} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 0 个缓存。

- 候选仓：13 ｜ 实扫：5 ｜ 跳过：8 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：263 ｜ 板块 A：2 ｜ 拦截进 B：261
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：1 个
- 侦察告警：java: ConnectError: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1081)

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| flowable/flowable-engine | 63f9cbfa3f48 | SCANNED | 81 |
| wodrake/ERP-AGENT-open-source | 84b94a537ce0 | SCANNED | 5 |
| oshi/oshi | 2eba26995b81 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| avansaber/erpclaw | aea97950a7d7 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| Loophole-LLC/Bastillion | 30efb971aa50 | SKIPPED (low_units_4) | 0 |
| xuliang2024/minitv | 3e0dc7aa98d0 | SCANNED | 8 |
| webbukkit/dynmap | 93b454efb880 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| yarsa/nepal-compliance | fbb9e95be233 | SKIPPED (low_units_7) | 0 |
| 88250/symphony | c3e204806f98 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| google/jimfs | ea4ffa030a61 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| pig-mesh/pig | 193997016e39 | SCANNED | 169 |
| apache/avro | 7b7dec155e53 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| yux567890/mall | 6430cbff307a | SCANNED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | pig | xss | PigTokenEndpoint.confirm | — | 2026-11-08 (10.9d) | 193997016e39 | [pig-auth/src/main/java/com/pig4cloud/pig/auth/endpoint/PigTokenEndpoint.java:111](https://github.com/pig-mesh/pig/blob/193997016e39c2158a11c6da3ec1fc9fa3162a9d/pig-auth/src/main/java/com/pig4cloud/pig/auth/endpoint/PigTokenEndpoint.java#L111) | [Advisory](https://github.com/pig-mesh/pig/security/advisories/new) · [Issue](https://github.com/pig-mesh/pig/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/pig_xss_confirm/SUBMISSION_PLAYBOOK.md) |
| 2 | pig | xss | PigTokenEndpoint.require | — | 2026-11-08 (10.9d) | 193997016e39 | [pig-auth/src/main/java/com/pig4cloud/pig/auth/endpoint/PigTokenEndpoint.java:92](https://github.com/pig-mesh/pig/blob/193997016e39c2158a11c6da3ec1fc9fa3162a9d/pig-auth/src/main/java/com/pig4cloud/pig/auth/endpoint/PigTokenEndpoint.java#L92) | [Advisory](https://github.com/pig-mesh/pig/security/advisories/new) · [Issue](https://github.com/pig-mesh/pig/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/pig_xss_require/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | ERP-AGENT-open-source | authz | chat_history | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | ERP-AGENT-open-source | authz | chat_resume | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | ERP-AGENT-open-source | authz | chat_state | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | ERP-AGENT-open-source | authz | get_messages | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | ERP-AGENT-open-source | authz | session_probe | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | flowable-engine | authz | AppDefinitionResource.executeAppDefinitionAction | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | flowable-engine | authz | AppDefinitionResource.getAppDefinition | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | flowable-engine | authz | AppDefinitionResourceDataResource.getAppDefinitionResource | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | flowable-engine | authz | AppDeploymentResource.deleteAppDeployment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | flowable-engine | authz | AppDeploymentResourceCollectionResource.getDeploymentResources | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | flowable-engine | authz | AppDeploymentResourceDataResource.getAppDeploymentResource | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | flowable-engine | authz | AppDeploymentResourceResource.getDeploymentResource | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 13 | flowable-engine | authz | AppModelResource.getModelJsonResource | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 14 | flowable-engine | authz | BatchPartCollectionResource.getBatches | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | flowable-engine | authz | BatchPartResource.getBatchPartDocument | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | flowable-engine | authz | BatchResource.deleteJob | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | flowable-engine | authz | BatchResource.getBatchDocument | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | flowable-engine | authz | BatchResource.getBatchSummary | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 19 | flowable-engine | authz | CaseDefinitionResource.batchMigrateHistoricInstancesOfCaseDefinition | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | flowable-engine | authz | CaseDefinitionResource.batchMigrateInstancesOfCaseDefinition | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | flowable-engine | authz | CaseDefinitionResource.migrateHistoricInstancesOfCaseDefinition | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | flowable-engine | authz | CaseDefinitionResource.migrateInstancesOfCaseDefinition | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | flowable-engine | authz | CaseInstanceIdentityLinkResource.deleteIdentityLink | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 24 | flowable-engine | authz | CaseInstanceResource.getStageOverview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 25 | flowable-engine | authz | CaseInstanceResource.migrateCaseInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 26 | flowable-engine | authz | CaseInstanceResource.updateCaseInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 27 | flowable-engine | authz | CaseInstanceResource.validateCaseInstanceMigration | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 28 | flowable-engine | authz | CaseInstanceVariableResource.deleteVariable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 29 | flowable-engine | authz | DeploymentResource.deleteDeployment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 30 | flowable-engine | authz | DeploymentResource.deleteDeployment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 31 | flowable-engine | authz | DeploymentResource.deleteDeployment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 32 | flowable-engine | authz | DeploymentResourceCollectionResource.getDeploymentResources | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 33 | flowable-engine | authz | DeploymentResourceResource.getDeploymentResource | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 34 | flowable-engine | authz | DmnDeploymentResource.deleteDmnDeployment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 35 | flowable-engine | authz | ExecutionVariableResource.deleteVariable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 36 | flowable-engine | authz | ExternalWorkerUnacquireJobResource.unaquireJob | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 37 | flowable-engine | authz | FormDataResource.getFormData | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 38 | flowable-engine | authz | GroupMembershipResource.deleteMembership | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 39 | flowable-engine | authz | GroupMembershipResource.deleteMembership | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 40 | flowable-engine | authz | HistoricCaseInstanceResource.migrateHistoricCaseInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 41 | flowable-engine | authz | HistoricProcessInstanceCommentResource.deleteComment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 42 | flowable-engine | authz | HistoricProcessInstanceCommentResource.getComment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 43 | flowable-engine | authz | HistoricProcessInstanceResource.deleteProcessInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 44 | flowable-engine | authz | HistoricTaskInstanceIdentityLinkCollectionResource.getTaskIdentityLinks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 45 | flowable-engine | authz | HistoricTaskInstanceResource.deleteTaskInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 46 | flowable-engine | authz | HistoricTaskInstanceResource.deleteTaskInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 47 | flowable-engine | authz | JobResource.deleteDeadLetterJob | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 48 | flowable-engine | authz | JobResource.deleteHistoryJob | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 49 | flowable-engine | authz | JobResource.deleteHistoryJob | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 50 | flowable-engine | authz | JobResource.deleteJob | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 51 | flowable-engine | authz | JobResource.deleteSuspendedJob | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 52 | flowable-engine | authz | JobResource.deleteTimerJob | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 53 | flowable-engine | authz | PlanItemInstanceResource.performPlanItemInstanceAction | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 54 | flowable-engine | authz | PlanItemInstanceVariableResource.deleteVariable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 55 | flowable-engine | authz | PrivilegeCollectionResource.addGroupPrivilege | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 56 | flowable-engine | authz | PrivilegeCollectionResource.addUserPrivilege | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 57 | flowable-engine | authz | PrivilegeCollectionResource.deleteGroupPrivilege | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 58 | flowable-engine | authz | PrivilegeCollectionResource.deleteUserPrivilege | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 59 | flowable-engine | authz | PrivilegeCollectionResource.getGroups | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 60 | flowable-engine | authz | PrivilegeCollectionResource.getUsers | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 61 | flowable-engine | authz | ProcessDefinitionResource.batchMigrateInstancesOfProcessDefinition | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 62 | flowable-engine | authz | ProcessDefinitionResource.migrateInstancesOfProcessDefinition | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 63 | flowable-engine | authz | ProcessInstanceIdentityLinkResource.deleteIdentityLink | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 64 | flowable-engine | authz | ProcessInstanceResource.deleteProcessInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 65 | flowable-engine | authz | ProcessInstanceResource.injectActivityInProcessInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 66 | flowable-engine | authz | ProcessInstanceResource.migrateProcessInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 67 | flowable-engine | authz | ProcessInstanceResource.updateProcessInstance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 68 | flowable-engine | authz | ProcessInstanceResource.validateProcessInstanceMigration | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 69 | flowable-engine | authz | ProcessInstanceVariableResource.deleteVariable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 70 | flowable-engine | authz | TableColumnsResource.getTableMetaData | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 71 | flowable-engine | authz | TableDataResource.getTableData | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 72 | flowable-engine | authz | TaskAttachmentContentResource.getAttachmentContent | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 73 | flowable-engine | authz | TaskAttachmentResource.deleteAttachment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 74 | flowable-engine | authz | TaskAttachmentResource.getAttachment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 75 | flowable-engine | authz | TaskCommentResource.deleteComment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 76 | flowable-engine | authz | TaskCommentResource.getComment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 77 | flowable-engine | authz | TaskEventResource.deleteEvent | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 78 | flowable-engine | authz | TaskEventResource.getEvent | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 79 | flowable-engine | authz | TaskIdentityLinkResource.deleteIdentityLink | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 80 | flowable-engine | authz | TaskIdentityLinkResource.deleteIdentityLink | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 81 | flowable-engine | authz | TaskResource.deleteTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 82 | flowable-engine | authz | TaskResource.deleteTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 83 | flowable-engine | authz | TaskVariableResource.deleteVariable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 84 | flowable-engine | authz | TaskVariableResource.deleteVariable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 85 | flowable-engine | authz | UserInfoResource.getUserInfo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 86 | flowable-engine | authz | UserInfoResource.setUserInfo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 87 | minitv | authz | change_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（docker-compose.yml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 88 | minitv | authz | drama_detail | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（docker-compose.yml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 89 | minitv | authz | drama_play | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 90 | minitv | authz | legal | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（docker-compose.yml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 91 | minitv | authz | one_decision | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（docker-compose.yml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 92 | minitv | authz | preview_drama | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（docker-compose.yml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 93 | minitv | authz | publish_reviewed | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（docker-compose.yml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 94 | minitv | hardcoded_secret | [secret-file] moderation.py | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（docker-compose.yml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 95 | pig | authz | GenCreateTableController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 96 | pig | authz | GenCreateTableController.getPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 97 | pig | authz | GenCreateTableController.removeById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 98 | pig | authz | GenCreateTableController.removeById#2 | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 99 | pig | authz | GenCreateTableController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 100 | pig | authz | GenCreateTableController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 101 | pig | authz | GenDsConfController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 102 | pig | authz | GenDsConfController.getSysDatasourceConfPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 103 | pig | authz | GenDsConfController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 104 | pig | authz | GenDsConfController.updateById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 105 | pig | authz | GenFieldTypeController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 106 | pig | authz | GenFieldTypeController.getFieldTypePage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 107 | pig | authz | GenFieldTypeController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 108 | pig | authz | GenFieldTypeController.updateById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 109 | pig | authz | GenGroupController.getById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 110 | pig | authz | GenGroupController.getgenGroupPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 111 | pig | authz | GenGroupController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 112 | pig | authz | GenGroupController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 113 | pig | authz | GenTableController.getColumn | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 114 | pig | authz | GenTableController.getDdl | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 115 | pig | authz | GenTableController.getTable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 116 | pig | authz | GenTableController.getTable#2 | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 117 | pig | authz | GenTableController.getTablePage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 118 | pig | authz | GenTableController.listTable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 119 | pig | authz | GenTableController.syncTable | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 120 | pig | authz | GenTableController.updateById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 121 | pig | authz | GenTableController.updateTableField | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 122 | pig | authz | GenTemplateController.getById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 123 | pig | authz | GenTemplateController.getGenTemplatePage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 124 | pig | authz | GenTemplateController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 125 | pig | authz | GenTemplateController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 126 | pig | authz | GenTemplateGroupController.getById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 127 | pig | authz | GenTemplateGroupController.getgenTemplateGroupPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 128 | pig | authz | GenTemplateGroupController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 129 | pig | authz | GenTemplateGroupController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 130 | pig | authz | GeneratorController.checkPath | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 131 | pig | authz | GeneratorController.preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 132 | pig | authz | PigTokenEndpoint.checkToken | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 133 | pig | authz | PigTokenEndpoint.removeToken | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 134 | pig | authz | SysApiKeyController.create | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 135 | pig | authz | SysApiKeyController.delete | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 136 | pig | authz | SysApiKeyController.page | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 137 | pig | authz | SysApiKeyController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 138 | pig | authz | SysAreaController.existsByAdcode | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 139 | pig | authz | SysAreaController.getDetails | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 140 | pig | authz | SysAreaController.getManageChildren | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 141 | pig | authz | SysAreaController.getSysAreaPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 142 | pig | authz | SysAreaController.getSysAreaTree | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 143 | pig | authz | SysAreaController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 144 | pig | authz | SysAreaController.searchManage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 145 | pig | authz | SysAreaController.sort | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 146 | pig | authz | SysAreaController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 147 | pig | authz | SysClientController.add | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 148 | pig | authz | SysClientController.getOauthClientDetailsPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 149 | pig | authz | SysClientController.update | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 150 | pig | authz | SysDeptController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 151 | pig | authz | SysDeptController.getDescendantList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 152 | pig | authz | SysDeptController.getOrgTreeUser | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 153 | pig | authz | SysDeptController.getTree | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 154 | pig | authz | SysDeptController.importDept | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 155 | pig | authz | SysDeptController.listOrgTree | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 156 | pig | authz | SysDeptController.removeById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 157 | pig | authz | SysDeptController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 158 | pig | authz | SysDeptController.update | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 159 | pig | authz | SysDictController.removeDictItemById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 160 | pig | authz | SysDictController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 161 | pig | authz | SysDictController.save#2 | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 162 | pig | authz | SysDictController.sortDictItem | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 163 | pig | authz | SysDictController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 164 | pig | authz | SysDictController.updateById#2 | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 165 | pig | authz | SysFileController.addGroup | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 166 | pig | authz | SysFileController.file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 167 | pig | authz | SysFileController.getSysFilePage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 168 | pig | authz | SysFileController.innerUpload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 169 | pig | authz | SysFileController.listGroup | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 170 | pig | authz | SysFileController.moveFileGroup | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 171 | pig | authz | SysFileController.rename | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 172 | pig | authz | SysFileController.updateGroup | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 173 | pig | authz | SysFileController.updateGroup#2 | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 174 | pig | authz | SysFileController.upload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 175 | pig | authz | SysI18nController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 176 | pig | authz | SysI18nController.getsysI18nPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 177 | pig | authz | SysI18nController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 178 | pig | authz | SysI18nController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 179 | pig | authz | SysJobController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 180 | pig | authz | SysJobController.getJobLog | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 181 | pig | authz | SysJobController.removeById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 182 | pig | authz | SysJobController.runJob | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 183 | pig | authz | SysJobController.shutdownJob | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 184 | pig | authz | SysJobController.startJob | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 185 | pig | authz | SysJobController.validate | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 186 | pig | authz | SysJobLogController.getSysJobLogPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 187 | pig | authz | SysLogController.getLogPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 188 | pig | authz | SysLogController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 189 | pig | authz | SysLogController.saveBatchLogs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 190 | pig | authz | SysMenuController.getRoleTree | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 191 | pig | authz | SysMenuController.getTree | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 192 | pig | authz | SysMenuController.getUserMenu | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 193 | pig | authz | SysMenuController.removeById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 194 | pig | authz | SysMenuController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 195 | pig | authz | SysMenuController.sort | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 196 | pig | authz | SysMenuController.update | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 197 | pig | authz | SysMessageController.getById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 198 | pig | authz | SysMessageController.getSysMessagePage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 199 | pig | authz | SysMessageController.getUserMessageList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 200 | pig | authz | SysMessageController.getUserMessageList#2 | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 201 | pig | authz | SysMessageController.listHookBizCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 202 | pig | authz | SysMessageController.read | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 203 | pig | authz | SysMessageController.removeUserMessage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 204 | pig | authz | SysMessageController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 205 | pig | authz | SysMessageController.send | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 206 | pig | authz | SysMessageController.sendEmail | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 207 | pig | authz | SysMessageController.sendNotice | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 208 | pig | authz | SysMessageController.sendSms | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 209 | pig | authz | SysMessageController.sendSmsCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 210 | pig | authz | SysMessageController.sendWebhook | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 211 | pig | authz | SysMessageController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 212 | pig | authz | SysPublicParamController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 213 | pig | authz | SysPublicParamController.getSysPublicParamPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 214 | pig | authz | SysPublicParamController.publicKey | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 215 | pig | authz | SysPublicParamController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 216 | pig | authz | SysPublicParamController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 217 | pig | authz | SysRegisterController.forgetUserPassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 218 | pig | authz | SysRegisterController.registerUser | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 219 | pig | authz | SysRegisterController.resetUserPassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 220 | pig | authz | SysRoleController.export | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 221 | pig | authz | SysRoleController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 222 | pig | authz | SysRoleController.getRoleList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 223 | pig | authz | SysRoleController.getRolePage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 224 | pig | authz | SysRoleController.getRoleWidget | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 225 | pig | authz | SysRoleController.importRole | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 226 | pig | authz | SysRoleController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 227 | pig | authz | SysRoleController.saveRoleMenus | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 228 | pig | authz | SysRoleController.saveRoleWidget | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 229 | pig | authz | SysRoleController.update | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 230 | pig | authz | SysScheduleController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 231 | pig | authz | SysScheduleController.getSchedulePage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 232 | pig | authz | SysScheduleController.list | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 233 | pig | authz | SysScheduleController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 234 | pig | authz | SysScheduleController.updateById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 235 | pig | authz | SysSensitiveWordController.getSysSensitiveWordPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 236 | pig | authz | SysSensitiveWordController.match | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 237 | pig | authz | SysSensitiveWordController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 238 | pig | authz | SysSensitiveWordController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 239 | pig | authz | SysSocialDetailsController.bindSocial | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 240 | pig | authz | SysSocialDetailsController.getSocialDetailsPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 241 | pig | authz | SysSocialDetailsController.getUserInfo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 242 | pig | authz | SysSocialDetailsController.info | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 243 | pig | authz | SysSocialDetailsController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 244 | pig | authz | SysSocialDetailsController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 245 | pig | authz | SysSystemConfigController.getDetails | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 246 | pig | authz | SysSystemConfigController.getSysSystemConfigPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 247 | pig | authz | SysSystemConfigController.save | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 248 | pig | authz | SysSystemConfigController.updateById | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 249 | pig | authz | SysSystemInfoController.clarity | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 250 | pig | authz | SysSystemInfoController.updateSiteConfig | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 251 | pig | authz | SysTokenController.getTokenPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 252 | pig | authz | SysUserController.export | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 253 | pig | authz | SysUserController.getUserPage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 254 | pig | authz | SysUserController.importUser | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 255 | pig | authz | SysUserController.listAncestorUsers | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 256 | pig | authz | SysUserController.lockUser | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 257 | pig | authz | SysUserController.unbinding | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 258 | pig | authz | SysUserController.updateUser | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权 | — |
| 259 | pig | authz | SysUserController.updateUserInfo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 260 | pig | authz | SysUserController.user | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 261 | pig | authz | SysUserController.user#2 | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 2 |
| B（其余状态） | 261 |
| 合计 | 263 |
