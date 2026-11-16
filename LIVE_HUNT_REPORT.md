# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-16 08:08:48
- 总条数：173 ｜ 板块 A：**11** ｜ 板块 B：**162**
- 状态计数：ZERO_RECORD_FRESH 11 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 162

<!-- live_hunt_counts: {"BOARD_A": 11, "BOARD_B": 162, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 162, "ZERO_RECORD_FRESH": 11} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 0 个缓存。

- 候选仓：13 ｜ 实扫：5 ｜ 跳过：5 ｜ 失败：3 ｜ 候选来源：github_search
- 本次新增根因：173 ｜ 板块 A：11 ｜ 拦截进 B：162
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：0 个

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| aklivity/zilla | bf5ef498eacb | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| Haohao-end/openagent |  | FAILED (clone_failed: t'...
error: invalid path ) | 0 |
| mguessan/davmail | 87a6a160d6d5 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| wwwzhouhui/dify-for-dsl | d835ecfa6cbe | SCANNED | 21 |
| wso2/product-apim | 239049b850ce | SCANNED | 12 |
| YFGaia/dify-plus | c48ecee4d7c3 | SCANNED | 82 |
| jitsi/jigasi | 8e050ed1b694 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| FunnyWolf/agentic-soc-platform | 2da9bb33a62b | SCANNED | 5 |
| scalecube/scalecube-services | 4ef08a2b5e1f | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| hustyichi/dify-rag | e15bb40fbe4a | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| java-up-up/damai | aaab651af141 | SCANNED | 53 |
| didi/KnowSearch |  | FAILED (TimeoutExpired: Command '['C:\\Users\\ee) | 0 |
| gravitee-io/gravitee-api-management |  | FAILED (TimeoutExpired: Command '['C:\\Users\\ee) | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | agentic-soc-platform | mass_assignment | SIEMAdaptiveQueryView.post | — | 2026-09-29 (47.7d) | 2da9bb33a62b | [backend/apps/agent_api/views.py:343](https://github.com/FunnyWolf/agentic-soc-platform/blob/2da9bb33a62bcc73fbfac364b1051da069b457ee/backend/apps/agent_api/views.py#L343) | [Advisory](https://github.com/FunnyWolf/agentic-soc-platform/security/advisories/new) · [Issue](https://github.com/FunnyWolf/agentic-soc-platform/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/agentic-soc-platform_mass_assignment_post/SUBMISSION_PLAYBOOK.md) |
| 2 | agentic-soc-platform | mass_assignment | SIEMDiscoverFieldsView.post | — | 2026-09-29 (47.7d) | 2da9bb33a62b | [backend/apps/agent_api/views.py:343](https://github.com/FunnyWolf/agentic-soc-platform/blob/2da9bb33a62bcc73fbfac364b1051da069b457ee/backend/apps/agent_api/views.py#L343) | [Advisory](https://github.com/FunnyWolf/agentic-soc-platform/security/advisories/new) · [Issue](https://github.com/FunnyWolf/agentic-soc-platform/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/agentic-soc-platform_mass_assignment_post/SUBMISSION_PLAYBOOK.md) |
| 3 | agentic-soc-platform | mass_assignment | SIEMESQLQueryView.post | — | 2026-09-29 (47.7d) | 2da9bb33a62b | [backend/apps/agent_api/views.py:343](https://github.com/FunnyWolf/agentic-soc-platform/blob/2da9bb33a62bcc73fbfac364b1051da069b457ee/backend/apps/agent_api/views.py#L343) | [Advisory](https://github.com/FunnyWolf/agentic-soc-platform/security/advisories/new) · [Issue](https://github.com/FunnyWolf/agentic-soc-platform/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/agentic-soc-platform_mass_assignment_post/SUBMISSION_PLAYBOOK.md) |
| 4 | agentic-soc-platform | mass_assignment | SIEMKeywordSearchView.post | — | 2026-09-29 (47.7d) | 2da9bb33a62b | [backend/apps/agent_api/views.py:343](https://github.com/FunnyWolf/agentic-soc-platform/blob/2da9bb33a62bcc73fbfac364b1051da069b457ee/backend/apps/agent_api/views.py#L343) | [Advisory](https://github.com/FunnyWolf/agentic-soc-platform/security/advisories/new) · [Issue](https://github.com/FunnyWolf/agentic-soc-platform/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/agentic-soc-platform_mass_assignment_post/SUBMISSION_PLAYBOOK.md) |
| 5 | agentic-soc-platform | mass_assignment | SIEMSPLQueryView.post | — | 2026-09-29 (47.7d) | 2da9bb33a62b | [backend/apps/agent_api/views.py:343](https://github.com/FunnyWolf/agentic-soc-platform/blob/2da9bb33a62bcc73fbfac364b1051da069b457ee/backend/apps/agent_api/views.py#L343) | [Advisory](https://github.com/FunnyWolf/agentic-soc-platform/security/advisories/new) · [Issue](https://github.com/FunnyWolf/agentic-soc-platform/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/agentic-soc-platform_mass_assignment_post/SUBMISSION_PLAYBOOK.md) |
| 6 | dify-for-dsl | ssrf | generate_video | — | 2026-11-11 (4.3d) | d835ecfa6cbe | [py/geekaiapp/g_jiekou.py:653](https://github.com/wwwzhouhui/dify-for-dsl/blob/d835ecfa6cbe45a70326e4e3336bbf73f2c68a17/py/geekaiapp/g_jiekou.py#L653) | [Advisory](https://github.com/wwwzhouhui/dify-for-dsl/security/advisories/new) · [Issue](https://github.com/wwwzhouhui/dify-for-dsl/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dify-for-dsl_ssrf_generate_video/SUBMISSION_PLAYBOOK.md) |
| 7 | dify-for-dsl | ssrf | generate_video | — | 2026-11-11 (4.3d) | d835ecfa6cbe | [py/geekaiapp/jimeng_video_service.py:73](https://github.com/wwwzhouhui/dify-for-dsl/blob/d835ecfa6cbe45a70326e4e3336bbf73f2c68a17/py/geekaiapp/jimeng_video_service.py#L73) | [Advisory](https://github.com/wwwzhouhui/dify-for-dsl/security/advisories/new) · [Issue](https://github.com/wwwzhouhui/dify-for-dsl/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dify-for-dsl_ssrf_generate_video/SUBMISSION_PLAYBOOK.md) |
| 8 | dify-for-dsl | ssrf | gjld_audio | — | 2026-11-11 (4.3d) | d835ecfa6cbe | [py/geekaiapp/g_jiekou.py:172](https://github.com/wwwzhouhui/dify-for-dsl/blob/d835ecfa6cbe45a70326e4e3336bbf73f2c68a17/py/geekaiapp/g_jiekou.py#L172) | [Advisory](https://github.com/wwwzhouhui/dify-for-dsl/security/advisories/new) · [Issue](https://github.com/wwwzhouhui/dify-for-dsl/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dify-for-dsl_ssrf_gjld_audio/SUBMISSION_PLAYBOOK.md) |
| 9 | dify-for-dsl | ssrf | jm_image | — | 2026-11-11 (4.3d) | d835ecfa6cbe | [py/geekaiapp/g_jiekou.py:242](https://github.com/wwwzhouhui/dify-for-dsl/blob/d835ecfa6cbe45a70326e4e3336bbf73f2c68a17/py/geekaiapp/g_jiekou.py#L242) | [Advisory](https://github.com/wwwzhouhui/dify-for-dsl/security/advisories/new) · [Issue](https://github.com/wwwzhouhui/dify-for-dsl/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dify-for-dsl_ssrf_jm_image/SUBMISSION_PLAYBOOK.md) |
| 10 | dify-for-dsl | ssrf | jm_image | — | 2026-11-11 (4.3d) | d835ecfa6cbe | [py/geekaiapp/wenshengtu1/jm1_jiekou.py:25](https://github.com/wwwzhouhui/dify-for-dsl/blob/d835ecfa6cbe45a70326e4e3336bbf73f2c68a17/py/geekaiapp/wenshengtu1/jm1_jiekou.py#L25) | [Advisory](https://github.com/wwwzhouhui/dify-for-dsl/security/advisories/new) · [Issue](https://github.com/wwwzhouhui/dify-for-dsl/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dify-for-dsl_ssrf_jm_image/SUBMISSION_PLAYBOOK.md) |
| 11 | product-apim | xss | PeopleRestService.addPerson | — | 2026-11-12 (3.7d) | 239049b850ce | [all-in-one-apim/modules/integration/tests-common/backend-service/jaxrs-app/src/main/java/org/wso2/am/integration/services/jaxrs/peoplesample/PeopleRestService.java:45](https://github.com/wso2/product-apim/blob/239049b850ce1a437e5a83899b8262a3a7f4ff7d/all-in-one-apim/modules/integration/tests-common/backend-service/jaxrs-app/src/main/java/org/wso2/am/integration/services/jaxrs/peoplesample/PeopleRestService.java#L45) | [Advisory](https://github.com/wso2/product-apim/security/advisories/new) · [Issue](https://github.com/wso2/product-apim/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/product-apim_xss_addPerson/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | damai | authz | AllRuleController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | damai | authz | ApiDataController.pageList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | damai | authz | AreaController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | damai | authz | AreaController.selectByIdList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | damai | authz | BroadcastController.call | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | damai | authz | ChannelDataController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | damai | authz | ChannelDataController.getByCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | damai | authz | DepthRuleController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | damai | authz | DepthRuleController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | damai | authz | DepthRuleController.updateStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | damai | authz | OrderController.cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | damai | authz | OrderController.get | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 13 | damai | authz | OrderController.getCache | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 14 | damai | authz | OrderController.pay | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | damai | authz | OrderController.payCheck | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | damai | authz | OrderController.selectList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | damai | authz | PayController.commonPay | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | damai | authz | PayController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 19 | damai | authz | PayController.notify | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | damai | authz | PayController.refund | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | damai | authz | PayController.tradeCheck | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | damai | authz | ProgramCategoryController.saveBatch | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | damai | authz | ProgramCategoryController.selectByParentProgramCategoryId | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 24 | damai | authz | ProgramCategoryController.selectByType | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 25 | damai | authz | ProgramController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 26 | damai | authz | ProgramController.recommendList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 27 | damai | authz | ProgramController.search | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 28 | damai | authz | ProgramController.selectHomeList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 29 | damai | authz | ProgramController.selectPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 30 | damai | authz | ProgramShowTimeController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 31 | damai | authz | RuleController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 32 | damai | authz | RuleController.get | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 33 | damai | authz | RuleController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 34 | damai | authz | RuleController.updateStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 35 | damai | authz | SeatController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 36 | damai | authz | SeatController.batchAdd | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 37 | damai | authz | SeatController.relateInfo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 38 | damai | authz | TestController.reset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 39 | damai | authz | TicketCategoryController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 40 | damai | authz | TicketCategoryController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 41 | damai | authz | TicketCategoryController.selectListByProgram | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 42 | damai | authz | TicketUserController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 43 | damai | authz | TicketUserController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 44 | damai | authz | TicketUserController.list | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 45 | damai | authz | UserCaptchaController.getCaptcha | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 46 | damai | authz | UserCaptchaController.verifyCaptcha | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 47 | damai | authz | UserController.authentication | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 48 | damai | authz | UserController.exist | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 49 | damai | authz | UserController.logout | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 50 | damai | authz | UserController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 51 | damai | authz | UserController.updateEmail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 52 | damai | authz | UserController.updateMobile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 53 | damai | authz | UserController.updatePassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 54 | dify-for-dsl | authz | get_course_top_students | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 55 | dify-for-dsl | authz | get_student_scores | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 56 | dify-for-dsl | cmdi | upload_video | **UNKNOWN** | — | NO_CMD_SINK: 入口文件无任何命令执行调用（os.system/subprocess/asyncio.create_subprocess），cmdi 来自切片里未被入口调用的辅助函数 | — |
| 57 | dify-for-dsl | log_injection | api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 58 | dify-for-dsl | log_injection | generate_audio | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 59 | dify-for-dsl | log_injection | generate_edit_image | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 60 | dify-for-dsl | log_injection | generate_edit_image | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 61 | dify-for-dsl | log_injection | generate_edit_image | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 62 | dify-for-dsl | log_injection | generate_hidream_e1 | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 63 | dify-for-dsl | log_injection | generate_image | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 64 | dify-for-dsl | log_injection | generate_image | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 65 | dify-for-dsl | log_injection | generate_image | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 66 | dify-for-dsl | log_injection | process_data | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 67 | dify-for-dsl | log_injection | process_data | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 68 | dify-for-dsl | unrestricted_upload | upload | **UNKNOWN** | — | NON_EXECUTABLE_UPLOAD: 已防路径穿越 / 已做扩展名白名单+固定命名，落盘目录非 Web 静态挂载（无 StaticFiles/addResourceHandlers 指向上传目录），上传物不可执行 | — |
| 69 | dify-for-dsl | unrestricted_upload | upload_video | **UNKNOWN** | — | NON_EXECUTABLE_UPLOAD: 已防路径穿越 / 已做扩展名白名单+固定命名，落盘目录非 Web 静态挂载（无 StaticFiles/addResourceHandlers 指向上传目录），上传物不可执行 | — |
| 70 | dify-plus | authz | AccountSessionByIdApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 71 | dify-plus | authz | AgentConfigDownloadRequestApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 72 | dify-plus | authz | AgentConfigEnvApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 73 | dify-plus | authz | AgentConfigManifestApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 74 | dify-plus | authz | AgentConfigNoteApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 75 | dify-plus | authz | AgentConfigPushApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 76 | dify-plus | authz | AgentConfigSkillInspectApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 77 | dify-plus | authz | AnnotationReplyActionStatusApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 78 | dify-plus | authz | AnnotationUpdateDeleteApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 79 | dify-plus | authz | ApiKeyAuthDataSourceBindingDelete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 80 | dify-plus | authz | AppDslCheckDependenciesApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 81 | dify-plus | authz | AppDslImportConfirmApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 82 | dify-plus | authz | AppRunApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 83 | dify-plus | authz | AppRunTaskStopApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 84 | dify-plus | authz | AppSite | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 85 | dify-plus | authz | AppSiteAccessTokenReset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 86 | dify-plus | authz | ChatStopApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 87 | dify-plus | authz | CompletionStopApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 88 | dify-plus | authz | ConsoleWorkflowPauseDetailsApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 89 | dify-plus | authz | ConversationApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 90 | dify-plus | authz | ConversationDetailApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 91 | dify-plus | authz | ConversationPinApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 92 | dify-plus | authz | ConversationUnPinApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 93 | dify-plus | authz | ConversationVariablesApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 94 | dify-plus | authz | DatasetMetadataBuiltInFieldServiceApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 95 | dify-plus | authz | DocumentApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 96 | dify-plus | authz | DocumentDownloadApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 97 | dify-plus | authz | DocumentListApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 98 | dify-plus | authz | EndUserApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 99 | dify-plus | authz | EnterpriseAppDSLExport | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 100 | dify-plus | authz | EnterpriseAppDSLImport | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 101 | dify-plus | authz | FilePreviewApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 102 | dify-plus | authz | FilePreviewApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 103 | dify-plus | authz | FilePreviewApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 104 | dify-plus | authz | GrantedFileContentApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 105 | dify-plus | authz | ImagePreviewApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 106 | dify-plus | authz | InstalledAppWorkflowTaskStopApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 107 | dify-plus | authz | MessageFeedbackApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 108 | dify-plus | authz | MessageFeedbackApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 109 | dify-plus | authz | MessageMoreLikeThisApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 110 | dify-plus | authz | MessageSuggestedApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 111 | dify-plus | authz | MessageSuggestedQuestionApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 112 | dify-plus | authz | ModelProviderIconApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 113 | dify-plus | authz | OAuthDataSourceSync | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 114 | dify-plus | authz | OpenApiWorkflowEventsApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 115 | dify-plus | authz | OpenApiWorkflowHumanInputFormApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 116 | dify-plus | authz | PartnerTenants | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 117 | dify-plus | authz | PermittedExternalAppDescribeApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 118 | dify-plus | authz | PublishedSkillPullApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 119 | dify-plus | authz | RecentAppListApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 120 | dify-plus | authz | RecommendedAppApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 121 | dify-plus | authz | SavedMessageApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 122 | dify-plus | authz | ToolFileApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 123 | dify-plus | authz | TraceAppConfigApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 124 | dify-plus | authz | WorkflowEventsApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 125 | dify-plus | authz | WorkflowRunArchiveDownloadApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 126 | dify-plus | authz | WorkflowRunArchiveDownloadFileApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 127 | dify-plus | authz | WorkflowRunDetailApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 128 | dify-plus | authz | WorkflowRunNodeExecutionListApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 129 | dify-plus | authz | WorkspaceAgentSkillBindingsApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 130 | dify-plus | authz | WorkspaceByIdApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 131 | dify-plus | authz | WorkspaceMemberApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 132 | dify-plus | authz | WorkspaceSkillApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 133 | dify-plus | authz | WorkspaceSkillAssistMessageApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 134 | dify-plus | authz | WorkspaceSkillDuplicateApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 135 | dify-plus | authz | WorkspaceSkillExportApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 136 | dify-plus | authz | WorkspaceSkillFileContentApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 137 | dify-plus | authz | WorkspaceSkillFilePreviewApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 138 | dify-plus | authz | WorkspaceSkillFilesApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 139 | dify-plus | authz | WorkspaceSkillFilesCheckApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 140 | dify-plus | authz | WorkspaceSkillPublishApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 141 | dify-plus | authz | WorkspaceSkillReferencesApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 142 | dify-plus | authz | WorkspaceSkillRestoreApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 143 | dify-plus | authz | WorkspaceSkillVersionApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 144 | dify-plus | authz | WorkspaceSkillVersionsApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 145 | dify-plus | authz | WorkspaceSwitchApi | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 146 | dify-plus | authz | get_run_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 147 | dify-plus | authz | get_run_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 148 | dify-plus | authz | handle_webhook | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 149 | dify-plus | authz | handle_webhook_debug | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 150 | dify-plus | authz | stream_run_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 151 | dify-plus | cmdi | health | **UNKNOWN** | — | NO_CMD_SINK: 入口文件无任何命令执行调用（os.system/subprocess/asyncio.create_subprocess），cmdi 来自切片里未被入口调用的辅助函数 | — |
| 152 | product-apim | authz | PeopleRestService.addPerson | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 153 | product-apim | authz | PeopleRestService.addPerson#2 | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 154 | product-apim | authz | PeopleRestService.addPersonQueryParam | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 155 | product-apim | authz | PeopleRestService.deletePerson | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 156 | product-apim | authz | PeopleRestService.getPeople#2 | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 157 | product-apim | authz | PeopleRestService.updatePerson | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 158 | product-apim | authz | PeopleRestService.updatePersonQueryParam | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 159 | product-apim | log_injection | recommend_apis | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 160 | product-apim | log_injection | recommend_apis | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 161 | product-apim | log_injection | recommend_apis | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 162 | product-apim | log_injection | recommend_apis | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 11 |
| B（其余状态） | 162 |
| 合计 | 173 |
