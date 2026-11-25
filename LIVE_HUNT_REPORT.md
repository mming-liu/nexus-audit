# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-25 09:10:27
- 总条数：397 ｜ 板块 A：**4** ｜ 板块 B：**393**
- 状态计数：ZERO_RECORD_FRESH 4 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 43 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 350

<!-- live_hunt_counts: {"BOARD_A": 4, "BOARD_B": 393, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 43, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 350, "ZERO_RECORD_FRESH": 4} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 0 个缓存。

- 候选仓：23（已处理 14） ｜ 实扫：6 ｜ 跳过：8 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：397 ｜ 板块 A：4 ｜ 拦截进 B：393
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：0 个

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| liyupi/yu-picture | 9e6a16e93fe2 | SCANNED | 37 |
| zgraham1981/Stablecoin-Payment-Gateway | 0e7e9a65dd7e | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| xiaonuobase/Snowy | ec938f39d6e7 | SKIPPED (unchanged_head) | 0 |
| Yinglianchun/Serein | 43dfa5b7efb7 | SCANNED | 23 |
| java-up-up/damai | e4c68a1b451e | SCANNED | 53 |
| aio-libs/multidict | d02731e26acc | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| marshmallow-code/webargs | 686c5cd2cb12 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| agentic-community/mcp-gateway-registry | d344af4beecd | SCANNED | 215 |
| JJJJSTIYYYY/alira | 13d125f25d84 | SKIPPED (low_units_1) | 0 |
| niyouqianma/workbuddy2api-hub | 22254ab84752 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| slackapi/bolt-python | 16056a48efcd | SKIPPED (low_units_2) | 0 |
| shazamio/ShazamIO | ff2d6ea403c7 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| schmitech/orbit | 6f1490d063d1 | SCANNED | 61 |
| dengyie/zcode2api | 7b7162ff4d94 | SCANNED | 8 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | yu-picture | header_injection | FileController.testDownloadFile | — | 2026-11-23 (1.8d) | 9e6a16e93fe2 | [yu-picture-backend-ddd/src/main/java/com/yupi/yupicture/interfaces/controller/FileController.java:70](https://github.com/liyupi/yu-picture/blob/9e6a16e93fe2e0c3ee9882b253324641fb8c6edb/yu-picture-backend-ddd/src/main/java/com/yupi/yupicture/interfaces/controller/FileController.java#L70) | [Advisory](https://github.com/liyupi/yu-picture/security/advisories/new) · [Issue](https://github.com/liyupi/yu-picture/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/yu-picture_header_injection_testDownloadFile/SUBMISSION_PLAYBOOK.md) |
| 2 | yu-picture | unrestricted_upload | FileController.testUploadFile | — | 2026-11-23 (1.8d) | 9e6a16e93fe2 | [yu-picture-backend-ddd/src/main/java/com/yupi/yupicture/interfaces/controller/FileController.java:36](https://github.com/liyupi/yu-picture/blob/9e6a16e93fe2e0c3ee9882b253324641fb8c6edb/yu-picture-backend-ddd/src/main/java/com/yupi/yupicture/interfaces/controller/FileController.java#L36) | [Advisory](https://github.com/liyupi/yu-picture/security/advisories/new) · [Issue](https://github.com/liyupi/yu-picture/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/yu-picture_unrestricted_upload_testUploadFile/SUBMISSION_PLAYBOOK.md) |
| 3 | yu-picture | unrestricted_upload | FileController.testUploadFile | — | 2026-11-23 (1.8d) | 9e6a16e93fe2 | [yu-picture-backend/src/main/java/com/yupi/yupicturebackend/controller/FileController.java:37](https://github.com/liyupi/yu-picture/blob/9e6a16e93fe2e0c3ee9882b253324641fb8c6edb/yu-picture-backend/src/main/java/com/yupi/yupicturebackend/controller/FileController.java#L37) | [Advisory](https://github.com/liyupi/yu-picture/security/advisories/new) · [Issue](https://github.com/liyupi/yu-picture/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/yu-picture_unrestricted_upload_testUploadFile/SUBMISSION_PLAYBOOK.md) |
| 4 | yu-picture | xss | FileController.testUploadFile | — | 2026-11-23 (1.8d) | 9e6a16e93fe2 | [yu-picture-backend-ddd/src/main/java/com/yupi/yupicture/interfaces/controller/FileController.java:36](https://github.com/liyupi/yu-picture/blob/9e6a16e93fe2e0c3ee9882b253324641fb8c6edb/yu-picture-backend-ddd/src/main/java/com/yupi/yupicture/interfaces/controller/FileController.java#L36) | [Advisory](https://github.com/liyupi/yu-picture/security/advisories/new) · [Issue](https://github.com/liyupi/yu-picture/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/yu-picture_xss_testUploadFile/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | Serein | authz | active_leaf | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | Serein | authz | call | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | Serein | authz | chat | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | Serein | authz | delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | Serein | authz | delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | Serein | authz | delete_memo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | Serein | authz | dream | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | Serein | authz | edges | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | Serein | authz | edit_memo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | Serein | authz | history | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | Serein | authz | history | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | Serein | authz | inbox | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 13 | Serein | authz | pending_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 14 | Serein | authz | pipeline_attempt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | Serein | authz | proposals | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | Serein | authz | read_persona | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | Serein | authz | restore | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | Serein | authz | review | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 19 | Serein | authz | revision_materials | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | Serein | authz | save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | Serein | authz | shadows | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | Serein | authz | status_memo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | Serein | authz | write | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 24 | damai | authz | AllRuleController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 25 | damai | authz | ApiDataController.pageList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 26 | damai | authz | AreaController.getById | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 27 | damai | authz | AreaController.selectByIdList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 28 | damai | authz | BroadcastController.call | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 29 | damai | authz | ChannelDataController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 30 | damai | authz | ChannelDataController.getByCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 31 | damai | authz | DepthRuleController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 32 | damai | authz | DepthRuleController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 33 | damai | authz | DepthRuleController.updateStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 34 | damai | authz | OrderController.cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 35 | damai | authz | OrderController.get | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 36 | damai | authz | OrderController.getCache | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 37 | damai | authz | OrderController.pay | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 38 | damai | authz | OrderController.payCheck | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 39 | damai | authz | OrderController.selectList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 40 | damai | authz | PayController.commonPay | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 41 | damai | authz | PayController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 42 | damai | authz | PayController.notify | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 43 | damai | authz | PayController.refund | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 44 | damai | authz | PayController.tradeCheck | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 45 | damai | authz | ProgramCategoryController.saveBatch | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 46 | damai | authz | ProgramCategoryController.selectByParentProgramCategoryId | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 47 | damai | authz | ProgramCategoryController.selectByType | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 48 | damai | authz | ProgramController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 49 | damai | authz | ProgramController.recommendList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 50 | damai | authz | ProgramController.search | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 51 | damai | authz | ProgramController.selectHomeList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 52 | damai | authz | ProgramController.selectPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 53 | damai | authz | ProgramShowTimeController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 54 | damai | authz | RuleController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 55 | damai | authz | RuleController.get | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 56 | damai | authz | RuleController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 57 | damai | authz | RuleController.updateStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 58 | damai | authz | SeatController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 59 | damai | authz | SeatController.batchAdd | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 60 | damai | authz | SeatController.relateInfo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 61 | damai | authz | TestController.reset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 62 | damai | authz | TicketCategoryController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 63 | damai | authz | TicketCategoryController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 64 | damai | authz | TicketCategoryController.selectListByProgram | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 65 | damai | authz | TicketUserController.add | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 66 | damai | authz | TicketUserController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 67 | damai | authz | TicketUserController.list | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 68 | damai | authz | UserCaptchaController.getCaptcha | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 69 | damai | authz | UserCaptchaController.verifyCaptcha | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 70 | damai | authz | UserController.authentication | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 71 | damai | authz | UserController.exist | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 72 | damai | authz | UserController.logout | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 73 | damai | authz | UserController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 74 | damai | authz | UserController.updateEmail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 75 | damai | authz | UserController.updateMobile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 76 | damai | authz | UserController.updatePassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 77 | mcp-gateway-registry | authz | add_ai_catalog_source | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 78 | mcp-gateway-registry | authz | add_anthropic_server | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 79 | mcp-gateway-registry | authz | add_asor_agent | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 80 | mcp-gateway-registry | authz | add_aws_registry | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 81 | mcp-gateway-registry | authz | add_openapi_target | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 82 | mcp-gateway-registry | authz | add_quarantine | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 83 | mcp-gateway-registry | authz | add_server_to_groups_api | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 84 | mcp-gateway-registry | authz | api_check_availability | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 85 | mcp-gateway-registry | authz | api_check_prices | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 86 | mcp-gateway-registry | authz | api_reserve_flight | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 87 | mcp-gateway-registry | authz | create_group_api | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 88 | mcp-gateway-registry | authz | create_pingfederate_user | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 89 | mcp-gateway-registry | authz | delete_backend_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 90 | mcp-gateway-registry | authz | delete_custom_entity | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 91 | mcp-gateway-registry | authz | delete_custom_type | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 92 | mcp-gateway-registry | authz | delete_federation_config | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 93 | mcp-gateway-registry | authz | delete_group_api | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 94 | mcp-gateway-registry | authz | delete_m2m_client | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 95 | mcp-gateway-registry | authz | delete_openapi_server | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 96 | mcp-gateway-registry | authz | delete_openapi_target | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 97 | mcp-gateway-registry | authz | delete_peer | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 98 | mcp-gateway-registry | authz | delete_rate_limit | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 99 | mcp-gateway-registry | authz | delete_rate_limit_membership | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 100 | mcp-gateway-registry | authz | delete_user_group | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 101 | mcp-gateway-registry | authz | disable_peer | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 102 | mcp-gateway-registry | authz | edit_server_submit | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 103 | mcp-gateway-registry | authz | enable_peer | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 104 | mcp-gateway-registry | authz | export_logs | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 105 | mcp-gateway-registry | authz | flush_metrics | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 106 | mcp-gateway-registry | authz | get_agent_batch_job | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 107 | mcp-gateway-registry | authz | get_backend_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 108 | mcp-gateway-registry | authz | get_client_groups | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 109 | mcp-gateway-registry | authz | get_client_groups | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 110 | mcp-gateway-registry | authz | get_custom_entity | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 111 | mcp-gateway-registry | authz | get_custom_entity_rating | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 112 | mcp-gateway-registry | authz | get_custom_type | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 113 | mcp-gateway-registry | authz | get_federation_config | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 114 | mcp-gateway-registry | authz | get_group_api | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 115 | mcp-gateway-registry | authz | get_m2m_client | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 116 | mcp-gateway-registry | authz | get_openapi_server | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 117 | mcp-gateway-registry | authz | get_openapi_target | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 118 | mcp-gateway-registry | authz | get_peer | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 119 | mcp-gateway-registry | authz | get_peer_connections | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 120 | mcp-gateway-registry | authz | get_peer_shared_resources | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 121 | mcp-gateway-registry | authz | get_peer_status | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 122 | mcp-gateway-registry | authz | get_rate_limit | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 123 | mcp-gateway-registry | authz | get_rate_limit_membership | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 124 | mcp-gateway-registry | authz | get_user_group | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 125 | mcp-gateway-registry | authz | internal_add_server_to_groups | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 126 | mcp-gateway-registry | authz | internal_create_group | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 127 | mcp-gateway-registry | authz | internal_register_service | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 128 | mcp-gateway-registry | authz | internal_remove_server_from_groups | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 129 | mcp-gateway-registry | authz | list_my_credentials | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 130 | mcp-gateway-registry | authz | management_delete_group | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 131 | mcp-gateway-registry | authz | management_delete_user | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 132 | mcp-gateway-registry | authz | management_get_group | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 133 | mcp-gateway-registry | authz | management_update_group | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 134 | mcp-gateway-registry | authz | management_update_user_groups | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 135 | mcp-gateway-registry | authz | mcp_proxy | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 136 | mcp-gateway-registry | authz | patch_m2m_client | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 137 | mcp-gateway-registry | authz | patch_user_group | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 138 | mcp-gateway-registry | authz | put_rate_limit | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 139 | mcp-gateway-registry | authz | put_rate_limit_membership | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 140 | mcp-gateway-registry | authz | query_logs | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 141 | mcp-gateway-registry | authz | rate_custom_entity | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 142 | mcp-gateway-registry | authz | rate_limit_status | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 143 | mcp-gateway-registry | authz | register_service | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 144 | mcp-gateway-registry | authz | register_service_api | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 145 | mcp-gateway-registry | authz | remove_ai_catalog_source | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 146 | mcp-gateway-registry | authz | remove_anthropic_server | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 147 | mcp-gateway-registry | authz | remove_asor_agent | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 148 | mcp-gateway-registry | authz | remove_aws_registry | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 149 | mcp-gateway-registry | authz | remove_quarantine | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 150 | mcp-gateway-registry | authz | remove_server_from_groups_api | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 151 | mcp-gateway-registry | authz | run_cleanup | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 152 | mcp-gateway-registry | authz | save_federation_config | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 153 | mcp-gateway-registry | authz | serve_branding_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 154 | mcp-gateway-registry | authz | set_rate_limit_enabled | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 155 | mcp-gateway-registry | authz | store_backend_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 156 | mcp-gateway-registry | authz | sync_ai_catalog | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 157 | mcp-gateway-registry | authz | sync_federation | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 158 | mcp-gateway-registry | authz | sync_peer | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 159 | mcp-gateway-registry | authz | update_client_groups | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 160 | mcp-gateway-registry | authz | update_client_groups | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 161 | mcp-gateway-registry | authz | update_custom_entity | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 162 | mcp-gateway-registry | authz | update_custom_entity_upstream_headers | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 163 | mcp-gateway-registry | authz | update_custom_type | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 164 | mcp-gateway-registry | authz | update_federation_config | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 165 | mcp-gateway-registry | authz | update_openapi_server | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 166 | mcp-gateway-registry | authz | update_openapi_target | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 167 | mcp-gateway-registry | authz | update_peer | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 168 | mcp-gateway-registry | authz | update_peer_token | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 169 | mcp-gateway-registry | authz | update_retention_policy | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 170 | mcp-gateway-registry | authz | validate_client_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 171 | mcp-gateway-registry | log_injection | add_ai_catalog_source | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 172 | mcp-gateway-registry | log_injection | add_anthropic_server | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 173 | mcp-gateway-registry | log_injection | add_asor_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 174 | mcp-gateway-registry | log_injection | add_aws_registry | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 175 | mcp-gateway-registry | log_injection | add_server_to_groups_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 176 | mcp-gateway-registry | log_injection | api_cancel_reservation | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 177 | mcp-gateway-registry | log_injection | api_check_availability | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 178 | mcp-gateway-registry | log_injection | api_check_prices | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 179 | mcp-gateway-registry | log_injection | api_confirm_booking | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 180 | mcp-gateway-registry | log_injection | api_create_trip_plan | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 181 | mcp-gateway-registry | log_injection | api_discover_agents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 182 | mcp-gateway-registry | log_injection | api_get_reservation | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 183 | mcp-gateway-registry | log_injection | api_process_payment | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 184 | mcp-gateway-registry | log_injection | api_recommendations | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 185 | mcp-gateway-registry | log_injection | api_reserve_flight | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 186 | mcp-gateway-registry | log_injection | api_search_flights | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 187 | mcp-gateway-registry | log_injection | check_agent_health | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 188 | mcp-gateway-registry | log_injection | clear_security_pending_local | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 189 | mcp-gateway-registry | log_injection | collect_metrics | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 190 | mcp-gateway-registry | log_injection | create_client_session | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 191 | mcp-gateway-registry | log_injection | create_group_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 192 | mcp-gateway-registry | log_injection | create_peer | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 193 | mcp-gateway-registry | log_injection | delete_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 194 | mcp-gateway-registry | log_injection | delete_federation_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 195 | mcp-gateway-registry | log_injection | delete_group_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 196 | mcp-gateway-registry | log_injection | delete_peer | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 197 | mcp-gateway-registry | log_injection | disable_peer | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 198 | mcp-gateway-registry | log_injection | discover_agents_by_skills | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 199 | mcp-gateway-registry | log_injection | discover_agents_semantic | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 200 | mcp-gateway-registry | log_injection | edit_server_form | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 201 | mcp-gateway-registry | log_injection | edit_server_submit | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 202 | mcp-gateway-registry | log_injection | egress_callback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 203 | mcp-gateway-registry | log_injection | enable_peer | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 204 | mcp-gateway-registry | log_injection | export_agents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 205 | mcp-gateway-registry | log_injection | export_audit_events | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 206 | mcp-gateway-registry | log_injection | export_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 207 | mcp-gateway-registry | log_injection | export_security_scans | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 208 | mcp-gateway-registry | log_injection | export_servers | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 209 | mcp-gateway-registry | log_injection | generate_user_token | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 210 | mcp-gateway-registry | log_injection | generate_user_token | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 211 | mcp-gateway-registry | log_injection | get_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 212 | mcp-gateway-registry | log_injection | get_audit_event | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 213 | mcp-gateway-registry | log_injection | get_audit_events | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 214 | mcp-gateway-registry | log_injection | get_federation_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 215 | mcp-gateway-registry | log_injection | get_group_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 216 | mcp-gateway-registry | log_injection | get_peer | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 217 | mcp-gateway-registry | log_injection | get_peer_connections | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 218 | mcp-gateway-registry | log_injection | get_peer_shared_resources | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 219 | mcp-gateway-registry | log_injection | get_peer_status | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 220 | mcp-gateway-registry | log_injection | get_server_canonical | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 221 | mcp-gateway-registry | log_injection | get_server_details | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 222 | mcp-gateway-registry | log_injection | get_server_version | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 223 | mcp-gateway-registry | log_injection | get_servers_json | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 224 | mcp-gateway-registry | log_injection | get_service_tools | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 225 | mcp-gateway-registry | log_injection | get_service_tools_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 226 | mcp-gateway-registry | log_injection | internal_add_server_to_groups | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 227 | mcp-gateway-registry | log_injection | internal_create_group | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 228 | mcp-gateway-registry | log_injection | internal_delete_group | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 229 | mcp-gateway-registry | log_injection | internal_list_groups | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 230 | mcp-gateway-registry | log_injection | internal_register_service | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 231 | mcp-gateway-registry | log_injection | internal_remove_server_from_groups | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 232 | mcp-gateway-registry | log_injection | internal_remove_service | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 233 | mcp-gateway-registry | log_injection | internal_toggle_service | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 234 | mcp-gateway-registry | log_injection | list_agents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 235 | mcp-gateway-registry | log_injection | list_federation_configs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 236 | mcp-gateway-registry | log_injection | list_groups_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 237 | mcp-gateway-registry | log_injection | list_peers | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 238 | mcp-gateway-registry | log_injection | list_server_versions | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 239 | mcp-gateway-registry | log_injection | list_servers | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 240 | mcp-gateway-registry | log_injection | list_skills | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 241 | mcp-gateway-registry | log_injection | list_virtual_servers | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 242 | mcp-gateway-registry | log_injection | management_create_m2m_user | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 243 | mcp-gateway-registry | log_injection | management_update_user_groups | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 244 | mcp-gateway-registry | log_injection | mcp_proxy | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 245 | mcp-gateway-registry | log_injection | oauth2_callback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 246 | mcp-gateway-registry | log_injection | oauth2_callback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 247 | mcp-gateway-registry | log_injection | oauth2_login | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 248 | mcp-gateway-registry | log_injection | oauth2_login_redirect | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 249 | mcp-gateway-registry | log_injection | oauth2_logout | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 250 | mcp-gateway-registry | log_injection | patch_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 251 | mcp-gateway-registry | log_injection | patch_server_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 252 | mcp-gateway-registry | log_injection | pull_agent_card | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 253 | mcp-gateway-registry | log_injection | rate_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 254 | mcp-gateway-registry | log_injection | rate_server | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 255 | mcp-gateway-registry | log_injection | rate_skill | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 256 | mcp-gateway-registry | log_injection | read_root | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 257 | mcp-gateway-registry | log_injection | record_export_audit_event | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 258 | mcp-gateway-registry | log_injection | refresh_service | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 259 | mcp-gateway-registry | log_injection | register_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 260 | mcp-gateway-registry | log_injection | register_service | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 261 | mcp-gateway-registry | log_injection | register_service_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 262 | mcp-gateway-registry | log_injection | reload_scopes | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 263 | mcp-gateway-registry | log_injection | remove_ai_catalog_source | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 264 | mcp-gateway-registry | log_injection | remove_anthropic_server | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 265 | mcp-gateway-registry | log_injection | remove_asor_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 266 | mcp-gateway-registry | log_injection | remove_aws_registry | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 267 | mcp-gateway-registry | log_injection | remove_server_from_groups_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 268 | mcp-gateway-registry | log_injection | remove_server_version | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 269 | mcp-gateway-registry | log_injection | remove_service_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 270 | mcp-gateway-registry | log_injection | rescan_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 271 | mcp-gateway-registry | log_injection | rescan_server | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 272 | mcp-gateway-registry | log_injection | save_federation_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 273 | mcp-gateway-registry | log_injection | set_cloud_provider_hint | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 274 | mcp-gateway-registry | log_injection | set_default_version | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 275 | mcp-gateway-registry | log_injection | sync_federation | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 276 | mcp-gateway-registry | log_injection | sync_peer | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 277 | mcp-gateway-registry | log_injection | toggle_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 278 | mcp-gateway-registry | log_injection | toggle_service_api | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 279 | mcp-gateway-registry | log_injection | toggle_service_route | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 280 | mcp-gateway-registry | log_injection | update_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 281 | mcp-gateway-registry | log_injection | update_custom_type | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 282 | mcp-gateway-registry | log_injection | update_federation_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 283 | mcp-gateway-registry | log_injection | update_peer | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 284 | mcp-gateway-registry | log_injection | update_peer_token | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 285 | mcp-gateway-registry | log_injection | update_server_auth_credential | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 286 | mcp-gateway-registry | log_injection | update_server_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 287 | mcp-gateway-registry | log_injection | update_skill | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 288 | mcp-gateway-registry | log_injection | validate_request | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 289 | mcp-gateway-registry | log_injection | vend_egress_token | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 290 | mcp-gateway-registry | log_injection | vend_generic_upstream_headers | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 291 | mcp-gateway-registry | log_injection | websocket_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 292 | orbit | authz | associate_prompt_with_api_key | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 293 | orbit | authz | chat_endpoint | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 294 | orbit | authz | clear_chat_history | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 295 | orbit | authz | create_thread | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 296 | orbit | authz | delete_adapter | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 297 | orbit | authz | delete_conversation_with_files | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 298 | orbit | authz | delete_mcp_server | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 299 | orbit | authz | delete_prompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 300 | orbit | authz | delete_skill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 301 | orbit | authz | delete_thread | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 302 | orbit | authz | export_adapter | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 303 | orbit | authz | get_adapter_config_file | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 304 | orbit | authz | get_adapter_edit_form | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 305 | orbit | authz | get_adapter_entry | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 306 | orbit | authz | get_admin_job_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 307 | orbit | authz | get_api_key_quota | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 308 | orbit | authz | get_api_key_status | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 309 | orbit | authz | get_chat_history | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-vmr6-q95v-7f9q、GHSA-mqqp-549x-j92q | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-vmr6-q95v-7f9q, GHSA-mqqp-549x-j92q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 310 | orbit | authz | get_observability_usage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 311 | orbit | authz | get_session_feedback | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 312 | orbit | authz | get_skill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 313 | orbit | authz | get_thread | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 314 | orbit | authz | list_admin_audit_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 315 | orbit | authz | openai_chat_completions | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 316 | orbit | authz | post_admin_login | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 317 | orbit | authz | reset_api_key_quota | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 318 | orbit | authz | save_adapter_config_file | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 319 | orbit | authz | save_adapter_entry | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 320 | orbit | authz | submit_feedback | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 321 | orbit | authz | test_adapter_query | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 322 | orbit | authz | toggle_adapter_enabled | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 323 | orbit | authz | update_api_key | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 324 | orbit | authz | update_api_key_quota | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 325 | orbit | authz | update_config_section | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 326 | orbit | authz | update_mcp_server | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 327 | orbit | authz | update_skill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 328 | orbit | log_injection | chat_endpoint | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 329 | orbit | log_injection | delete_adapter | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w、GHSA-x7j2-phmx-4wmj、GHSA-f946-p3h8-h2f2、GHSA-w9xh-99x5-vrw5、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w, GHSA-x7j2-phmx-4wmj, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 330 | orbit | log_injection | delete_api_key | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 331 | orbit | log_injection | delete_file | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 332 | orbit | log_injection | get_adapter_full_history | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w） | https://api.github.com/repos/schmitech/orbit/security-advisories |
| 333 | orbit | log_injection | get_adapter_history | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-5wx2-h979-qq6w | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-5wx2-h979-qq6w） | https://api.github.com/repos/schmitech/orbit/security-advisories |
| 334 | orbit | log_injection | get_api_key_detail | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 335 | orbit | log_injection | get_api_key_status | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 336 | orbit | log_injection | get_file_content | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 337 | orbit | log_injection | get_user_by_username | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 338 | orbit | log_injection | list_user_sessions | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 339 | orbit | log_injection | login | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-vmr6-q95v-7f9q、GHSA-x7j2-phmx-4wmj | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-vmr6-q95v-7f9q, GHSA-x7j2-phmx-4wmj） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 340 | orbit | log_injection | post_admin_login_2fa | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 341 | orbit | log_injection | query_file | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 342 | orbit | log_injection | rename_api_key | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 343 | orbit | log_injection | renew_api_key | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 344 | orbit | log_injection | reprocess_file | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 345 | orbit | log_injection | reset_api_key_quota | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 346 | orbit | log_injection | revoke_user_session | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 347 | orbit | log_injection | stop_chat_stream | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-5wx2-h979-qq6w、GHSA-vmr6-q95v-7f9q、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-5wx2-h979-qq6w, GHSA-vmr6-q95v-7f9q） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 348 | orbit | log_injection | tail_log_file | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 349 | orbit | log_injection | update_api_key | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 350 | orbit | log_injection | update_api_key_quota | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2、GHSA-6v6x-gmh6-p6r2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 351 | orbit | log_injection | upload_file | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xxrm-2pxg-6j3f、GHSA-mqqp-549x-j92q、GHSA-f946-p3h8-h2f2 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xxrm-2pxg-6j3f, GHSA-mqqp-549x-j92q, GHSA-f946-p3h8-h2f2） | https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories、https://api.github.com/repos/schmitech/orbit/security-advisories |
| 352 | orbit | log_injection | websocket_metrics | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-8vxv-44px-mpw4 | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-8vxv-44px-mpw4） | https://api.github.com/repos/schmitech/orbit/security-advisories |
| 353 | yu-picture | authz | PictureController.doPictureReview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 354 | yu-picture | authz | PictureController.doPictureReview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 355 | yu-picture | authz | PictureController.listPictureByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 356 | yu-picture | authz | PictureController.listPictureByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 357 | yu-picture | authz | PictureController.listPictureVOByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 358 | yu-picture | authz | PictureController.listPictureVOByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 359 | yu-picture | authz | PictureController.listPictureVOByPageWithCache | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 360 | yu-picture | authz | PictureController.listPictureVOByPageWithCache | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 361 | yu-picture | authz | PictureController.uploadPictureByBatch | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 362 | yu-picture | authz | PictureController.uploadPictureByBatch | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 363 | yu-picture | authz | SpaceAnalyzeController.getSpaceCategoryAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 364 | yu-picture | authz | SpaceAnalyzeController.getSpaceCategoryAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 365 | yu-picture | authz | SpaceAnalyzeController.getSpaceRankAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 366 | yu-picture | authz | SpaceAnalyzeController.getSpaceRankAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 367 | yu-picture | authz | SpaceAnalyzeController.getSpaceSizeAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 368 | yu-picture | authz | SpaceAnalyzeController.getSpaceSizeAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 369 | yu-picture | authz | SpaceAnalyzeController.getSpaceTagAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 370 | yu-picture | authz | SpaceAnalyzeController.getSpaceTagAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 371 | yu-picture | authz | SpaceAnalyzeController.getSpaceUsageAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 372 | yu-picture | authz | SpaceAnalyzeController.getSpaceUsageAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 373 | yu-picture | authz | SpaceAnalyzeController.getSpaceUserAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 374 | yu-picture | authz | SpaceAnalyzeController.getSpaceUserAnalyze | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 375 | yu-picture | authz | SpaceController.addSpace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 376 | yu-picture | authz | SpaceController.addSpace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 377 | yu-picture | authz | SpaceController.listSpaceByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 378 | yu-picture | authz | SpaceController.listSpaceByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 379 | yu-picture | authz | SpaceController.listSpaceVOByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 380 | yu-picture | authz | SpaceController.listSpaceVOByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 381 | yu-picture | authz | UserController.deleteUser | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 382 | yu-picture | authz | UserController.listUserVOByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 383 | yu-picture | authz | UserController.listUserVOByPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 384 | yu-picture | log_injection | FileController.testDownloadFile | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 385 | yu-picture | log_injection | FileController.testDownloadFile | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 386 | zcode2api | authz | claim_job_result | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 387 | zcode2api | authz | claim_preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 388 | zcode2api | authz | coding_limits | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 389 | zcode2api | authz | edit_account | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 390 | zcode2api | authz | login_poll | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 391 | zcode2api | authz | refresh_one | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 392 | zcode2api | authz | rotate_fingerprint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 393 | zcode2api | authz | set_enabled | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 4 |
| B（其余状态） | 393 |
| 合计 | 397 |
