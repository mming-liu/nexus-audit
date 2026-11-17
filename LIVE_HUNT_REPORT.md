# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-17 10:09:34
- 总条数：33 ｜ 板块 A：**6** ｜ 板块 B：**27**
- 状态计数：ZERO_RECORD_FRESH 6 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 27

<!-- live_hunt_counts: {"BOARD_A": 6, "BOARD_B": 27, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 27, "ZERO_RECORD_FRESH": 6} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 19 个缓存。

- 候选仓：19 ｜ 实扫：5 ｜ 跳过：12 ｜ 失败：2 ｜ 候选来源：github_search
- 本次新增根因：33 ｜ 板块 A：6 ｜ 拦截进 B：27
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：1 个

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| w8123/EnterpriseAgentFramework | 4ddeb5d8894d | SCANNED | 5 |
| SemiAnalysisAI/InferenceX | 5146af7ab7bb | SKIPPED (low_units_1) | 0 |
| zeasin/qihang-erp-open | 40a16a87fc8f | SCANNED | 4 |
| christopherowen/spark-ds41f |  | FAILED (TimeoutExpired: Command '['C:\\Users\\ee) | 0 |
| s-pms/SPMS-Server | 23a4b0b9570c | SCANNED | 10 |
| jaylfc/taOS |  | FAILED (TimeoutExpired: Command '['C:\\Users\\ee) | 0 |
| eugr/spark-vllm-docker | ba3011572f2a | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| vllm-project/llm-compressor | 385fab4aca40 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| noonghunna/club-3090 | a7b0510e282a | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| fsdatalab/quail | d238e8f05975 | SKIPPED (low_units_1) | 0 |
| 1CatAI/1Cat-vLLM | 2d05ba9d8102 | SCANNED | 8 |
| vllm-project/tpu-inference | d9c7e19da8c4 | SKIPPED (low_units_3) | 0 |
| yhfgyyf/vllm-deepseek-v4-sm89 | 1f77384f331f | SCANNED | 6 |
| InferMatrixLab/vllm-rlt | c338aaa32f24 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| adventists-ai/sophon-realtime | 2c48aa543fe6 | SKIPPED (low_units_3) | 0 |
| hasso5703/alzeo | 39e2d3c03135 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| Valen-Team/Valen | f6df4fdbc45b | SKIPPED (low_units_2) | 0 |
| lightseekorg/TorchSpec | 17e971b8fd2e | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| containers/ramalama | 58c808965f18 | SKIPPED (low_units_7) | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | EnterpriseAgentFramework | spel | RuntimePageWorkbenchInternalController.executionReadiness | — | 2026-11-15 (1.5d) | 4ddeb5d8894d | [reachai-runtime-service/src/main/java/com/enterprise/ai/runtime/internal/RuntimePageWorkbenchInternalController.java:85](https://github.com/w8123/EnterpriseAgentFramework/blob/4ddeb5d8894d2ad7e931a09e20f5197ab384f8cd/reachai-runtime-service/src/main/java/com/enterprise/ai/runtime/internal/RuntimePageWorkbenchInternalController.java#L85) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_spel_executionReadiness/SUBMISSION_PLAYBOOK.md) |
| 2 | SPMS-Server | redir | FileController.getFileUrl | — | 2026-10-14 (33.7d) | 23a4b0b9570c | [src/main/java/cn/hamm/spms/module/system/file/FileController.java:56](https://github.com/s-pms/SPMS-Server/blob/23a4b0b9570cc79c8a9090563f60817f2165dce8/src/main/java/cn/hamm/spms/module/system/file/FileController.java#L56) | [Advisory](https://github.com/s-pms/SPMS-Server/security/advisories/new) · [Issue](https://github.com/s-pms/SPMS-Server/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/SPMS-Server_redir_getFileUrl/SUBMISSION_PLAYBOOK.md) |
| 3 | qihang-erp-open | hash | PurchaseOrderController.add | — | 2026-11-06 (10.5d) | 40a16a87fc8f | [erp-api/src/main/java/cn/qihangerp/erp/controller/erp/PurchaseOrderController.java:68](https://github.com/zeasin/qihang-erp-open/blob/40a16a87fc8ff6f948c1cf376cdae5e4bfb3e75b/erp-api/src/main/java/cn/qihangerp/erp/controller/erp/PurchaseOrderController.java#L68) | [Advisory](https://github.com/zeasin/qihang-erp-open/security/advisories/new) · [Issue](https://github.com/zeasin/qihang-erp-open/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/qihang-erp-open_hash_add/SUBMISSION_PLAYBOOK.md) |
| 4 | qihang-erp-open | hash | ShipRecordController.recordList | — | 2026-11-06 (10.5d) | 40a16a87fc8f | [erp-api/src/main/java/cn/qihangerp/erp/controller/erp/ShipRecordController.java:37](https://github.com/zeasin/qihang-erp-open/blob/40a16a87fc8ff6f948c1cf376cdae5e4bfb3e75b/erp-api/src/main/java/cn/qihangerp/erp/controller/erp/ShipRecordController.java#L37) | [Advisory](https://github.com/zeasin/qihang-erp-open/security/advisories/new) · [Issue](https://github.com/zeasin/qihang-erp-open/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/qihang-erp-open_hash_recordList/SUBMISSION_PLAYBOOK.md) |
| 5 | qihang-erp-open | hash | ShopOrderController.pullDetail | — | 2026-11-06 (10.5d) | 40a16a87fc8f | [erp-api/src/main/java/cn/qihangerp/erp/controller/oms/ShopOrderController.java:87](https://github.com/zeasin/qihang-erp-open/blob/40a16a87fc8ff6f948c1cf376cdae5e4bfb3e75b/erp-api/src/main/java/cn/qihangerp/erp/controller/oms/ShopOrderController.java#L87) | [Advisory](https://github.com/zeasin/qihang-erp-open/security/advisories/new) · [Issue](https://github.com/zeasin/qihang-erp-open/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/qihang-erp-open_hash_pullDetail/SUBMISSION_PLAYBOOK.md) |
| 6 | qihang-erp-open | hash | ShopRefundController.pullDetail | — | 2026-11-06 (10.5d) | 40a16a87fc8f | [erp-api/src/main/java/cn/qihangerp/erp/controller/oms/ShopRefundController.java:55](https://github.com/zeasin/qihang-erp-open/blob/40a16a87fc8ff6f948c1cf376cdae5e4bfb3e75b/erp-api/src/main/java/cn/qihangerp/erp/controller/oms/ShopRefundController.java#L55) | [Advisory](https://github.com/zeasin/qihang-erp-open/security/advisories/new) · [Issue](https://github.com/zeasin/qihang-erp-open/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/qihang-erp-open_hash_pullDetail/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | 1Cat-vLLM | authz | cancel_responses | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | 1Cat-vLLM | authz | create | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | 1Cat-vLLM | authz | retrieve_responses | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | 1Cat-vLLM | log_injection | reset_encoder_cache | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 5 | 1Cat-vLLM | log_injection | reset_mm_cache | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 6 | 1Cat-vLLM | log_injection | reset_prefix_cache | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 7 | 1Cat-vLLM | log_injection | start_profile | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 8 | 1Cat-vLLM | log_injection | stop_profile | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 9 | EnterpriseAgentFramework | authz | RuntimePageAssistantWorkflowController.attach | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | EnterpriseAgentFramework | authz | RuntimePageAssistantWorkflowController.context | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | EnterpriseAgentFramework | authz | invoke | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | EnterpriseAgentFramework | unchecked_low_level_calls | RuntimePublicController.clearAgentSession | **UNKNOWN** | — | RULE_LANGUAGE_MISMATCH: unchecked_low_level_calls 是 Solidity 类目，入口文件是 .java | — |
| 13 | SPMS-Server | authz | BaseBillController.addFinish | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 14 | SPMS-Server | authz | DeviceController.getDeviceConfig | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | SPMS-Server | authz | DeviceController.getDevicePayloadHistory | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | SPMS-Server | authz | FileController.upload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | SPMS-Server | authz | OrderController.addOrderDetail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | SPMS-Server | authz | RoleController.authorizeMenu | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 19 | SPMS-Server | authz | RoleController.authorizePermission | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | SPMS-Server | authz | RoomController.create | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | SPMS-Server | authz | UserController.updateMyInfo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | vllm-deepseek-v4-sm89 | log_injection | create_score_v1 | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 23 | vllm-deepseek-v4-sm89 | log_injection | reset_encoder_cache | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 24 | vllm-deepseek-v4-sm89 | log_injection | reset_mm_cache | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 25 | vllm-deepseek-v4-sm89 | log_injection | reset_prefix_cache | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 26 | vllm-deepseek-v4-sm89 | log_injection | start_profile | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 27 | vllm-deepseek-v4-sm89 | log_injection | stop_profile | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 6 |
| B（其余状态） | 27 |
| 合计 | 33 |
