# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-20 23:41:50
- 总条数：280 ｜ 板块 A：**0** ｜ 板块 B：**280**
- 状态计数：ZERO_RECORD_FRESH 0 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 3 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 277

<!-- live_hunt_counts: {"BOARD_A": 0, "BOARD_B": 280, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 3, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 277, "ZERO_RECORD_FRESH": 0} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 10 个缓存。

- 候选仓：10 ｜ 实扫：6 ｜ 跳过：3 ｜ 失败：1 ｜ 候选来源：github_search
- 本次新增根因：280 ｜ 板块 A：0 ｜ 拦截进 B：280
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：1 个
- 侦察缓存与回填：缓存命中 0 页 / 限流回填 4 仓

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| mateaix/mateclaw | 9a5c89c0491e | SCANNED | 2 |
| backtrue/thinkwithblack-skill | 6a43460e60b3 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| vastsa/FileCodeBox | 42b2c29ccb56 | SCANNED | 12 |
| GanymedeNil/document.ai | 265cb9f82eac | SCANNED | 2 |
| Haohao-end/openagent | 47a4fc6d4292 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| caura-ai/caura | c38e85c79a01 | SCANNED | 183 |
| cuic19053-hue/stardust-agent | 91f308e98110 | SCANNED | 67 |
| arvin341az-glitch/RVG | e0bd74df4163 | SCANNED | 14 |
| indranilbanerjee/digital-marketing-pro | be4142b25bba | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| SalesforceAIResearch/CRMArena |  | FAILED (clone_failed: .sslBackend=openssl', '-c') | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — | — |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | FileCodeBox | authz | cancel_upload | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 2 | FileCodeBox | authz | complete_upload | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 3 | FileCodeBox | authz | download_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | FileCodeBox | authz | file_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | FileCodeBox | authz | file_download | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | FileCodeBox | authz | file_preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | FileCodeBox | authz | get_upload_status | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 8 | FileCodeBox | authz | presign_upload_cancel | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 9 | FileCodeBox | authz | presign_upload_confirm | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 10 | FileCodeBox | authz | presign_upload_proxy | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 11 | FileCodeBox | authz | presign_upload_status | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 12 | FileCodeBox | authz | upload_chunk | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 13 | RVG | authz | packet_up_upload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 14 | RVG | authz | public_sub_data | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 15 | RVG | authz | public_sub_page | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 16 | RVG | authz | stream_up_upload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | RVG | authz | sub_group_subscription | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 18 | RVG | authz | subscription_single | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 19 | RVG | authz | trojan_packet_up_upload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | RVG | authz | trojan_stream_up_upload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | RVG | authz | trojan_xhttp_downlink | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | RVG | authz | xhttp_downlink | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | RVG | log_injection | delete_link | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 24 | RVG | log_injection | packet_up_upload | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 25 | RVG | log_injection | trojan_packet_up_upload | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 26 | RVG | log_injection | update_link | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 27 | caura | authz | accept | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 28 | caura | authz | admin_list_fleets | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 29 | caura | authz | admin_list_memories | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 30 | caura | authz | admin_memory_stats | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 31 | caura | authz | admin_stats | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 32 | caura | authz | apply_states | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 33 | caura | authz | approve | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 34 | caura | authz | approve_delivery | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 35 | caura | authz | begin_send | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 36 | caura | authz | claim_interview_request | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 37 | caura | authz | clear_bulletin | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 38 | caura | authz | clear_notes | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 39 | caura | authz | collection_count | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 40 | caura | authz | command_result | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 41 | caura | authz | confirm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 42 | caura | authz | confirm_correction | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 43 | caura | authz | count_active_memories | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 44 | caura | authz | count_held_memories | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 45 | caura | authz | count_memories | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 46 | caura | authz | count_nodes | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 47 | caura | authz | defer | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 48 | caura | authz | delete_agent | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 49 | caura | authz | delete_agent | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 50 | caura | authz | delete_all_memories | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 51 | caura | authz | delete_document | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 52 | caura | authz | delete_document | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 53 | caura | authz | delete_fleet | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 54 | caura | authz | delete_keystone | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 55 | caura | authz | delete_keystone | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 56 | caura | authz | delete_memory | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 57 | caura | authz | deploy_attempt_count | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 58 | caura | authz | edit | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 59 | caura | authz | encrypt_organization_api_keys | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 60 | caura | authz | find_broken_entity_links | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 61 | caura | authz | find_by_content_hash | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 62 | caura | authz | find_by_supersedes_id | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 63 | caura | authz | find_children_by_parent_id | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 64 | caura | authz | find_duplicate_hash | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 65 | caura | authz | find_embedding_by_content_hash | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 66 | caura | authz | find_exact_entity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 67 | caura | authz | find_orphaned_entities | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 68 | caura | authz | find_rdf_conflicts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 69 | caura | authz | find_running_report | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 70 | caura | authz | fleet_distribution | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 71 | caura | authz | fleet_stats | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 72 | caura | authz | flush_usage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 73 | caura | authz | get_agent | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 74 | caura | authz | get_agent | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 75 | caura | authz | get_agent_activity_digest | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 76 | caura | authz | get_audit_usage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 77 | caura | authz | get_baton | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 78 | caura | authz | get_bulletin | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 79 | caura | authz | get_contradictions | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 80 | caura | authz | get_correction | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 81 | caura | authz | get_correction | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 82 | caura | authz | get_document | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 83 | caura | authz | get_embedding_coverage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 84 | caura | authz | get_entity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 85 | caura | authz | get_entity_coverage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 86 | caura | authz | get_entity_route | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 87 | caura | authz | get_entity_with_linked_memories | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 88 | caura | authz | get_exposure | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xw4x-jwf5-8m9h | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xw4x-jwf5-8m9h） | https://api.github.com/repos/caura-ai/caura/security-advisories |
| 89 | caura | authz | get_full_graph | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 90 | caura | authz | get_graph | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 91 | caura | authz | get_idempotency | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 92 | caura | authz | get_keystone_version | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 93 | caura | authz | get_keystones | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 94 | caura | authz | get_latest_report | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 95 | caura | authz | get_latest_report | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 96 | caura | authz | get_lifecycle_audit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 97 | caura | authz | get_lifecycle_audit | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 98 | caura | authz | get_lifecycle_candidates | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 99 | caura | authz | get_memory | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 100 | caura | authz | get_memory | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 101 | caura | authz | get_memory_conflict | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 102 | caura | authz | get_memory_contradictions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 103 | caura | authz | get_memory_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 104 | caura | authz | get_memory_exposure | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 105 | caura | authz | get_memory_stats | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 106 | caura | authz | get_model | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 107 | caura | authz | get_notes | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 108 | caura | authz | get_organization_settings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 109 | caura | authz | get_outgoing_relations | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 110 | caura | authz | get_pending_commands | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 111 | caura | authz | get_report | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 112 | caura | authz | get_report | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 113 | caura | authz | get_tenant_suppression | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 114 | caura | authz | get_type_distribution | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 115 | caura | authz | get_usage | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 116 | caura | authz | get_value | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 117 | caura | authz | has_recent_success | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 118 | caura | authz | in_flight_deploy | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 119 | caura | authz | ingest_file_endpoint | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 120 | caura | authz | ingest_undo_endpoint | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 121 | caura | authz | install_plugin_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 122 | caura | authz | keystone_version | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 123 | caura | authz | keystone_versions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 124 | caura | authz | list_agents | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 125 | caura | authz | list_audit_logs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 126 | caura | authz | list_collections | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 127 | caura | authz | list_collections | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 128 | caura | authz | list_commands | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 129 | caura | authz | list_commands | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 130 | caura | authz | list_corrections | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 131 | caura | authz | list_documents | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 132 | caura | authz | list_entities | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 133 | caura | authz | list_entities | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 134 | caura | authz | list_fleets | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 135 | caura | authz | list_fleets | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 136 | caura | authz | list_fleets | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 137 | caura | authz | list_held_memories | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 138 | caura | authz | list_held_memories | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 139 | caura | authz | list_inbox | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 140 | caura | authz | list_keystone_versions | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 141 | caura | authz | list_keystones | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 142 | caura | authz | list_memories | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 143 | caura | authz | list_memory_conflicts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 144 | caura | authz | list_memory_corrections | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 145 | caura | authz | list_nodes | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 146 | caura | authz | list_nodes | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 147 | caura | authz | list_notices | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 148 | caura | authz | list_notices | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 149 | caura | authz | list_null_embedding_ids | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 150 | caura | authz | list_open_task_failures | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 151 | caura | authz | list_recipients | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 152 | caura | authz | list_reports | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 153 | caura | authz | list_reports | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 154 | caura | authz | memory_count | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 155 | caura | authz | memory_field | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 156 | caura | authz | memory_stats | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 157 | caura | authz | merge_entity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 158 | caura | authz | nodes_summary | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 159 | caura | authz | notices_checked | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 160 | caura | authz | notices_delivered | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 161 | caura | authz | patch_agent_trust | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 162 | caura | authz | patch_agent_tune | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 163 | caura | authz | purge_fleet | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 164 | caura | authz | quarantine | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 165 | caura | authz | query_usage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 166 | caura | authz | query_value | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 167 | caura | authz | re_extract_memory | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 168 | caura | authz | record_correction | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 169 | caura | authz | record_exposure | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xw4x-jwf5-8m9h | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_GHSA: GHSA-xw4x-jwf5-8m9h） | https://api.github.com/repos/caura-ai/caura/security-advisories |
| 170 | caura | authz | record_origin | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 171 | caura | authz | record_outcome | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 172 | caura | authz | record_recipients | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 173 | caura | authz | record_reuse | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 174 | caura | authz | redistribute_memories | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 175 | caura | authz | reject | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 176 | caura | authz | release_idempotency_claim | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 177 | caura | authz | release_node | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 178 | caura | authz | reset_search_profile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 179 | caura | authz | resolve_conflict | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 180 | caura | authz | resolve_memory_conflict | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 181 | caura | authz | rollback_session | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 182 | caura | authz | send_correction_notices | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 183 | caura | authz | set_predicate_if_null | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 184 | caura | authz | set_subject_entity_if_null | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 185 | caura | authz | set_supersedes_if_null | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 186 | caura | authz | soft_delete_memory | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 187 | caura | authz | touch_sessions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 188 | caura | authz | unverify_memory | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 189 | caura | authz | update_agent_fleet | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 190 | caura | authz | update_agent_fleet | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 191 | caura | authz | update_command_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 192 | caura | authz | update_embedding | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 193 | caura | authz | update_entity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 194 | caura | authz | update_lifecycle_audit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 195 | caura | authz | update_memory | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 196 | caura | authz | update_memory_entities | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 197 | caura | authz | update_memory_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 198 | caura | authz | update_memory_status | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 199 | caura | authz | update_organization_settings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 200 | caura | authz | update_report | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 201 | caura | authz | update_search_profile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 202 | caura | authz | update_trust_level | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 203 | caura | authz | verify_audit_chain | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 204 | caura | authz | verify_memory | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 205 | caura | log_injection | delete_all_memories | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 206 | caura | log_injection | fanout_lifecycle_action | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 207 | caura | log_injection | get_graph | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 208 | caura | log_injection | get_memory | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 209 | caura | log_injection | heartbeat | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-xw4x-jwf5-8m9h | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-xw4x-jwf5-8m9h） | https://api.github.com/repos/caura-ai/caura/security-advisories |
| 210 | document.ai | authz | cancel_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 211 | document.ai | authz | session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 212 | mateclaw | log_injection | ChatController.chatStream | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 213 | mateclaw | unrestricted_upload | WikiController.uploadRaw | **UNKNOWN** | — | NON_EXECUTABLE_UPLOAD: 已防路径穿越 / 已做扩展名白名单+固定命名，落盘目录非 Web 静态挂载（无 StaticFiles/addResourceHandlers 指向上传目录），上传物不可执行 | — |
| 214 | stardust-agent | authz | ack | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 215 | stardust-agent | authz | acknowledge | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 216 | stardust-agent | authz | apply | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 217 | stardust-agent | authz | cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 218 | stardust-agent | authz | cancel_section_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 219 | stardust-agent | authz | chat | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 220 | stardust-agent | authz | confirm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 221 | stardust-agent | authz | confirm_document | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 222 | stardust-agent | authz | confirm_project_fact | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 223 | stardust-agent | authz | confirm_reference | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 224 | stardust-agent | authz | confirm_text | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 225 | stardust-agent | authz | context | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 226 | stardust-agent | authz | create_section_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 227 | stardust-agent | authz | delete_diagram | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 228 | stardust-agent | authz | delete_document | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 229 | stardust-agent | authz | delete_leader_photo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 230 | stardust-agent | authz | diagram_preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 231 | stardust-agent | authz | document_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 232 | stardust-agent | authz | download | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 233 | stardust-agent | authz | download_docx | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 234 | stardust-agent | authz | export_docx | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 235 | stardust-agent | authz | generate_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 236 | stardust-agent | authz | generate_project_image | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 237 | stardust-agent | authz | generate_section | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 238 | stardust-agent | authz | get_admin_usage_details | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 239 | stardust-agent | authz | get_local_turn | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 240 | stardust-agent | authz | get_payment_order | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 241 | stardust-agent | authz | get_project | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 242 | stardust-agent | authz | get_project_token_stats | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 243 | stardust-agent | authz | get_project_usage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 244 | stardust-agent | authz | get_review | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 245 | stardust-agent | authz | get_section_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 246 | stardust-agent | authz | import_official_source | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 247 | stardust-agent | authz | legacy_fields | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 248 | stardust-agent | authz | list_model_interactions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 249 | stardust-agent | authz | list_reviews | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 250 | stardust-agent | authz | list_section_versions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 251 | stardust-agent | authz | page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 252 | stardust-agent | authz | preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 253 | stardust-agent | authz | preview_official_source | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 254 | stardust-agent | authz | process_cloud_document | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 255 | stardust-agent | authz | propose_diagram | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 256 | stardust-agent | authz | propose_project_facts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 257 | stardust-agent | authz | recommend_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 258 | stardust-agent | authz | register_cloud_upload | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 259 | stardust-agent | authz | restore_section_version | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 260 | stardust-agent | authz | save_diagram | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 261 | stardust-agent | authz | search_official | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 262 | stardust-agent | authz | search_papers | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 263 | stardust-agent | authz | search_private_materials | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 264 | stardust-agent | authz | search_public_knowledge | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 265 | stardust-agent | authz | select_conversation_skill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 266 | stardust-agent | authz | simulate_review | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 267 | stardust-agent | authz | status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 268 | stardust-agent | authz | submit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 269 | stardust-agent | authz | submit_local_turn | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 270 | stardust-agent | authz | submit_review | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 271 | stardust-agent | authz | trace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 272 | stardust-agent | authz | update_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 273 | stardust-agent | authz | update_plans | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 274 | stardust-agent | authz | update_project | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 275 | stardust-agent | authz | update_project_facts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 276 | stardust-agent | authz | update_requirements | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 277 | stardust-agent | authz | update_section | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 278 | stardust-agent | authz | upload_documents | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 279 | stardust-agent | authz | upload_leader_photo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 280 | stardust-agent | authz | validate_project | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 0 |
| B（其余状态） | 280 |
| 合计 | 280 |
