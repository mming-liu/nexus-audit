# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-21 09:07:18
- 总条数：87 ｜ 板块 A：**2** ｜ 板块 B：**85**
- 状态计数：ZERO_RECORD_FRESH 2 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 2 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 83

<!-- live_hunt_counts: {"BOARD_A": 2, "BOARD_B": 85, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 2, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 83, "ZERO_RECORD_FRESH": 2} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 0 个缓存。

- 候选仓：6 ｜ 实扫：4 ｜ 跳过：2 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：87 ｜ 板块 A：2 ｜ 拦截进 B：85
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：2 个
- 侦察缓存与回填：缓存命中 0 页 / 限流回填 6 仓

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| GroundedCoreAI/nexusdesk | a614f17688cf | SKIPPED (all_local_or_demo) | 0 |
| scub-france/docling-Studio | 1de192940769 | SKIPPED (unchanged_head) | 0 |
| xr843/fojin | ade71d82c383 | SCANNED | 40 |
| fim-ai/fim-one | 2d2d20d21613 | SCANNED | 13 |
| dnotitia/akb | 9f5f9e2df283 | SCANNED | 34 |
| martian56/redcell | f6dae370731c | SCANNED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | fojin | hash | get_kg_lineage_arcs | — | 2026-11-21 (0.0d) | ade71d82c383 | [backend/app/api/knowledge_graph.py:383](https://github.com/xr843/fojin/blob/ade71d82c383db02daec81cf4c25b42dc12a052b/backend/app/api/knowledge_graph.py#L383) | [Advisory](https://github.com/xr843/fojin/security/advisories/new) · [Issue](https://github.com/xr843/fojin/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/fojin_hash_get_kg_lineage_arcs/SUBMISSION_PLAYBOOK.md) |
| 2 | fojin | hash | get_kg_timeline | — | 2026-11-21 (0.0d) | ade71d82c383 | [backend/app/api/knowledge_graph.py:296](https://github.com/xr843/fojin/blob/ade71d82c383db02daec81cf4c25b42dc12a052b/backend/app/api/knowledge_graph.py#L296) | [Advisory](https://github.com/xr843/fojin/security/advisories/new) · [Issue](https://github.com/xr843/fojin/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/fojin_hash_get_kg_timeline/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | akb | authz | app_evaluate_target | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 2 | akb | authz | app_get_rollout | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 3 | akb | authz | app_get_snapshot | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 4 | akb | authz | app_resume_rollout | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 5 | akb | authz | approve_operation_request | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 6 | akb | authz | cancel_operation_request | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 7 | akb | authz | change_read | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 8 | akb | authz | change_target_ownership | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 9 | akb | authz | confirm_file_replace | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 10 | akb | authz | confirm_upload | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 11 | akb | authz | deny_operation_request | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 12 | akb | authz | discard_document_image | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 13 | akb | authz | execute_operation | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 14 | akb | authz | get_app_installation | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 15 | akb | authz | get_download_url | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 16 | akb | authz | get_public_publication | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 17 | akb | authz | mcp_monitoring | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 18 | akb | authz | observation_trace | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 19 | akb | authz | operation_login_challenge | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 20 | akb | authz | operation_login_events | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 21 | akb | authz | operation_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 22 | akb | authz | publication_auth | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 23 | akb | authz | publication_capabilities | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 24 | akb | authz | publication_document_asset | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 25 | akb | authz | publication_download | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 26 | akb | authz | publication_embed | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 27 | akb | authz | publication_meta | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 28 | akb | authz | publication_raw | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 29 | akb | authz | reauthorize_operation | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 30 | akb | authz | renew_publication_view_grant | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 31 | akb | authz | retire_operation | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 32 | akb | authz | set_monitoring_access_route | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 33 | akb | hardcoded_secret | [secret-file] docker-compose.keycloak.yaml | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 34 | akb | hardcoded_secret | [secret-file] exercise.py | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 同仓主服务仅绑定回环（eval/longmemeval/docker-compose.yaml 端口映射 127.0.0.1），子路由继承单机边界，无远程攻击面 | — |
| 35 | fim-one | authz | admin_delete_org | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 36 | fim-one | authz | admin_update_org | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 37 | fim-one | authz | callback | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-x8r3-xjc7-ph3c | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫（REPO_LEVEL_GHSA: GHSA-x8r3-xjc7-ph3c） | https://api.github.com/repos/fim-ai/fim-one/security-advisories |
| 38 | fim-one | authz | channel_callback | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 39 | fim-one | authz | delete_market_resource | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 40 | fim-one | authz | download_artifact | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 41 | fim-one | authz | export_audit_log | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 42 | fim-one | authz | get_avatar | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 43 | fim-one | authz | list_audit_log | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 44 | fim-one | authz | list_call_log | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 45 | fim-one | authz | list_review_log | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 46 | fim-one | authz | unpublish_market_resource | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 47 | fim-one | log_injection | authorize | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-x8r3-xjc7-ph3c | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项（REPO_LEVEL_GHSA: GHSA-x8r3-xjc7-ph3c） | https://api.github.com/repos/fim-ai/fim-one/security-advisories |
| 48 | fojin | authz | download | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 49 | fojin | authz | export_text | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 50 | fojin | authz | get | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 51 | fojin | authz | get_canonical_parallels | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 52 | fojin | authz | get_chunk_alignment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 53 | fojin | authz | get_citation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 54 | fojin | authz | get_entry | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 55 | fojin | authz | get_full_parallel_content | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 56 | fojin | authz | get_juan_alignment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 57 | fojin | authz | get_kg_entity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 58 | fojin | authz | get_kg_entity_graph | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 59 | fojin | authz | get_kg_entity_mentions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 60 | fojin | authz | get_manifest | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 61 | fojin | authz | get_sentence_alignment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 62 | fojin | authz | get_text | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 63 | fojin | authz | get_text_versions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 64 | fojin | authz | get_work | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 65 | fojin | authz | get_work_by_text | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 66 | fojin | authz | juan_languages | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 67 | fojin | authz | list_by_text | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 68 | fojin | authz | list_juans | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 69 | fojin | authz | list_text_entities | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 70 | fojin | authz | list_text_identifiers | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 71 | fojin | authz | list_text_manifests | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 72 | fojin | authz | list_text_relations | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 73 | fojin | authz | list_work_witnesses | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 74 | fojin | authz | parallel_read | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 75 | fojin | authz | person_seo_html | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 76 | fojin | authz | proxy_manifest | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 77 | fojin | authz | read_juan | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 78 | fojin | authz | read_juan_apparatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 79 | fojin | authz | read_juan_audio | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 80 | fojin | authz | read_juan_line_anchors | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 81 | fojin | authz | resolve_cbeta_id | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 82 | fojin | authz | shared_qa_og_image | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 83 | fojin | authz | shared_qa_seo_html | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 84 | fojin | authz | text_detail_seo_html | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 85 | fojin | authz | text_reader_seo_html | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 2 |
| B（其余状态） | 85 |
| 合计 | 87 |
