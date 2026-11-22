# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-22 09:20:20
- 总条数：448 ｜ 板块 A：**4** ｜ 板块 B：**444**
- 状态计数：ZERO_RECORD_FRESH 4 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 444

<!-- live_hunt_counts: {"BOARD_A": 4, "BOARD_B": 444, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 444, "ZERO_RECORD_FRESH": 4} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 0 个缓存。

- 候选仓：14 ｜ 实扫：6 ｜ 跳过：8 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：448 ｜ 板块 A：4 ｜ 拦截进 B：444
- 证据不足未列：1 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：0 个

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| Swayingleaves/novanova-studio | eb7c8e92abbe | SCANNED | 233 |
| ColinGPT9/clips-studio | 7238297fb4ae | SKIPPED (all_local_or_demo) | 0 |
| Berikai/bitwig-theme-editor | d20230335fed | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| MahmoudSalah22/fl-studio-windows | efa93ce7ba6d | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| dromara/dax-pay | 466517a1b7cb | SCANNED | 3 |
| skilltoAI/skillto-ai-studio | e777c2b40949 | SKIPPED (low_units_5) | 0 |
| ing-bank/INGenious | 7e2643b7c9d9 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| lightly-ai/lightly-studio | b70f038a74a1 | SCANNED | 58 |
| nkxx188/Drama3-Studio | 94f55303f5dd | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| Xerophayze/TTS-Story | 303dbcaa976c | SCANNED | 60 |
| apple/creator-studio-doc-format | 995911cae658 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| karl-andres/fl-studio-mcp | 7c379ee995c4 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| Keys-Wasserman/Imagination-Studio-by-keys-Wasserman | 16f00b462a5a | SCANNED | 45 |
| brightbeanxyz/brightbean-studio | 14b92fc18549 | SCANNED | 49 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | dax-pay | redir | EasyPayApiV1Controller.submit | — | 2026-11-16 (5.8d) | 466517a1b7cb | [daxpay-plugin/daxpay-plugin-easypay/src/main/java/cn/daxpay/open/plugin/easypay/controller/api/EasyPayApiV1Controller.java:38](https://github.com/dromara/dax-pay/blob/466517a1b7cb8fd64e4d66191598394a178792d9/daxpay-plugin/daxpay-plugin-easypay/src/main/java/cn/daxpay/open/plugin/easypay/controller/api/EasyPayApiV1Controller.java#L38) | [Advisory](https://github.com/dromara/dax-pay/security/advisories/new) · [Issue](https://github.com/dromara/dax-pay/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dax-pay_redir_submit/SUBMISSION_PLAYBOOK.md) |
| 2 | dax-pay | redir | EasyPayApiV2Controller.submit | — | 2026-11-16 (5.8d) | 466517a1b7cb | [daxpay-plugin/daxpay-plugin-easypay/src/main/java/cn/daxpay/open/plugin/easypay/controller/api/EasyPayApiV2Controller.java:38](https://github.com/dromara/dax-pay/blob/466517a1b7cb8fd64e4d66191598394a178792d9/daxpay-plugin/daxpay-plugin-easypay/src/main/java/cn/daxpay/open/plugin/easypay/controller/api/EasyPayApiV2Controller.java#L38) | [Advisory](https://github.com/dromara/dax-pay/security/advisories/new) · [Issue](https://github.com/dromara/dax-pay/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dax-pay_redir_submit/SUBMISSION_PLAYBOOK.md) |
| 3 | dax-pay | redir | OpenAuthController.getOpenId | — | 2026-11-16 (5.8d) | 466517a1b7cb | [daxpay-payment/daxpay-payment-unipay/src/main/java/cn/daxpay/open/payment/unipay/client/controller/OpenAuthController.java:40](https://github.com/dromara/dax-pay/blob/466517a1b7cb8fd64e4d66191598394a178792d9/daxpay-payment/daxpay-payment-unipay/src/main/java/cn/daxpay/open/payment/unipay/client/controller/OpenAuthController.java#L40) | [Advisory](https://github.com/dromara/dax-pay/security/advisories/new) · [Issue](https://github.com/dromara/dax-pay/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dax-pay_redir_getOpenId/SUBMISSION_PLAYBOOK.md) |
| 4 | novanova-studio | pathtraver | StorageBillingController.listFiles | — | 2026-11-21 (0.8d) | eb7c8e92abbe | [server/src/main/java/com/novanovastudio/controller/StorageBillingController.java:47](https://github.com/Swayingleaves/novanova-studio/blob/eb7c8e92abbec7ac62e0a31afb725ad684ea18cd/server/src/main/java/com/novanovastudio/controller/StorageBillingController.java#L47) | [Advisory](https://github.com/Swayingleaves/novanova-studio/security/advisories/new) · [Issue](https://github.com/Swayingleaves/novanova-studio/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/novanova-studio_pathtraver_listFiles/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | Imagination-Studio-by-keys-Wasserman | authz | attach_to_film | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 2 | Imagination-Studio-by-keys-Wasserman | authz | cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | Imagination-Studio-by-keys-Wasserman | authz | cancel | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 4 | Imagination-Studio-by-keys-Wasserman | authz | cancel_run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | Imagination-Studio-by-keys-Wasserman | authz | cancel_task | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 6 | Imagination-Studio-by-keys-Wasserman | authz | change_thread | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 7 | Imagination-Studio-by-keys-Wasserman | authz | comfy_result | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | Imagination-Studio-by-keys-Wasserman | authz | comfy_submit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | Imagination-Studio-by-keys-Wasserman | authz | delete_graph | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | Imagination-Studio-by-keys-Wasserman | authz | discard | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | Imagination-Studio-by-keys-Wasserman | authz | drop_dataset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | Imagination-Studio-by-keys-Wasserman | authz | get_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 13 | Imagination-Studio-by-keys-Wasserman | authz | get_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 14 | Imagination-Studio-by-keys-Wasserman | authz | get_pack | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | Imagination-Studio-by-keys-Wasserman | authz | get_run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | Imagination-Studio-by-keys-Wasserman | authz | get_take | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | Imagination-Studio-by-keys-Wasserman | authz | get_take | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | Imagination-Studio-by-keys-Wasserman | authz | import_prompts | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 19 | Imagination-Studio-by-keys-Wasserman | authz | install | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | Imagination-Studio-by-keys-Wasserman | authz | link_cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | Imagination-Studio-by-keys-Wasserman | authz | one | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | Imagination-Studio-by-keys-Wasserman | authz | one | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | Imagination-Studio-by-keys-Wasserman | authz | one_import | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 24 | Imagination-Studio-by-keys-Wasserman | authz | one_task | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 25 | Imagination-Studio-by-keys-Wasserman | authz | one_thread | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 26 | Imagination-Studio-by-keys-Wasserman | authz | remove | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 27 | Imagination-Studio-by-keys-Wasserman | authz | remove | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 28 | Imagination-Studio-by-keys-Wasserman | authz | remove_project | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 29 | Imagination-Studio-by-keys-Wasserman | authz | remove_thread | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 30 | Imagination-Studio-by-keys-Wasserman | authz | reply | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 31 | Imagination-Studio-by-keys-Wasserman | authz | save_project | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 32 | Imagination-Studio-by-keys-Wasserman | authz | save_project | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 33 | Imagination-Studio-by-keys-Wasserman | authz | start_now | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 34 | Imagination-Studio-by-keys-Wasserman | authz | status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 35 | Imagination-Studio-by-keys-Wasserman | authz | status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 36 | Imagination-Studio-by-keys-Wasserman | authz | stop | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 37 | Imagination-Studio-by-keys-Wasserman | authz | stop_thread | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 38 | Imagination-Studio-by-keys-Wasserman | authz | take_audio | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 39 | Imagination-Studio-by-keys-Wasserman | authz | take_audio | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 40 | Imagination-Studio-by-keys-Wasserman | authz | take_live | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 41 | Imagination-Studio-by-keys-Wasserman | authz | take_live | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 42 | Imagination-Studio-by-keys-Wasserman | authz | to_editor | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 43 | Imagination-Studio-by-keys-Wasserman | authz | to_motion | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 44 | Imagination-Studio-by-keys-Wasserman | authz | to_slate | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 45 | Imagination-Studio-by-keys-Wasserman | authz | tool_check | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 46 | TTS-Story | authz | apply_chunk_audio_effects | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 47 | TTS-Story | authz | breeze_api_preview | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 48 | TTS-Story | authz | breeze_api_recover_production | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 49 | TTS-Story | authz | breeze_api_release_production | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 50 | TTS-Story | authz | breeze_voice_design_task_delete | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 51 | TTS-Story | authz | breeze_voice_design_task_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 52 | TTS-Story | authz | cancel_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 53 | TTS-Story | authz | control_library_regeneration | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 54 | TTS-Story | authz | custom_voice_detail | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 55 | TTS-Story | authz | delete_chatterbox_voice | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 56 | TTS-Story | authz | delete_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 57 | TTS-Story | authz | delete_library_item | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 58 | TTS-Story | authz | delete_saved_project | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 59 | TTS-Story | authz | download_audio | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 60 | TTS-Story | authz | download_audio_bundle | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 61 | TTS-Story | authz | download_external_voice | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 62 | TTS-Story | authz | download_m4b | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 63 | TTS-Story | authz | finish_review_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 64 | TTS-Story | authz | gemini_tts_delete_voice | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 65 | TTS-Story | authz | gemini_tts_voice_preview | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 66 | TTS-Story | authz | get_job_chunks | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 67 | TTS-Story | authz | get_job_details | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 68 | TTS-Story | authz | get_library_chapter_durations | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 69 | TTS-Story | authz | get_library_item_chunks | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 70 | TTS-Story | authz | get_saved_project | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 71 | TTS-Story | authz | library_job_word_replacements | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 72 | TTS-Story | authz | m4b_progress_endpoint | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 73 | TTS-Story | authz | omnivoice_voice_design_task_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 74 | TTS-Story | authz | optional_engine_install_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 75 | TTS-Story | authz | pause_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 76 | TTS-Story | authz | preview_chatterbox_voice | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 77 | TTS-Story | authz | preview_chunk_audio_effects | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 78 | TTS-Story | authz | preview_external_voice | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 79 | TTS-Story | authz | qwen3_voice_design_task_delete | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 80 | TTS-Story | authz | qwen3_voice_design_task_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 81 | TTS-Story | authz | rebuild_library_all | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 82 | TTS-Story | authz | rebuild_library_chapter | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 83 | TTS-Story | authz | rebuild_library_full_story | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 84 | TTS-Story | authz | rebuild_library_selected_chapters | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 85 | TTS-Story | authz | rename_chatterbox_voice | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 86 | TTS-Story | authz | rename_library_chapter | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 87 | TTS-Story | authz | repair_library_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 88 | TTS-Story | authz | request_chunk_regeneration | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 89 | TTS-Story | authz | request_full_job_regeneration | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 90 | TTS-Story | authz | restore_library_item_to_review | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 91 | TTS-Story | authz | resume_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 92 | TTS-Story | authz | save_review_speaker_profile | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 93 | TTS-Story | authz | transcribe_chatterbox_voice | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 94 | TTS-Story | authz | update_chatterbox_voice_metadata | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 95 | TTS-Story | authz | update_library_metadata | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 96 | TTS-Story | authz | update_library_title | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 97 | TTS-Story | log_injection | cancel_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 98 | TTS-Story | log_injection | download_audio | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 99 | TTS-Story | log_injection | download_audio_bundle | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 100 | TTS-Story | log_injection | download_m4b | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 101 | TTS-Story | log_injection | generate_voice_samples_api | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 102 | TTS-Story | log_injection | restore_library_item_to_review | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 103 | TTS-Story | pathtraver | download_audio | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 104 | TTS-Story | unrestricted_upload | create_chatterbox_voice | **UNKNOWN** | — | UPLOAD_SERVING_ONLY: 已防路径穿越 / 已做扩展名白名单+固定命名，且下载为 attachment 或仅内部语料入库，无静态挂载或内联渲染面 | — |
| 105 | TTS-Story | unrestricted_upload | upload_voice_prompt | **UNKNOWN** | — | UPLOAD_SERVING_ONLY: 已防路径穿越 / 已做扩展名白名单+固定命名，且下载为 attachment 或仅内部语料入库，无静态挂载或内联渲染面 | — |
| 106 | brightbean-studio | authz | account_analytics | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 107 | brightbean-studio | authz | account_list | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 108 | brightbean-studio | authz | asset_delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 109 | brightbean-studio | authz | asset_detail | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 110 | brightbean-studio | authz | asset_download | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 111 | brightbean-studio | authz | asset_edit | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 112 | brightbean-studio | authz | asset_move | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 113 | brightbean-studio | authz | asset_star_toggle | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 114 | brightbean-studio | authz | asset_update_tags | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 115 | brightbean-studio | authz | cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 116 | brightbean-studio | authz | checklist_partial | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 117 | brightbean-studio | authz | client_list | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 118 | brightbean-studio | authz | connect_bluesky | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 119 | brightbean-studio | authz | connect_devto | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 120 | brightbean-studio | authz | delete_reply | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 121 | brightbean-studio | authz | disconnect | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 122 | brightbean-studio | authz | folder_create | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 123 | brightbean-studio | authz | folder_delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 124 | brightbean-studio | authz | folder_rename | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 125 | brightbean-studio | authz | library_index | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 126 | brightbean-studio | authz | list_media | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 127 | brightbean-studio | authz | list_messages | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 128 | brightbean-studio | authz | mark_as_read | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 129 | brightbean-studio | authz | post_analytics | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 130 | brightbean-studio | authz | processing_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 131 | brightbean-studio | authz | reconnect | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 132 | brightbean-studio | authz | remove_client | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 133 | brightbean-studio | authz | resend_invite | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 134 | brightbean-studio | authz | retrieve | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 135 | brightbean-studio | authz | retrieve | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 136 | brightbean-studio | authz | retrieve_message | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 137 | brightbean-studio | authz | retry_webhooks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 138 | brightbean-studio | authz | revoke_invite | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 139 | brightbean-studio | authz | revoke_key | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 140 | brightbean-studio | authz | revoke_link | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 141 | brightbean-studio | authz | schedule | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 142 | brightbean-studio | authz | search | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 143 | brightbean-studio | authz | send_link_email | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 144 | brightbean-studio | authz | shared_asset_delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 145 | brightbean-studio | authz | shared_asset_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 146 | brightbean-studio | authz | shared_asset_download | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 147 | brightbean-studio | authz | shared_asset_update_tags | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 148 | brightbean-studio | authz | shared_version_list | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 149 | brightbean-studio | authz | tag_autocomplete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 150 | brightbean-studio | authz | update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 151 | brightbean-studio | authz | update_reply | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 152 | brightbean-studio | authz | version_list | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 153 | brightbean-studio | authz | version_restore | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 154 | brightbean-studio | log_injection | youtube_webhook | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 155 | lightly-studio | authz | add_sample_ids_to_tag_id | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 156 | lightly-studio | authz | add_samples_to_tag_by_filter | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 157 | lightly-studio | authz | add_tag_to_sample | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 158 | lightly-studio | authz | bulk_delete_annotations | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 159 | lightly-studio | authz | commit_temp_classifier | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 160 | lightly-studio | authz | count_mcap_sequence_annotations_by_collection | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 161 | lightly-studio | authz | count_video_frame_annotations | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 162 | lightly-studio | authz | create_evaluation_run | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 163 | lightly-studio | authz | delete_annotation_label | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 164 | lightly-studio | authz | delete_run | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 165 | lightly-studio | authz | delete_tag | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 166 | lightly-studio | authz | drop_temp_classifier | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 167 | lightly-studio | authz | execute_operator | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 168 | lightly-studio | authz | export_download | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 169 | lightly-studio | authz | get_2d_embeddings | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 170 | lightly-studio | authz | get_2d_embeddings_status | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 171 | lightly-studio | authz | get_all_classifiers | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 172 | lightly-studio | authz | get_all_groups | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 173 | lightly-studio | authz | get_annotation | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 174 | lightly-studio | authz | get_camera_frame | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 175 | lightly-studio | authz | get_evaluation_annotation_metrics_info | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 176 | lightly-studio | authz | get_evaluation_confusion_matrix | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 177 | lightly-studio | authz | get_evaluation_runs | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 178 | lightly-studio | authz | get_evaluation_sample_metrics_info | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 179 | lightly-studio | authz | get_fields_bounds | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 180 | lightly-studio | authz | get_frame_by_id | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 181 | lightly-studio | authz | get_group_components_by_group_id | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 182 | lightly-studio | authz | get_metadata_histograms | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 183 | lightly-studio | authz | get_metadata_value_counts | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 184 | lightly-studio | authz | get_operator_parameters | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 185 | lightly-studio | authz | get_summary | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 186 | lightly-studio | authz | get_tracks | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 187 | lightly-studio | authz | get_video_by_id | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 188 | lightly-studio | authz | get_video_frames_fields_bounds | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 189 | lightly-studio | authz | load_classifier_from_buffer | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 190 | lightly-studio | authz | read_annotation_label | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 191 | lightly-studio | authz | read_collection_hierarchy | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 192 | lightly-studio | authz | read_dataset | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 193 | lightly-studio | authz | read_image | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 194 | lightly-studio | authz | recompute_evaluation_run | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 195 | lightly-studio | authz | remove_thing_ids_to_tag_id | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 196 | lightly-studio | authz | run_classifier_route | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 197 | lightly-studio | authz | sample_history | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 198 | lightly-studio | authz | samples_to_refine | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 199 | lightly-studio | authz | save_classifier_to_file | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 200 | lightly-studio | authz | serve_image_by_sample_id | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 201 | lightly-studio | authz | serve_video_by_sample_id | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 202 | lightly-studio | authz | set_annotation_label_color | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 203 | lightly-studio | authz | stream_frame | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 204 | lightly-studio | authz | train_classifier | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 205 | lightly-studio | authz | update_annotation_label | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 206 | lightly-studio | authz | update_classifiers_annotations | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 207 | lightly-studio | authz | update_parent_track | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 208 | lightly-studio | authz | update_run | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 209 | lightly-studio | authz | v1_add_tag_to_samples | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 210 | lightly-studio | authz | v1_query_samples | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 211 | lightly-studio | authz | v1_read_collection | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 212 | lightly-studio | authz | v1_remove_tag_from_samples | **UNKNOWN** | — | AUTHENTICATED_LOCAL_ONLY: 服务默认回环绑定且挂有全局请求鉴权（lightly_studio_serve/src/lightly_studio_serve/server.py 默认 host=127.0.0.1 变量绑定 + lightly_studio_serve/src/lightly_studio_serve/server.py 全局请求鉴权），属认证后本地管理面，不作为远程未授权 0-day 交单 | — |
| 213 | novanova-studio | authz | AdminApiLogController.listApiLogs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 214 | novanova-studio | authz | AdminComicDramaFinalPromptController.savePricing | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 215 | novanova-studio | authz | AdminCreditController.generateCreditCards | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 216 | novanova-studio | authz | AdminCreditController.getRevenueOverview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 217 | novanova-studio | authz | AdminCreditController.listRevenueRecords | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 218 | novanova-studio | authz | AdminEmailCampaignController.createCampaign | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 219 | novanova-studio | authz | AdminEmailCampaignController.listDeliveries | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 220 | novanova-studio | authz | AdminEmailCampaignController.listRecipientUsers | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 221 | novanova-studio | authz | AdminEmailCampaignController.previewContent | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 222 | novanova-studio | authz | AdminEmailCampaignController.updateEmailServiceSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 223 | novanova-studio | authz | AdminEpisodeBodiesController.savePricing | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 224 | novanova-studio | authz | AdminPaymentSettingsController.updateAlipaySettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 225 | novanova-studio | authz | AdminPaymentSettingsController.updateWechatSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 226 | novanova-studio | authz | AdminScriptAiActionController.savePricing | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 227 | novanova-studio | authz | AdminStoryBibleController.savePricing | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 228 | novanova-studio | authz | AdminUserController.adjustUserCredits | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 229 | novanova-studio | authz | AdminUserController.createUser | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 230 | novanova-studio | authz | AdminUserController.getUserTrend | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 231 | novanova-studio | authz | AdminUserController.listUsers | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 232 | novanova-studio | authz | AdminUserController.resetUserPassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 233 | novanova-studio | authz | AdminUserController.unlockUserPassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 234 | novanova-studio | authz | AdminUserController.updateUserRole | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 235 | novanova-studio | authz | AdminUserController.updateUserStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 236 | novanova-studio | authz | AgentController.getSessionHistory | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 237 | novanova-studio | authz | AgentController.requestStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 238 | novanova-studio | authz | AiTaskController.createTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 239 | novanova-studio | authz | AiTaskController.pollVideoTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 240 | novanova-studio | authz | AiTaskController.workflowQuote | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 241 | novanova-studio | authz | AlipayPaymentController.returnToFrontend | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 242 | novanova-studio | authz | AuthController.changePassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 243 | novanova-studio | authz | AuthController.requestPasswordReset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 244 | novanova-studio | authz | AuthController.resetPassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 245 | novanova-studio | authz | AuthController.sendEmailCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 246 | novanova-studio | authz | AuthController.updateUserProfile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 247 | novanova-studio | authz | CheckInController.getCheckInStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 248 | novanova-studio | authz | ComicDramaController.adoptMedia | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 249 | novanova-studio | authz | ComicDramaController.bindCanvas | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 250 | novanova-studio | authz | ComicDramaController.composePrompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 251 | novanova-studio | authz | ComicDramaController.composePrompts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 252 | novanova-studio | authz | ComicDramaController.confirmShotDraft | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 253 | novanova-studio | authz | ComicDramaController.confirmUpdate | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 254 | novanova-studio | authz | ComicDramaController.createBatchTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 255 | novanova-studio | authz | ComicDramaController.createGenerationTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 256 | novanova-studio | authz | ComicDramaController.deleteShot | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 257 | novanova-studio | authz | ComicDramaController.deleteTextTrack | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 258 | novanova-studio | authz | ComicDramaController.deleteTimelineText | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 259 | novanova-studio | authz | ComicDramaController.discardShotDraft | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 260 | novanova-studio | authz | ComicDramaController.estimateGeneration | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 261 | novanova-studio | authz | ComicDramaController.exportVideo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 262 | novanova-studio | authz | ComicDramaController.generateShotDraft | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 263 | novanova-studio | authz | ComicDramaController.initializeProject | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 264 | novanova-studio | authz | ComicDramaController.listAssetVersions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 265 | novanova-studio | authz | ComicDramaController.listAssetVersionsByIds | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 266 | novanova-studio | authz | ComicDramaController.listAssets | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 267 | novanova-studio | authz | ComicDramaController.listBatchTasks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 268 | novanova-studio | authz | ComicDramaController.listCanvasBindings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 269 | novanova-studio | authz | ComicDramaController.listImpacts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 270 | novanova-studio | authz | ComicDramaController.listMedia | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 271 | novanova-studio | authz | ComicDramaController.listProjects | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 272 | novanova-studio | authz | ComicDramaController.listShots | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 273 | novanova-studio | authz | ComicDramaController.listTimelineTexts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 274 | novanova-studio | authz | ComicDramaController.listVoiceTracks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 275 | novanova-studio | authz | ComicDramaController.reorderShots | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 276 | novanova-studio | authz | ComicDramaController.reorderTimelineTexts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 277 | novanova-studio | authz | ComicDramaController.saveAsset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 278 | novanova-studio | authz | ComicDramaController.saveAssetVersion | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 279 | novanova-studio | authz | ComicDramaController.savePrompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 280 | novanova-studio | authz | ComicDramaController.saveShot | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 281 | novanova-studio | authz | ComicDramaController.saveTimelineText | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 282 | novanova-studio | authz | ComicDramaController.saveVoiceTrack | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 283 | novanova-studio | authz | ComicDramaController.updateSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 284 | novanova-studio | authz | ComicDramaController.updateShotDraft | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 285 | novanova-studio | authz | CommunityController.saveCommunityConfigs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 286 | novanova-studio | authz | CreditController.getCreditOverview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 287 | novanova-studio | authz | CreditController.listCreditTransactions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 288 | novanova-studio | authz | CreditController.listRedemptionRecords | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 289 | novanova-studio | authz | CreditController.listTaskRecords | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 290 | novanova-studio | authz | CreditPaymentController.createOrder | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 291 | novanova-studio | authz | CreditPaymentController.getOrderPayment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 292 | novanova-studio | authz | CreditPaymentController.getOrderStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 293 | novanova-studio | authz | CreditProductConfigController.createProduct | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 294 | novanova-studio | authz | CreditProductConfigController.updateProduct | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 295 | novanova-studio | authz | CreditProductConfigController.updateProductStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 296 | novanova-studio | authz | DramaController.confirmStage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 297 | novanova-studio | authz | DramaController.createProject | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 298 | novanova-studio | authz | DramaController.deleteProject | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 299 | novanova-studio | authz | DramaController.discardVersion | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 300 | novanova-studio | authz | DramaController.generateMedia | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 301 | novanova-studio | authz | DramaController.getWorkspace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 302 | novanova-studio | authz | DramaController.regenerateStage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 303 | novanova-studio | authz | DramaController.sendMessage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 304 | novanova-studio | authz | DramaController.updateProject | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 305 | novanova-studio | authz | EpisodeBodiesController.cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 306 | novanova-studio | authz | EpisodeBodiesController.quote | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 307 | novanova-studio | authz | EpisodeBodiesController.retry | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 308 | novanova-studio | authz | EpisodeBodiesController.start | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 309 | novanova-studio | authz | GenerationStyleController.createStyle | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 310 | novanova-studio | authz | GenerationStyleController.deleteStyles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 311 | novanova-studio | authz | GenerationStyleController.listStyles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 312 | novanova-studio | authz | GenerationStyleController.updateStyle | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 313 | novanova-studio | authz | GenerationStyleController.updateStyleStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 314 | novanova-studio | authz | HomepageShowcaseController.create | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 315 | novanova-studio | authz | HomepageShowcaseController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 316 | novanova-studio | authz | HomepageShowcaseController.listPublic | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 317 | novanova-studio | authz | HomepageShowcaseController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 318 | novanova-studio | authz | HomepageShowcaseController.updateStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 319 | novanova-studio | authz | NotificationController.createNotification | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 320 | novanova-studio | authz | NotificationController.markAsRead | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 321 | novanova-studio | authz | NotificationController.publishNotification | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 322 | novanova-studio | authz | NovelAdaptationController.analyzeConsistency | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 323 | novanova-studio | authz | OAuthAuthorizationServerController.authorize | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 324 | novanova-studio | authz | OAuthAuthorizationServerController.getAuthorizationRequest | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 325 | novanova-studio | authz | OAuthClientConfigController.createOAuthClient | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 326 | novanova-studio | authz | OAuthClientConfigController.updateOAuthClient | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 327 | novanova-studio | authz | OAuthConfigController.updateOAuthProvider | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 328 | novanova-studio | authz | PersistenceController.createChannel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 329 | novanova-studio | authz | PersistenceController.createModelConfig | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 330 | novanova-studio | authz | PersistenceController.createObjectStorage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 331 | novanova-studio | authz | PersistenceController.listGenerationLogs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 332 | novanova-studio | authz | PersistenceController.refreshChannelModels | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 333 | novanova-studio | authz | PersistenceController.registerRemoteMedia | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 334 | novanova-studio | authz | PersistenceController.setDefaultModel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 335 | novanova-studio | authz | PersistenceController.testObjectStorage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 336 | novanova-studio | authz | PersistenceController.updateChannel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 337 | novanova-studio | authz | PersistenceController.updateCheckInRewardSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 338 | novanova-studio | authz | PersistenceController.updateCreditSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 339 | novanova-studio | authz | PersistenceController.updateFirstPurchaseBonusSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 340 | novanova-studio | authz | PersistenceController.updateInvitationRewardSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 341 | novanova-studio | authz | PersistenceController.updateModelConfig | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 342 | novanova-studio | authz | PersistenceController.updateObjectStorage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 343 | novanova-studio | authz | PersistenceController.updateTimeoutSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 344 | novanova-studio | authz | PlatformExternalLinkController.saveExternalLinkConfig | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 345 | novanova-studio | authz | PlatformNavigationMenuController.saveNavigationMenuConfigs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 346 | novanova-studio | authz | PlatformVideoExportSettingsController.saveVideoExportSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 347 | novanova-studio | authz | PromptLibraryController.createPrompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 348 | novanova-studio | authz | PromptLibraryController.deletePrompts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 349 | novanova-studio | authz | PromptLibraryController.updatePrompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 350 | novanova-studio | authz | PromptLibraryController.updatePromptStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 351 | novanova-studio | authz | PromptOptimizationController.optimizePrompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 352 | novanova-studio | authz | ScriptController.applyAiDraft | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 353 | novanova-studio | authz | ScriptController.createProject | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 354 | novanova-studio | authz | ScriptController.createVersion | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 355 | novanova-studio | authz | ScriptController.deleteEpisode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 356 | novanova-studio | authz | ScriptController.discardAiDraft | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 357 | novanova-studio | authz | ScriptController.generateDraft | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 358 | novanova-studio | authz | ScriptController.getAiActionPricing | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 359 | novanova-studio | authz | ScriptController.listAiDrafts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 360 | novanova-studio | authz | ScriptController.listProjects | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 361 | novanova-studio | authz | ScriptController.listVersions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 362 | novanova-studio | authz | ScriptController.reorderEpisodes | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 363 | novanova-studio | authz | ScriptController.restoreVersion | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 364 | novanova-studio | authz | ScriptController.saveCharacters | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 365 | novanova-studio | authz | ScriptController.saveEpisode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 366 | novanova-studio | authz | ScriptController.saveOutline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 367 | novanova-studio | authz | ScriptController.saveOverview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 368 | novanova-studio | authz | ScriptController.saveWorld | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 369 | novanova-studio | authz | ScriptController.updateCover | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 370 | novanova-studio | authz | ScriptSourceController.confirmStructure | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 371 | novanova-studio | authz | ScriptSourceController.getSourceSection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 372 | novanova-studio | authz | ScriptSourceController.mergeSections | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 373 | novanova-studio | authz | ScriptSourceController.renameSection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 374 | novanova-studio | authz | ScriptSourceController.retryImport | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 375 | novanova-studio | authz | ScriptSourceController.splitSection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 376 | novanova-studio | authz | ScriptSourceController.uploadSource | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 377 | novanova-studio | authz | SharedWorkController.access | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 378 | novanova-studio | authz | SharedWorkController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 379 | novanova-studio | authz | SharedWorkController.fantastic | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 380 | novanova-studio | authz | SharedWorkController.mine | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 381 | novanova-studio | authz | SharedWorkController.preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 382 | novanova-studio | authz | SharedWorkController.publicDetail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 383 | novanova-studio | authz | SharedWorkController.review | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 384 | novanova-studio | authz | SharedWorkController.reviews | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 385 | novanova-studio | authz | SharedWorkController.submit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 386 | novanova-studio | authz | SkillController.createSkill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 387 | novanova-studio | authz | SkillController.createUserSkill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 388 | novanova-studio | authz | SkillController.deleteSkills | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 389 | novanova-studio | authz | SkillController.getSkillDetail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 390 | novanova-studio | authz | SkillController.listMarketSkills | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 391 | novanova-studio | authz | SkillController.listMySkills | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 392 | novanova-studio | authz | SkillController.listSkills | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 393 | novanova-studio | authz | SkillController.reviewSkill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 394 | novanova-studio | authz | SkillController.updateSkill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 395 | novanova-studio | authz | SkillController.updateSkillStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 396 | novanova-studio | authz | SkillController.updateUserSkill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 397 | novanova-studio | authz | StandardOAuthConfigController.createStandardOAuthProvider | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 398 | novanova-studio | authz | StandardOAuthConfigController.updateStandardOAuthProvider | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 399 | novanova-studio | authz | StorageBillingController.getFileAccess | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 400 | novanova-studio | authz | StorageBillingController.listFiles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 401 | novanova-studio | authz | StorageBillingController.purchaseCapacity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 402 | novanova-studio | authz | StorageBillingController.saveCapacityPackage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 403 | novanova-studio | authz | StorageBillingController.saveCapacitySettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 404 | novanova-studio | authz | StoryBibleController.cancelAnalysis | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 405 | novanova-studio | authz | StoryBibleController.confirmAllItems | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 406 | novanova-studio | authz | StoryBibleController.confirmItem | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 407 | novanova-studio | authz | StoryBibleController.confirmItems | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 408 | novanova-studio | authz | StoryBibleController.getAnalysisStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 409 | novanova-studio | authz | StoryBibleController.getItem | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 410 | novanova-studio | authz | StoryBibleController.listItems | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 411 | novanova-studio | authz | StoryBibleController.mergeEntities | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 412 | novanova-studio | authz | StoryBibleController.quoteAnalysis | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 413 | novanova-studio | authz | StoryBibleController.rejectItem | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 414 | novanova-studio | authz | StoryBibleController.retryAnalysis | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 415 | novanova-studio | authz | StoryBibleController.saveItem | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 416 | novanova-studio | authz | StoryBibleController.splitEntity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 417 | novanova-studio | authz | StoryBibleController.startAnalysis | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 418 | novanova-studio | authz | StoryboardController.composePrompts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 419 | novanova-studio | authz | StoryboardController.createAssetImageTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 420 | novanova-studio | authz | StoryboardController.generateStoryboard | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 421 | novanova-studio | authz | TeamController.acceptInvitation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 422 | novanova-studio | authz | TeamController.createMember | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 423 | novanova-studio | authz | TeamController.createTeam | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 424 | novanova-studio | authz | TeamController.getPublicTeam | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 425 | novanova-studio | authz | TeamController.inviteMember | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 426 | novanova-studio | authz | TeamController.removeMember | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 427 | novanova-studio | authz | TeamController.resendInvitation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 428 | novanova-studio | authz | TeamController.resetMemberPassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 429 | novanova-studio | authz | TeamController.revokeInvitation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 430 | novanova-studio | authz | TeamController.saveResourcePreference | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 431 | novanova-studio | authz | TeamController.updateConfigurationMode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 432 | novanova-studio | authz | TeamController.updateMemberRole | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 433 | novanova-studio | authz | TeamController.updateMemberStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 434 | novanova-studio | authz | TeamController.updateResourceGrants | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 435 | novanova-studio | authz | TeamController.updateTeam | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 436 | novanova-studio | authz | TeamController.updateTeamSettings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 437 | novanova-studio | authz | VideoCompositionController.composeVideo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 438 | novanova-studio | authz | WholeBookAdaptationController.advance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 439 | novanova-studio | authz | WholeBookAdaptationController.cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 440 | novanova-studio | authz | WholeBookAdaptationController.confirm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 441 | novanova-studio | authz | WholeBookAdaptationController.quote | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 442 | novanova-studio | authz | WholeBookAdaptationController.retry | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 443 | novanova-studio | authz | WholeBookAdaptationController.start | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 444 | novanova-studio | authz | WholeBookAdaptationController.status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 4 |
| B（其余状态） | 444 |
| 合计 | 448 |
