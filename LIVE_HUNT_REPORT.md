# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-08 09:00:35
- 总条数：40 ｜ 板块 A：**2** ｜ 板块 B：**38**
- 状态计数：ZERO_RECORD_FRESH 2 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 38

<!-- live_hunt_counts: {"BOARD_A": 2, "BOARD_B": 38, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 38, "ZERO_RECORD_FRESH": 2} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 14 个缓存。

- 候选仓：31 ｜ 实扫：8 ｜ 跳过：21 ｜ 失败：2 ｜ 候选来源：github_search
- 本次新增根因：40 ｜ 板块 A：2 ｜ 拦截进 B：38
- 冷却期免克隆：15 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| boommanpro/gaia-workflow-engine | c45955256913 | SKIPPED | 0 |
| Druthulu/ProjectArchitect | e162628314c9 | SKIPPED | 0 |
| holdmyspot-com/cat | 1d282487738b | SKIPPED | 0 |
| KbWen/agentic-os | 82203b5c0689 | SKIPPED | 0 |
| langgraph4j/langgraph4j | 23aef94c1755 | SKIPPED | 0 |
| sbhooley/ainativelang |  | FAILED | 0 |
| Swayingleaves/novanova-studio | 0269e4856fc0 | SKIPPED | 0 |
| microsoft/intelligence-toolkit | f6ee0f21e571 | SKIPPED | 0 |
| quarkiverse/quarkus-flow | dedd3568b556 | SKIPPED | 0 |
| willmiao/ComfyUI-Lora-Manager | f4ea2551a89c | SKIPPED | 0 |
| w8123/EnterpriseAgentFramework | 1f1230d50db0 | SKIPPED | 0 |
| xorbitsai/xagent | 7dc47a883769 | SKIPPED | 0 |
| tmseidel/ai-git-bot | cdfd192ca8c6 | SKIPPED | 0 |
| pytraveler/MiniMax-H3-Prompt-Rewriter-ComfyUI | cf951b1c0cc1 | SCANNED | 1 |
| taishan666/MaxKB4j | e008b2be340f | SKIPPED | 0 |
| drowzeys/Imagination-Studio-by-keys-Wasserman | 79c88086dd90 | SCANNED | 20 |
| risesoft-y9/WorkFlow-Engine | e91293ca1db4 | SKIPPED | 0 |
| sealandseacat/dbmask | d472f4bcf411 | SKIPPED | 0 |
| diudiu-tech/delivery-harness | 3fb2d17354c4 | SCANNED | 2 |
| WenyuChiou/ai-research-skills | b649037b02b8 | SKIPPED | 0 |
| dbos-inc/dbos-transact-java | 514f6d99823b | SKIPPED | 0 |
| daymade/claude-code-skills | dc3eb11ece30 | SCANNED | 3 |
| zeroaihub/Java-Agent-Study | 6b2875e40349 | SCANNED | 8 |
| openJiuwen-ai/iCode | 78848b268d26 | SKIPPED | 0 |
| feng-shan-jian/ApprovaPlat | 971d229e4b0f | SCANNED | 0 |
| SudoHopeX/KaliGPT |  | FAILED | 0 |
| Eleven617/mall-ai-after-sales-platform | 60d53bd1fad3 | SCANNED | 5 |
| Lanqiao-Luca/ai-video-marker | ecc70da022a9 | SKIPPED | 0 |
| stoopid-computers/funchole | 6277878d603c | SCANNED | 1 |
| zhnt/loushang | c3d6f3f18728 | SKIPPED | 0 |
| Zzz1phyrf/ComfyUI-H3-LongVideo | 2e12b50d8fdd | SKIPPED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | MiniMax-H3-Prompt-Rewriter-ComfyUI | nosqli | refmod_preview | — | 2026-11-08 (0.1d) | cf951b1c0cc1 | [minimax_h3_rewriter/routes.py:615](https://github.com/pytraveler/MiniMax-H3-Prompt-Rewriter-ComfyUI/blob/cf951b1c0cc171d1aadb27ae5aac77f893b78f64/minimax_h3_rewriter/routes.py#L615) | [Advisory](https://github.com/pytraveler/MiniMax-H3-Prompt-Rewriter-ComfyUI/security/advisories/new) · [Issue](https://github.com/pytraveler/MiniMax-H3-Prompt-Rewriter-ComfyUI/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/MiniMax-H3-Prompt-Rewriter-ComfyUI_nosqli_refmod_preview/SUBMISSION_PLAYBOOK.md) |
| 2 | funchole | sqli | InvocationActivityController.list | — | 2026-10-09 (30.3d) | 6277878d603c | [controlplane/src/main/java/com/funchole/backend/controlplane/controller/InvocationActivityController.java:32](https://github.com/stoopid-computers/funchole/blob/6277878d603cddf31b7886933221b92dafe216c6/controlplane/src/main/java/com/funchole/backend/controlplane/controller/InvocationActivityController.java#L32) | [Advisory](https://github.com/stoopid-computers/funchole/security/advisories/new) · [Issue](https://github.com/stoopid-computers/funchole/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/funchole_sqli_list/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | Imagination-Studio-by-keys-Wasserman | authz | attach_to_film | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 2 | Imagination-Studio-by-keys-Wasserman | authz | cancel | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 3 | Imagination-Studio-by-keys-Wasserman | authz | cancel_task | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 4 | Imagination-Studio-by-keys-Wasserman | authz | change_thread | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 5 | Imagination-Studio-by-keys-Wasserman | authz | get_job | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 6 | Imagination-Studio-by-keys-Wasserman | authz | import_prompts | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 7 | Imagination-Studio-by-keys-Wasserman | authz | one_import | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 8 | Imagination-Studio-by-keys-Wasserman | authz | one_task | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 9 | Imagination-Studio-by-keys-Wasserman | authz | one_thread | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 10 | Imagination-Studio-by-keys-Wasserman | authz | remove_thread | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 11 | Imagination-Studio-by-keys-Wasserman | authz | reply | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 12 | Imagination-Studio-by-keys-Wasserman | authz | save_project | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 13 | Imagination-Studio-by-keys-Wasserman | authz | stop_thread | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 14 | Imagination-Studio-by-keys-Wasserman | authz | take_audio | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | Imagination-Studio-by-keys-Wasserman | authz | take_live | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | Imagination-Studio-by-keys-Wasserman | authz | take_live | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | Imagination-Studio-by-keys-Wasserman | authz | to_editor | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | Imagination-Studio-by-keys-Wasserman | authz | to_motion | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 19 | Imagination-Studio-by-keys-Wasserman | authz | to_slate | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 20 | Imagination-Studio-by-keys-Wasserman | authz | tool_check | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 21 | Java-Agent-Study | authz | AdminController.grant | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | Java-Agent-Study | authz | KnowledgeWorkspaceController.createKnowledgeBase | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | Java-Agent-Study | authz | KnowledgeWorkspaceController.createWorkspace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 24 | Java-Agent-Study | deserial | Demo8StructuredOutput.agentDecide | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 25 | Java-Agent-Study | deserial | Demo8StructuredOutput.byJsonFormat | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 26 | Java-Agent-Study | deserial | Demo8StructuredOutput.byPrompt | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 27 | Java-Agent-Study | xss | Demo2ChatCompletions.creative | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 28 | Java-Agent-Study | xss | Demo2ChatCompletions.precise | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 29 | claude-code-skills | authz | api_audio | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 30 | claude-code-skills | authz | api_context | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 31 | claude-code-skills | authz | api_queue | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 32 | delivery-harness | authz | KnowledgeController.search | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 33 | delivery-harness | authz | OperationsController.audit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 34 | mall-ai-after-sales-platform | authz | list_agent_tasks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 35 | mall-ai-after-sales-platform | authz | service_case_cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 36 | mall-ai-after-sales-platform | authz | service_case_customer_information | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 37 | mall-ai-after-sales-platform | authz | service_case_reopen | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 38 | mall-ai-after-sales-platform | authz | service_case_timeline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 2 |
| B（其余状态） | 38 |
| 合计 | 40 |
