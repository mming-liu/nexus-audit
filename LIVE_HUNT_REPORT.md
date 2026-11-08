# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-08 10:29:11
- 总条数：6 ｜ 板块 A：**5** ｜ 板块 B：**1**
- 状态计数：ZERO_RECORD_FRESH 5 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 1

<!-- live_hunt_counts: {"BOARD_A": 5, "BOARD_B": 1, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 1, "ZERO_RECORD_FRESH": 5} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 3 个缓存。

- 候选仓：22 ｜ 实扫：1 ｜ 跳过：19 ｜ 失败：2 ｜ 候选来源：github_search
- 本次新增根因：6 ｜ 板块 A：5 ｜ 拦截进 B：1
- 冷却期免克隆：18 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| Swayingleaves/novanova-studio | 0269e4856fc0 | SKIPPED | 0 |
| sbhooley/ainativelang |  | FAILED | 0 |
| boommanpro/gaia-workflow-engine | c45955256913 | SKIPPED | 0 |
| iha2/superlite | 9747f27e49ed | SKIPPED | 0 |
| langgraph4j/langgraph4j | 23aef94c1755 | SKIPPED | 0 |
| KbWen/agentic-os | 82203b5c0689 | SKIPPED | 0 |
| w8123/EnterpriseAgentFramework | 5203cf772114 | SCANNED | 6 |
| xorbitsai/xagent | 7dc47a883769 | SKIPPED | 0 |
| tmseidel/ai-git-bot | cdfd192ca8c6 | SKIPPED | 0 |
| drowzeys/Imagination-Studio-by-keys-Wasserman | 79c88086dd90 | SKIPPED | 0 |
| risesoft-y9/WorkFlow-Engine | e91293ca1db4 | SKIPPED | 0 |
| sealandseacat/dbmask | d472f4bcf411 | SKIPPED | 0 |
| diudiu-tech/delivery-harness | 3fb2d17354c4 | SKIPPED | 0 |
| WenyuChiou/ai-research-skills | b649037b02b8 | SKIPPED | 0 |
| dbos-inc/dbos-transact-java | 514f6d99823b | SKIPPED | 0 |
| daymade/claude-code-skills | dc3eb11ece30 | SKIPPED | 0 |
| feng-shan-jian/ApprovaPlat | 971d229e4b0f | SKIPPED | 0 |
| openJiuwen-ai/iCode | 78848b268d26 | SKIPPED | 0 |
| SudoHopeX/KaliGPT |  | FAILED | 0 |
| Lanqiao-Luca/ai-video-marker | ecc70da022a9 | SKIPPED | 0 |
| zhnt/loushang | c3d6f3f18728 | SKIPPED | 0 |
| isaac-for-healthcare/i4h-workflows | 2ab93f52bb0d | SKIPPED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | EnterpriseAgentFramework | deserial | InternalAgentSkillCatalogController.resolveExecution | — | 2026-11-07 (1.0d) | 5203cf772114 | [reachai-control-service/src/main/java/com/enterprise/ai/control/internal/InternalAgentSkillCatalogController.java:39](https://github.com/w8123/EnterpriseAgentFramework/blob/5203cf77211430d148b5253db6b496caddbf23bd/reachai-control-service/src/main/java/com/enterprise/ai/control/internal/InternalAgentSkillCatalogController.java#L39) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_deserial_resolveExecution/SUBMISSION_PLAYBOOK.md) |
| 2 | EnterpriseAgentFramework | sqli | PlatformEmbedPublicController.claimPageAction | — | 2026-11-07 (1.0d) | 5203cf772114 | [reachai-control-service/src/main/java/com/enterprise/ai/control/platform/PlatformEmbedPublicController.java:536](https://github.com/w8123/EnterpriseAgentFramework/blob/5203cf77211430d148b5253db6b496caddbf23bd/reachai-control-service/src/main/java/com/enterprise/ai/control/platform/PlatformEmbedPublicController.java#L536) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_claimPageAction/SUBMISSION_PLAYBOOK.md) |
| 3 | EnterpriseAgentFramework | sqli | PlatformEmbedPublicController.submitPageActionResult | — | 2026-11-07 (1.0d) | 5203cf772114 | [reachai-control-service/src/main/java/com/enterprise/ai/control/platform/PlatformEmbedPublicController.java:460](https://github.com/w8123/EnterpriseAgentFramework/blob/5203cf77211430d148b5253db6b496caddbf23bd/reachai-control-service/src/main/java/com/enterprise/ai/control/platform/PlatformEmbedPublicController.java#L460) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_submitPageActionResult/SUBMISSION_PLAYBOOK.md) |
| 4 | EnterpriseAgentFramework | sqli | PlatformRunCenterConversationController.detail | — | 2026-11-07 (1.0d) | 5203cf772114 | [reachai-control-service/src/main/java/com/enterprise/ai/control/platform/PlatformRunCenterConversationController.java:99](https://github.com/w8123/EnterpriseAgentFramework/blob/5203cf77211430d148b5253db6b496caddbf23bd/reachai-control-service/src/main/java/com/enterprise/ai/control/platform/PlatformRunCenterConversationController.java#L99) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_detail/SUBMISSION_PLAYBOOK.md) |
| 5 | EnterpriseAgentFramework | sqli | PlatformRunCenterConversationController.list | — | 2026-11-07 (1.0d) | 5203cf772114 | [reachai-control-service/src/main/java/com/enterprise/ai/control/platform/PlatformRunCenterConversationController.java:50](https://github.com/w8123/EnterpriseAgentFramework/blob/5203cf77211430d148b5253db6b496caddbf23bd/reachai-control-service/src/main/java/com/enterprise/ai/control/platform/PlatformRunCenterConversationController.java#L50) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_list/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | EnterpriseAgentFramework | unchecked_low_level_calls | RuntimePublicController.clearAgentSession | **UNKNOWN** | — | RULE_LANGUAGE_MISMATCH: unchecked_low_level_calls 是 Solidity 类目，入口文件是 .java | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 5 |
| B（其余状态） | 1 |
| 合计 | 6 |
