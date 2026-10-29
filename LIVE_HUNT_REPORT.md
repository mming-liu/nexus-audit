# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-29 22:15:01
- 总条数：6 ｜ 板块 A：**6** ｜ 板块 B：**0**
- 状态计数：ZERO_RECORD_FRESH 6 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 0

<!-- live_hunt_counts: {"BOARD_A": 6, "BOARD_B": 0, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 0, "ZERO_RECORD_FRESH": 6} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 7 个缓存。

- 候选仓：10 ｜ 实扫：7 ｜ 跳过：0 ｜ 失败：3 ｜ 候选来源：github_search
- 本次新增根因：6 ｜ 板块 A：6 ｜ 拦截进 B：0

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| jazzband/django-sortedm2m | d113f8d68249 | SCANNED | 0 |
| roboflow/trackers | c473ab5520c6 | SCANNED | 0 |
| UKGovernmentBEIS/inspect_ai | c07fcbf01fbd | SCANNED | 6 |
| MIgHTy-alIeN/ethereum-flashloan-mev-bot | bc396306c5d7 | SCANNED | 0 |
| google/copybara | 6843b48cf02a | SCANNED | 0 |
| Zettelkasten-Team/Zettelkasten | d58c86c31cf3 | SCANNED | 0 |
| epam/ai-dial-core | 87a7ec71534b | SCANNED | 0 |
| huggingface/lighteval |  | FAILED | 0 |
| neo4j/neo4j-python-driver |  | FAILED | 0 |
| useblocks/sphinx-needs |  | FAILED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | inspect_ai | authz | list_eval_samples | — | 2026-10-29 (0.0d) | c07fcbf01fbd | [src/inspect_ai/_control/server.py:798](https://github.com/UKGovernmentBEIS/inspect_ai/blob/c07fcbf01fbd83e5b61c90c0e3b6288b98a8c303/src/inspect_ai/_control/server.py#L798) | [Advisory](https://github.com/UKGovernmentBEIS/inspect_ai/security/advisories/new) · [Issue](https://github.com/UKGovernmentBEIS/inspect_ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/inspect_ai_authz_list_eval_samples/SUBMISSION_PLAYBOOK.md) |
| 2 | inspect_ai | authz | sample_cancel | — | 2026-10-29 (0.0d) | c07fcbf01fbd | [src/inspect_ai/_control/server.py:1224](https://github.com/UKGovernmentBEIS/inspect_ai/blob/c07fcbf01fbd83e5b61c90c0e3b6288b98a8c303/src/inspect_ai/_control/server.py#L1224) | [Advisory](https://github.com/UKGovernmentBEIS/inspect_ai/security/advisories/new) · [Issue](https://github.com/UKGovernmentBEIS/inspect_ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/inspect_ai_authz_sample_cancel/SUBMISSION_PLAYBOOK.md) |
| 3 | inspect_ai | authz | sample_score_status | — | 2026-10-29 (0.0d) | c07fcbf01fbd | [src/inspect_ai/_control/server.py:1191](https://github.com/UKGovernmentBEIS/inspect_ai/blob/c07fcbf01fbd83e5b61c90c0e3b6288b98a8c303/src/inspect_ai/_control/server.py#L1191) | [Advisory](https://github.com/UKGovernmentBEIS/inspect_ai/security/advisories/new) · [Issue](https://github.com/UKGovernmentBEIS/inspect_ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/inspect_ai_authz_sample_score_status/SUBMISSION_PLAYBOOK.md) |
| 4 | inspect_ai | authz | task_pause | — | 2026-10-29 (0.0d) | c07fcbf01fbd | [src/inspect_ai/_control/server.py:1073](https://github.com/UKGovernmentBEIS/inspect_ai/blob/c07fcbf01fbd83e5b61c90c0e3b6288b98a8c303/src/inspect_ai/_control/server.py#L1073) | [Advisory](https://github.com/UKGovernmentBEIS/inspect_ai/security/advisories/new) · [Issue](https://github.com/UKGovernmentBEIS/inspect_ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/inspect_ai_authz_task_pause/SUBMISSION_PLAYBOOK.md) |
| 5 | inspect_ai | authz | task_resume | — | 2026-10-29 (0.0d) | c07fcbf01fbd | [src/inspect_ai/_control/server.py:1085](https://github.com/UKGovernmentBEIS/inspect_ai/blob/c07fcbf01fbd83e5b61c90c0e3b6288b98a8c303/src/inspect_ai/_control/server.py#L1085) | [Advisory](https://github.com/UKGovernmentBEIS/inspect_ai/security/advisories/new) · [Issue](https://github.com/UKGovernmentBEIS/inspect_ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/inspect_ai_authz_task_resume/SUBMISSION_PLAYBOOK.md) |
| 6 | inspect_ai | authz | task_score_status | — | 2026-10-29 (0.0d) | c07fcbf01fbd | [src/inspect_ai/_control/server.py:1125](https://github.com/UKGovernmentBEIS/inspect_ai/blob/c07fcbf01fbd83e5b61c90c0e3b6288b98a8c303/src/inspect_ai/_control/server.py#L1125) | [Advisory](https://github.com/UKGovernmentBEIS/inspect_ai/security/advisories/new) · [Issue](https://github.com/UKGovernmentBEIS/inspect_ai/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/inspect_ai_authz_task_score_status/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 6 |
| B（其余状态） | 0 |
| 合计 | 6 |
