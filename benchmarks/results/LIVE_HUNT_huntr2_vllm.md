# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/live_hunt_huntr2_vllm.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-30 23:26:28
- 总条数：7 ｜ 板块 A：**0** ｜ 板块 B：**7**
- 状态计数：ZERO_RECORD_FRESH 0 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 5 / PATCHED_UPSTREAM 2 / STALE_REPO 0 / UNKNOWN 0

<!-- live_hunt_counts: {"BOARD_A": 0, "BOARD_B": 7, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 5, "PATCHED_UPSTREAM": 2, "STALE_REPO": 0, "UNKNOWN": 0, "ZERO_RECORD_FRESH": 0} -->

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | vllm | authz | RoutedExperts | **PATCHED_UPSTREAM** | — | unit_not_found_on_head | https://github.com/vllm-project/vllm/blob/6a95c89c371939997d9ce3b616360b529760f0bc/vllm/model_executor/layers/fused_moe/routed_experts.py#L73 |
| 2 | vllm | log_injection | create_score_v1 | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-vvpg-rrww-wpmh、GHSA-8397-8qf6-f2gm、GHSA-h3rc-j82p-2c3h、GHSA-6cxc-2vcg-w5qc、GHSA-q97c-p368-75c4 | local_seed_hit | https://api.github.com/repos/vllm-project/vllm/security-advisories |
| 3 | vllm | log_injection | reset_encoder_cache | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-vvpg-rrww-wpmh、GHSA-8397-8qf6-f2gm、GHSA-h3rc-j82p-2c3h、GHSA-6cxc-2vcg-w5qc、GHSA-q97c-p368-75c4 | local_seed_hit | https://api.github.com/repos/vllm-project/vllm/security-advisories |
| 4 | vllm | log_injection | reset_mm_cache | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-vvpg-rrww-wpmh、GHSA-8397-8qf6-f2gm、GHSA-h3rc-j82p-2c3h、GHSA-6cxc-2vcg-w5qc、GHSA-q97c-p368-75c4 | local_seed_hit | https://api.github.com/repos/vllm-project/vllm/security-advisories |
| 5 | vllm | log_injection | reset_prefix_cache | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-vvpg-rrww-wpmh、GHSA-8397-8qf6-f2gm、GHSA-h3rc-j82p-2c3h、GHSA-6cxc-2vcg-w5qc、GHSA-q97c-p368-75c4 | local_seed_hit | https://api.github.com/repos/vllm-project/vllm/security-advisories |
| 6 | vllm | log_injection | start_profile | **PATCHED_UPSTREAM** | — | empty_method_body_on_head | https://github.com/vllm-project/vllm/blob/6a95c89c371939997d9ce3b616360b529760f0bc/vllm/entrypoints/serve/profile/api_router.py#L38 |
| 7 | vllm | log_injection | stop_profile | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-vvpg-rrww-wpmh、GHSA-8397-8qf6-f2gm、GHSA-h3rc-j82p-2c3h、GHSA-6cxc-2vcg-w5qc、GHSA-q97c-p368-75c4 | local_seed_hit | https://api.github.com/repos/vllm-project/vllm/security-advisories |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 0 |
| B（其余状态） | 7 |
| 合计 | 7 |
