# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-07 15:22:32
- 总条数：1 ｜ 板块 A：**1** ｜ 板块 B：**0**
- 状态计数：ZERO_RECORD_FRESH 1 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 0

<!-- live_hunt_counts: {"BOARD_A": 1, "BOARD_B": 0, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 0, "ZERO_RECORD_FRESH": 1} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 5 个缓存。

- 候选仓：5 ｜ 实扫：3 ｜ 跳过：2 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：1 ｜ 板块 A：1 ｜ 拦截进 B：0
- 冷却期免克隆：0 个（已关闭）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| jingsewu/open-wes | c85c6ac50cbc | SKIPPED | 0 |
| lasswellt/govee-homeassistant | 7216551ad43a | SKIPPED | 0 |
| opentiny/tiny-engine-backend-java | b06d169ea6df | SCANNED | 0 |
| suoten/ProtoForge | ec88708ad14b | SCANNED | 0 |
| oinone/oinone-pamirs | 32d4a041f66d | SCANNED | 1 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | oinone-pamirs | pathtraver | LocalFileClient.getStaticFile | — | 2026-09-03 (64.9d) | 32d4a041f66d | [pamirs-framework/pamirs-connectors-cdn/src/main/java/pro/shushi/pamirs/framework/connectors/cdn/client/LocalFileClient.java:76](https://github.com/oinone/oinone-pamirs/blob/32d4a041f66d64592ddcc6f935639d81265871ca/pamirs-framework/pamirs-connectors-cdn/src/main/java/pro/shushi/pamirs/framework/connectors/cdn/client/LocalFileClient.java#L76) | [Advisory](https://github.com/oinone/oinone-pamirs/security/advisories/new) · [Issue](https://github.com/oinone/oinone-pamirs/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/oinone-pamirs_pathtraver_getStaticFile/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 1 |
| B（其余状态） | 0 |
| 合计 | 1 |
