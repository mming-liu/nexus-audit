# STAGE REPORT · v1.5.4（M366：证据不足根因必须报数）

> 日期：2026-11-13 ｜ 基线：v1.5.3（1178cab）
> 结论：v1.5.3 修掉了"假重复压掉真根因"；复核今日报告时又发现第二处
> **静默丢失** —— NVD 熔断压成 UNKNOWN 的 515 条根因，A/B 两板都不显示。
> 已在报告头部显式报数。

## 一、问题：515 条根因既不进 A 也不进 B

今日（2026-11-13）`daily_hunt.json` 只有 38 行，且全是本地降噪项：

| 项 | 值 |
|---|---|
| 报告行数 | 38（B 板） |
| 其中 | `LOW_SEVERITY_LOG_INJECTION` 29 + `NO_SQL_SINK` 9 |
| dedup 缓存 UNKNOWN | **515**（515/515 都是 `nvd_circuit_open`） |

代码路径：v1.5.1 把"NVD 熔断"的候选降成 `UNKNOWN`（`INCOMPLETE_DEDUP_EVIDENCE`），
但 `process_repo()` 只保留 `noise_code` 与 `ZERO_RECORD_FRESH` 两类记录，
其余 `continue` —— 于是这些根因**在报告里完全消失**，既不在 A 也不在 B。

这比 v1.5.3 的假重复更隐蔽：假重复至少能在 `matched_ids` 里看到证据，
静默丢弃连"被丢过"都看不出来。

## 二、修复（M366）

| 位置 | 改动 |
|---|---|
| `daily_hunt.is_incomplete_dedup()` | 识别 `status=UNKNOWN` 且 `reason` 以 `INCOMPLETE_DEDUP_EVIDENCE` 开头的记录 |
| `process_repo()` | 丢弃前计数，返回 `incomplete_dedup` |
| `run()` | 跨仓累加，写入 `daily_meta["incomplete_dedup"]` |
| `_header()` | 报告头部新增一行：`- 证据不足未列：N 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）` |

**为什么只报数、不逐条列进 B**：NVD 熔断时几乎**每个**根因都会落到这一类
（今日 515 条），逐条列会把 B 板变成 500+ 行"不可判"的噪音，反而埋掉真正
可交单的项。报数能让人立刻看到"NVD 挂了"，要逐条复核再加开关。

## 三、门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,607 项**（+4：`[327]`） |
| `triage_fallbacks.py --check-floor` | 16/16 |
| `cli.py doctor` | PASS |
| `.githooks/pre-push` | exit 0 |

## 四、遗留

1. 今日报告不重生成（38 行是真实输出，515 条需重扫才会回到流程）。
2. NVD 熔断仍是主瓶颈；`incomplete_dedup` 这个数会一直很大，直到 NVD 恢复
   或换出口。
3. 若需要"逐条列出证据不足项"，建议加 `--list-incomplete`（默认关）。
