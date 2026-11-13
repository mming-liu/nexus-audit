# STAGE REPORT · v1.5.5（M367–M370：裸 authz 前置拦截 / NVD 多源仲裁 / 极速重扫）

> 日期：2026-11-13 ｜ 基线：v1.5.4（9d9f029）
> 结论：查重调用从 **515 次降到 14 次**，GitHub 403 从 171 次降到 **0**；
> NVD 仍熔断，但 M368 的四源仲裁让 9 条候选重新浮上 A 板 —— 逐条精核后
> **全部为假阳**（SQLAlchemy 被误判为拼接 SQL）。

## 一、M367：裸 authz 前置拦截 + max_roots 默认 5

| 改动 | 位置 |
|---|---|
| `is_bare_wild_authz()`：`authz` + 非 HIGH 提拔 + 无 `/admin` 路由 | `daily_hunt.py` |
| 在 `process_repo()` 的 **promote 之后、进 kept 之前**直接压 `blocked_roots`（0 请求、不占名额） | 同上 |
| `run(max_roots=5)`；`cli daily-hunt --max-roots` 默认 5（0=不限） | `daily_hunt.py` / `cli.py` |
| 新增 `--repos`：显式重扫名单，跳过侦察 | `daily_hunt.py` / `cli.py` |

上午 515 次查重里约 460 次是这类裸 authz；重扫实测 **14 次**。

## 二、M368：NVD 熔断不再一票否决

- `_dedup_quorum_ok()`：CIRCL + 仓内 GHSA + 全网 GHSA + 仓内 Issue
  **四源全部成功返回**（0 命中）时，NVD 熔断也判 `ZERO_RECORD_FRESH`；
- 记录 `nvd_fallback="CIRCL+GHSA"`、`evidence_gaps` 写入
  `nvd_circuit_open_fallback_circl_ghsa`；报告头部新增
  「NVD 熔断兜底：N 条经 CIRCL+GHSA 仲裁」；
- 仅当 NVD+CIRCL 双挂，或仓内 Issue/GHSA 403 限流时，才压
  `UNKNOWN + INCOMPLETE_DEDUP_EVIDENCE`（原因精确到源）；
- `NVD_API_KEY` 环境变量 → 请求头 `apiKey`。

## 三、M369：门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,616 项**（+9：`[328]`） |
| `triage_fallbacks.py --check-floor` | 16/16 |
| `cli.py doctor` | PASS |
| `.githooks/pre-push` | exit 0 |

`[328]` 覆盖：裸 authz 不发查重（dedup_fn 调用 0 次）、直接进 B；
NVD 熔断+四源全通 → FRESH（带 fallback 标记）；NVD+CIRCL 双挂 → UNKNOWN；
Issue 403 → UNKNOWN；`max_roots` 默认 5。

## 四、M370：重扫今日 8 仓

命令：`daily-hunt --repos <8 仓> --max-roots 5 --cooldown-days 0`（独立 state/report，
不覆盖当日正式报告）。

| 指标 | 上午 | 重扫 |
|---|---|---|
| dedup 调用 | 515 | **14** |
| GitHub 403 | 171 | **0** |
| 板块 A | 0 | 9（**全部假阳**） |
| 耗时 | 82 分钟 | ~17 分钟（8 个冷克隆；热缓存复跑约 3–5 分钟） |

9 条 A 候选逐条源码精核见
[rescan_2026-11-13_review.md](benchmarks/results/rescan_2026-11-13_review.md)：
全部是 `sqli`/`mass_assignment` 误判 —— `select(Model).where(col == param)`
被当成拼接 SQL，其中 `list_skills`/`list_tool_configs` 体内根本没有 SQL。

## 五、下一步（建议 M371）

1. `sqli_verdict` 识别 SQLAlchemy 参数化写法（`select().where(col == v)`、
   `t.c.x == v`、`.in_(...)`），不判 True；
2. 把 `NO_SQL_SINK` 从"文件级"收紧到"入口级"：入口体无 SQL 字面量/执行调用
   时不因切片里的兄弟函数判 sqli；
3. NVD 仍是 0 命中的唯一缺口，`NVD_API_KEY` 配好后 A 板可去掉 fallback 标记。
