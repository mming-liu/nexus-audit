# STAGE REPORT · v1.3（M285 → M292）

> 日期：2026-10-29 ｜ 基线：`v1.2 M281-M284`（e064c66）
> 结论：**链路冒烟 PASS（1643 项断言）**、`doctor` exit 0、`export_disputes --check` 通过。

## 一、这一版解决什么

50 个固定靶场已经冻结为“误报率门禁”，不再承担找新洞。本版把“找洞”搬到一条
可挂机的每日流水线：**每天自动抓 GitHub 新活跃仓 → 只扫有新提交的 → 只报新根因 →
提取完证据即焚缓存**，调度交给 harness 的定时任务，仓库里不再生成 GitHub Actions
或 Windows 计划任务。

```bash
python cli.py daily-hunt --languages java,python,solidity --days 14 --limit 10 --evict-cache
```

## 二、施工项

| 编号 | 交付 | 落点 |
| --- | --- | --- |
| M285 | 每日动态抓仓：`pushed:>{近 N 天} stars:300..30000 archived:false fork:false`，剔除 demo/tutorial/ctf/interview 教学仓，Issues 优先，无网回退离线种子 | `core/context/target_scout.py`（`scout_daily` / `is_tutorial` / `search_query`） |
| M286 | 状态账本：`last_scanned_sha` + `exported_roots`；同 HEAD 直接跳过；只报新引入/未导出根因；`--evict-cache` 即扫即焚 | `core/context/daily_hunt.py`、`benchmarks/results/daily_hunt_state.json`（gitignore） |
| M287 | 陌生野仓板块 A 降噪：`PUBLIC_READONLY_ENDPOINT` / `DEMO_CONTROLLER` 压进 B；`AUTHZ_SIBLING_GUARD` 反向提拔（同文件写接口都带注解、唯它漏加 → HIGH） | `core/context/wild_noise.py` |
| M288 | 大盘「今日巡猎」段：候选/实扫/跳过/失败/新增 + 每仓结果表；板块 A 增加置信度列；JSON 追加 `daily` 段 | `core/context/live_hunt_report.py`、`daily_hunt.py` |
| M289 | 调度改为 harness 定时任务（每天 09:00 Asia/Shanghai），**不生成** `nexus-daily-hunt.yml`，**不注册** `register_daily_hunt_task.ps1` | README + 冒烟 [280] 反向锁 |
| M290 | 售前免费试扫预览单：`client-audit <dir> --presale-preview` 只出 `00_PRESALE_PREVIEW.md` + 管理层摘要，不生成补丁/PoC/复测 | `core/reporting/client_deliverable.py`、`cli.py` |
| M292 | 冒烟 [274]–[280] + 版本 1.3.0 + 1643 项断言里程碑 | `benchmarks/smoke_test_chains.py`、`core/__init__.py` |

## 三、顺手修掉的真 bug

`head_age_days == 0.0`（HEAD 提交就在今天）被 `or 999999` 当成“未知”，导致
**任何今天刚提交的仓库都被判 `STALE_REPO`**。这正是每日巡猎最常遇到的情形
（`pushed` 窗口内的仓 HEAD 往往就是今天），不修则板块 A 永远为空。
已在 `live_hunt.run_one` 与 `live_hunt_report._board` 两侧按“只把 None/空串当未知”修正，
并补了冒烟 [277] 的端到端断言。

## 四、验证记录

| 项目 | 结果 |
| --- | --- |
| `python benchmarks/smoke_test_chains.py` | PASS ✔ 1643 项断言（含新增 [274]–[280]） |
| `python cli.py doctor` | exit 0（十二段全绿） |
| `python benchmarks/export_disputes.py --check` | 4 条争议证据逐字对上源码 |
| `daily-hunt --dry-run --offline` | 不落盘、exit 0 |
| 真实仓（newbee-mall-api）走完整 dedup | 扫描/查重/写报告/写账本全链路正常；HEAD 2023 → 不计入板块 A（符合门禁） |

## 五、已知边界

- harness 的定时任务是**会话级**的：DeepSeek Harness 不在运行时不会触发；要长期挂机，
  需保持该会话/应用常驻（或改回系统级计划任务，但那会重新引入仓库外依赖）。
- 每日巡猎要判 `ZERO_RECORD_FRESH` 必须联网查重（NVD/CIRCL/GitHub）；`--offline-dedup`
  只会产出 `UNKNOWN`，这是“没查过就不许说新鲜”的既有口径。
- `exported_roots` 只增不减：同一“类目 / 入口 / 文件”根因只报一次；需要重报时删账本对应条目或整份账本。
