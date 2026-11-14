# STAGE REPORT · v1.5.11（M391–M394：时区归一 + 轻量克隆 + 侦察可观测性）

> 日期：2026-11-14 ｜ 基线：v1.5.10（63982d2）
> 结论：`_pushed_before` 的 UTC/本地混算已修；克隆改轻量模式后实测 0 失败；
> 报告头部能显式看到 `dropped_unchanged` 与 `http_403` 告警；验证巡猎捞出
> 1 条 A（ERC20 规则误判 Python 路由），当轮修复并复扫 **A=0**。

## 一、M391：时区归一

`_ts_epoch()`：`...Z` / 带偏移量 → UTC epoch；无时区标记的 `last_scanned_at`
按本地时区解释后转 epoch；`_pushed_before` 改为 epoch 比较。

旧实现去 `Z` 后裸字符串比较，在 UTC+8 下把"扫描后 8 小时内"的新 push 误判为
"未变"，会白白跳过刚更新的仓。

单测：本地 `2026-11-14 20:28:00`（=12:28Z）扫描后，`15:00Z` 的新 push
→ `False`（不算未变）；`10:00Z` → `True`。

## 二、M392：PoC 过滤 + 轻量克隆

1. `_TOOL_LIB_RE` 补 `poc|pocs|vulnerability-wiki|vuln-wiki|writeup|writeups|
   payloads|nuclei-templates|cve-\d{4}` —— `SourByte05/Vulnerability-Wiki-PoC`
   在侦察阶段被 `is_tool_lib` 拦截（`True`），普通 CRM 仓不受影响（`False`）。
2. `upstream_sync.sync_repo()`：
   - 首次克隆不再先 `ls-remote` 探测默认分支（瞬断会盲退 `main`，非 main 仓必失败），
     直接 `git clone --depth N --filter=blob:none --single-branch --no-tags`；
   - 老 git 不支持 `--filter` 时自动回退普通 `--depth N --single-branch --no-tags`；
   - 残留目录（无 `.git/HEAD`）先安全清理；
   - 克隆后 `git rev-parse HEAD` + `rev-parse --abbrev-ref HEAD` 取 `head_sha`/`branch`。

实测：验证巡猎 1 个候选 **0 失败**（此前同类仓常出现空 HEAD FAILED）。

## 三、M393：报告可观测性 + 限流预算

1. `LIVE_HUNT_REPORT.md` 头部新增：
   - `- 侦察免克隆排除（未变老仓）：N 个`（`scout.dropped_unchanged`）；
   - `- 侦察告警：...`（`scout.error` 非空时打印，不再静默吞 403）；
   - 账本表 `FAILED (clone_failed: ...)` / `SKIPPED (unchanged_head)` 带简短原因。
2. `scout_daily()` 限流保护：
   - 任一 `_get` 返回 403/429 → `rate_limited=True`，**立即终止**主循环剩余项、
     关键词顺延、翻页与 M380 补拉；
   - 限流且有效候选为 0 → 回退离线种子并标注 `source="github_search_rate_limited"`。

实测报告头部：

```
- 侦察免克隆排除（未变老仓）：0 个
- 侦察告警：python: http_403
```

## 四、M394：门禁与实盘验证

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,664 项**（`[334]` 12 项） |
| `triage_fallbacks.py --check-floor` | **16/16** |
| `cli.py doctor` | PASS |
| `.githooks/pre-push` | exit 0 |

`[334]`：时区两例、PoC 过滤两例、`--filter=blob:none`、头部三字段、
FAILED/SKIPPED 原因、限流识别两例、Python 不判 ERC20 类目。

### 验证巡猎（22:32）

| 项 | 值 |
|---|---|
| 候选 / 实扫 / 跳过 / 失败 | 1 / 1 / 0 / **0** |
| 根因 | 401（A=1，B=400） |
| A 候选 | `agenticos` `unchecked_erc20_return` `backend/app/api/routes/v1/phone.py:83` |

精核：Python FastAPI 路由 `transfer(a, b)` 被 **Solidity 专属**的
`unchecked_erc20_return` 规则判 True —— 语言不匹配假阳。
当轮修复：`SOLIDITY_ONLY` 补 `unchecked_erc20_return` / `oracle_stale_price`
（`fa1dbd8`），复扫 `agenticos` → **402 条根因、A=0、B=402**。

## 五、提交

- `df88ddd` — v1.5.11 代码（M391–M393）
- `fa1dbd8` — ERC20 类目限定 Solidity 文件（M394 精核修复）
- 后续 docs 提交 — 本报告 + 巡猎报告
