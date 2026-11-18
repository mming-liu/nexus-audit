# STAGE REPORT · v1.5.24（M443–M446：候选供给修复 / 空页回退 / 翻页冷却过滤）

> 执行日期：2026-11-18 08:00 ｜ 基线：v1.5.23（`2ed6b61`）
> 主题：修复 `target_scout.py` 中导致 2026-11-17 只回 1 个候选的三个精确
> Bug（词池与 `_TOOL_LIB_RE` 冲突、`page>1` 空页不回退、翻页漏
> `scanned_at` 过滤），并复跑在线巡猎验证供给恢复。
> 结论：在线巡猎从 **1 候选** 恢复到 **14 候选 / 7 实扫 / 0 失败**；
> 新出 6 条 A 经白盒精核：5 条规则假阳（SnackBase regex_dos ×3、
> Wukong redir ×1、movo upload ×1）已修，剩 1 条 Wukong `securecookie`
> 为真实低危（Cookie 缺 `Secure`）；3 仓复扫 **A 6 → 1**。
> 门禁 smoke **1,800** / triage 16/16 / doctor PASS。

## 一、M443：词池去冲突（`core/context/target_scout.py`）

`NEW_GEN_KEYWORDS` 的 java/python 各 30 词，保留前 15 项不变，后 15 项
移除与 `_TOOL_LIB_RE` 冲突的 `ollama`/`dify`/`vllm`/`openwebui`/`fastgpt`/
`langgraph`/`crewai`/`autogen`，替换为通用 Web 业务词：

- java：`admin cms erp crm mall oa shop pay studio panel gateway console portal nas webhook`
- python：`fastapi django flask admin cms erp crm mall studio panel gateway console portal nas webhook`

验证：30×2 个词逐一 `is_tool_lib()` 均为 False（`[347]` 第 1 项）。
2026-11-17 轮到的 `"vllm"` 不再出现，Java 轨也不会连续 0 命中烧预算。

## 二、M444：三个翻页 Bug

### 1. `page>1` 空页回退条件（第 795 行）

```python
# 旧：if page > 1 and int(data.get("total_count") or 0) == 0
if (page > 1 and not (data.get("items") or [])
        and not rate_limited):
```

GitHub Search 在总匹配 1..30 条时请求 `page=2` 会返回
`{"total_count": 12, "items": []}`；旧条件因 `total_count != 0` 不回退，
直接解析空列表。现在只要当前页 `items` 为空就回退 `page=1`。

### 2. `_topup_one()` 按需翻页

- 成功取数后 `online_ok += 1`；
- `scanned_at` 过滤同步累加 `dropped_unchanged`；
- 调用方始终传 `page=1`；
- 函数内当 `page == 1`、过滤后 `len(parsed) < 2`、`total_count > per_page`
  且未限流/未耗尽预算时，才补抓一次 `page=2`（不再盲抓第 2 页）。

### 3. 主循环翻页 `more` 的 `scanned_at` 过滤

`while` 条件由 `excluded` 放宽为 `(excluded or scanned_at)`；翻页结果在
`excluded` 过滤后补 `_pushed_before` 过滤并累加 `dropped_unchanged`。

验证（`[347]`）：`page=2` 返回空 `items`、`page=1` 返回
`org/real-erp-web` 时 `scout_daily` 成功回退并拿到候选；翻页 `more` 中
`pushed_at <= scanned_at` 的项被排除、新项保留、`dropped_unchanged >= 1`。

## 三、M445：门禁 `[347]`（4 + 3 项）

| 断言 | 结果 |
|---|---|
| 30×2 新生代词不与 `_TOOL_LIB_RE` 冲突 | ✅ |
| `page=2` 空 items → 回退 `page=1` 拿到候选 | ✅ |
| 翻页 `more` 排除未变项、保留新项 | ✅ |
| 未变项计入 `dropped_unchanged` | ✅ |
| 导入常量作正则模式不判 `regex_dos` | ✅（M446 附带修复） |
| 配置/上下文取址的跳转不判 `redir` | ✅（M446 附带修复） |
| 上传文件名只用于解析、`open` 为常量日志路径 → `None` | ✅（M446 附带修复） |

## 四、M446：在线巡猎 + 白盒精核 + 复扫

### 1. 在线巡猎（参数不变，`--repo-timeout 600`）

```
python cli.py daily-hunt --languages java,python --days 21 --limit 8 \
  --min-stars 300 --max-roots 5 --cooldown-days 7 --repo-timeout 600
```

| 项 | v1.5.23 | v1.5.24 |
|---|---|---|
| 候选 | 1 | **14** |
| 实扫 | 0 | **7** |
| 跳过 | 1 | 7 |
| 失败 | 0 | 0 |
| 新增根因 | 0 | 389 |
| 板块 A / B | 0 / 0 | **6 / 383** |

供给恢复：三个 Bug 修复后，309 仓账本 + 7 天冷却下仍能拿到 14 个候选。

### 2. 新 A 白盒精核（6 条）

| # | 仓库 | 类目 | 结论 |
|---|---|---|---|
| 1-3 | SnackBase | regex_dos ×3（`upload_backup`/`delete_backup`/`download_backup`） | **假阳**：`re.fullmatch(ARCHIVE_NAME_PATTERN, name)` 的模式是导入常量（`^[a-z0-9_-]{1,150}\.zip$`），不是用户可控正则；旧规则把裸标识符一律当 tainted。已修：标识符先查入口形参/局部赋值，导入常量 → False |
| 4 | Wukong-AICRM | redir（`OidcController.minioSso`） | **假阳**：`sendRedirect` 目标由 `RequestContextUtil.getMinioConsoleUrl(oidcConfig...)` 配置拼接，不来自请求参数。已修：目标链上出现 `*Config*/*ContextUtil*.getXxx()` → False |
| 5 | movo | unrestricted_upload（`analyze_template`） | **假阳**：上传内容仅 `BytesIO` 内存解析（docx/pdf/pptx/xlsx），`open()` 只写常量日志 `/tmp/askai_backend_error.log`；旧规则把常量 open 当落盘 sink。已修：sink 实参必须引用 `file.filename`（含一跳别名），否则 None |
| 6 | Wukong-AICRM | securecookie（`OidcController.minioSso`） | **真实低危**：`new Cookie(...)` 设了 `HttpOnly`/`Path`/`MaxAge`，但**没有 `setSecure(true)`**，会话 Cookie 可经 HTTP 发送（CWE-614）。保留在 A 板供人工复核/交单 |

### 3. 3 仓离线复扫

```
python cli.py daily-hunt --repos lalitgehani/SnackBase,WuKongOpenSource/Wukong-AICRM,himovo/movo \
  --offline --cooldown-days 0 --max-roots 5 --state .tmp/m446_state.json \
  --report .tmp/m446_LIVE_HUNT_REPORT.md --json .tmp/m446_daily_hunt.json \
  --packs-dir .tmp/m446_packs --repo-timeout 600
```

| 轮次 | 根因 | 板块 A | 板块 B |
|---|---|---|---|
| v1.5.24 在线巡猎 | 389 | **6** | 383 |
| v1.5.24 3 仓复扫 | 143 | **1** | 142 |

唯一 A：`Wukong-AICRM securecookie OidcController.minioSso`。

## 五、门禁结果

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,800 项断言**（v1.5.23 为 1,793；`[347]` 7 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 六、提交清单

- `core/context/target_scout.py` — M443 词池去冲突 + M444 空页回退/按需翻页/翻页冷却过滤
- `core/agents/rule_detectors.py` — M446 附带修复：regex_dos 常量模式、redir 配置取址、upload 常量 open
- `benchmarks/smoke_test_chains.py` — M445 `[347]` 7 项
- `LIVE_HUNT_REPORT.md` — 本轮在线巡猎（14 候选 / A=6）
- `STAGE_REPORT_2026-11-17_v1.5.24.md` — 本报告
