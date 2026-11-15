# STAGE REPORT · v1.5.14（M403–M406：动态顺延 / 缓存沙箱 / 回填分账 / 失败冷却）

> 日期：2026-11-15 ｜ 基线：v1.5.13（`f58044b`）
> 主题：同日暖缓存复跑不再 0 候选；相邻日查询词 0 重叠；冒烟测试全局缓存
> 沙箱；回填来源精确分账；超时/失败仓 3 天冷却。
> 结论：**未清缓存、未重置状态**的同日暖缓存实盘跑出 **14 候选 / 8 实扫 /
> 452 根因（板块 A 8）**，0 次 403；`[337]` 12 项离线门禁全绿，冒烟
> 1,731 项；`YunaiV/ruoyi-vue-pro` 未再进入本轮（不再重复卡 300s）。

## 一、M403：相邻日词去重 + 预算驱动动态顺延

### 1. 相邻天查询词 0 重叠

词索引从 `day_index + k` 改为按"每轮词数"步进：

```python
base_ng = day_index * max(1, ng)          # 新生代
keyword = new_keywords[(base_ng + k) % len(new_keywords)]

base_trad = day_index * max(1, traditional_terms)   # 传统轨
offset = base_trad + k
```

实测（`today=2026-11-15` vs `2026-11-16`，`terms_per_language=2`）：

| 语言/轨道 | 11-15 | 11-16 | 交集 |
|---|---|---|---|
| java new_gen | `"spring-boot" "rag"` | `"spring-boot" "agent"` | ∅ |
| java traditional | `mes` | `wms` | ∅ |
| python new_gen | `fastapi "rag"` | `fastapi "agent"` | ∅ |
| python traditional | `fastapi admin` | `fastapi cms` | ∅ |

旧写法在 `terms=2` 时相邻天有 50% 重叠（第二天一半查询是昨天跑过的缓存页）。

### 2. 预算驱动的动态顺延补拉

M380 补拉循环的固定 `extra_rounds < 2` 升级为：

```python
max_extra_rounds = 8
while (allow_online and extra_rounds < max_extra_rounds
       and not rate_limited and not budget_exhausted
       and _candidate_count() < max(1, int(limit))
       and not _rate_limited()):
```

每轮同时轮换**新生代下一顺位词**与**传统轨下一顺位词**：

- 新生代：`kws[(day_index * max(1, ng) + ng + round - 1) % len(kws)]`
- 传统轨：`offset = day_index * max(1, traditional_terms) + traditional_terms + round - 1`

关键点：顺延查询命中本地缓存（`from_cache=True`）**不消耗 `http_requests`**，
所以循环会连续跨过"已扫缓存轮次"，直到翻到当天未查过的轮换词、用剩余预算
真正抓回新候选。这正是 v1.5.13 同日暖缓存 0 候选（预算未耗尽却受
`extra_rounds < 2` 限制）的根治点。

## 二、M404：冒烟全局缓存沙箱 + 假仓写盘守卫

### 1. 进程级沙箱

`benchmarks/smoke_test_chains.py` 顶部（`_ws_mkdtemp` 就绪后）初始化：

```python
_SMOKE_SCOUT_CACHE_DIR = _ws_mkdtemp("nexus_smoke_scout_")
_os.environ["NEXUS_SCOUT_CACHE_DIR"] = _SMOKE_SCOUT_CACHE_DIR
_atexit.register(lambda: _shutil_mod.rmtree(_SMOKE_SCOUT_CACHE_DIR,
                                            ignore_errors=True))
```

整套冒烟中任何未显式传 `cache_dir` 的 `scout_daily()` 全部落进沙箱；退出时
自动清理。用工作区 `.tmp`（而非系统 `%TEMP%`）是为了绕开 DSH 沙箱的 ACL
限制。

### 2. 实盘目录假仓写盘守卫

`_write_cache()` 新增第二道保险：目标为默认实盘目录（`cache_dir is None`
且未设置 `NEXUS_SCOUT_CACHE_DIR`，或 `cache_dir` 解析后等于
`DEFAULT_CACHE_DIR`）时，若响应 `items` 非空且**全部** `full_name` 以
`acme/` 或 `example/` 开头，直接跳过写盘。

> 实现放在 `_write_cache()` 而不是只放 `_get_cached()`：`scout_daily._fetch`
> 走的是同一个写盘点，这样连"实盘默认目录 + 在线抓取"路径也一并守住。

## 三、M405：回填来源分账 + 失败仓 3 天冷却

### 1. 两级回填分账

`scout_daily()` 分别累计 `cache_backfilled`（第一级缓存池）与
`seed_backfilled`（第二级离线种子），`backfilled = 两者之和`；返回字典新增
两个字段。`source` 精确归因：

| 条件 | source |
|---|---|
| `rate_limited` 且在线主循环 0 候选 | `github_search_rate_limited` |
| `seed_backfilled > 0` 且 `len(ordered) == seed_backfilled` | `offline_seed_backfill` |
| `seed_backfilled > 0`（混合） | `github_search+seed_backfill` |
| 其他 | `github_search`（纯离线入口仍为 `offline_seed`） |

`live_hunt_report.scout_cache_line()` 增加两个可选参数；`seed_backfilled > 0`
时渲染分账：

```
- 侦察缓存与回填：缓存命中 5 页 / 限流回填 8 仓（缓存 3 / 种子 5）
```

`seed_backfilled == 0` 保持旧格式（兼容 `[335]` 的等值断言）。`daily_hunt`
头部与 `daily_meta` 同步透传 `cache_backfilled` / `seed_backfilled`。

### 2. 失败/超时仓 3 天冷却

- `daily_hunt.run()` 的 `sync.get("status") != "OK"` 与 `except Exception`
  分支都会写账本：

  ```python
  state["repos"][slug] = {**entry, "last_failed_at": _now(),
                          "last_failed_reason": reason[:200]}
  ```

- 开头构建 `exclude` 时，除 `last_scanned_at` 冷却外，若
  `last_failed_at` 距今 `< min(cooldown_days, 3)` 天，同样加入 `exclude`；
- 扫描循环再补一道防线：即使侦察器把 slug 塞回来，也记
  `SKIPPED (failed_cooldown_3d)`，不再白卡一次 300s 克隆。

## 四、M406：门禁 `[337]`

`benchmarks/smoke_test_chains.py` 末尾新增 `[337]`（纯离线，12 项断言）：

| 组 | 覆盖 |
|---|---|
| 沙箱 | `NEXUS_SCOUT_CACHE_DIR` 指向工作区临时目录且存在 |
| 写盘守卫 | 默认实盘目录下 `_get_cached` 收到全 `acme/*` 响应 → 0 个缓存文件落盘 |
| 动态顺延 | 主 specs 全命中缓存（4 页）且候选全被 `exclude_slugs` 清空 → 继续顺延、用剩余预算抓回新词候选，`http_requests <= 8` |
| 回填分账 | 全种子回填时 `source == "offline_seed_backfill"`、`seed_backfilled == len(items)`、`cache_backfilled == 0`、披露行分账格式 |
| 失败冷却 | 单仓抛 `TimeoutExpired` → `last_failed_at` 入账；紧接着复跑记 `SKIPPED (failed_cooldown_3d)`，`sync_fn` 只调用 1 次 |

同时更新两处旧断言以匹配新语义：

- `[297]` M311：动态顺延会额外发查询，改为只数**主 specs**（每语言 2 个），
  另加"顺延查询不越过单轮预算 8"。
- `[335]` M396：同日复跑不再断言"0 网络请求"（动态游标会继续翻新词），改为
  "已缓存页全部命中、新顺延轮才走网络（≤ 8）"。

## 五、实盘：同日暖缓存复跑（未清缓存、未重置状态）

命令（**未**清空 `.cache/scout_search`、**未**重置
`daily_hunt_state.json`）：

```
python cli.py daily-hunt --languages java,python --days 21 --limit 8 \
  --min-stars 300 --max-roots 5 --cooldown-days 7 --repo-timeout 300
```

### 5.1 结果

| 项 | v1.5.13 同日暖缓存 | v1.5.14 同日暖缓存 |
|---|---|---|
| 候选 | **0** | **14**（JSON；账本 13：8 实扫名额用满后剩 1 个未入账） |
| 实扫 / 跳过 / 失败 | 0 / 0 / 0 | **8 / 3 / 2** |
| 新增根因 | 0 | **452**（板块 A **8** / 板块 B 444） |
| 侦察 | `cache_hits=9`、0 网络 | `cache_hits=5`、`backfilled=0`、`scout_error` 空（0 次 403） |
| 耗时 | 0 秒（全缓存） | 29m32s（含 2 次 300s 克隆超时） |

账本：`tubecreate/tubecli`（227）、`ljxpython/ai-agent-platform`（85）、
`ydsgangge-ux/dramatica-flow`（64）、`ghost-in-the-droid/android-agent`（40）、
`LvcidPsyche/auto-browser`（27）、`aegra/aegra`（9）、
`wb04307201/spring-ai-loom-agent`（0）、`Pipelex/pipelex`（0）；
3 个 SKIPPED 为 `imfeh2/fora`（ZERO_ENTRY_LIB）、`aixisstudio/Snitch`
（all_local_or_demo）、`JJJJSTIYYYY/alira`（low_units_1）。

### 5.2 超时仓

- `mateaix/mateclaw`（15:27:00）与 `IBM/mcp-context-forge`（15:41:58）本轮
  克隆超时，已写入 `last_failed_at`；下一轮会走 3 天失败冷却，不再重复卡。
- `YunaiV/ruoyi-vue-pro` **没有进入本轮候选**（动态顺延用新词抓到 14 个候选，
  未触发第二级离线种子，故不在种子名单里被再次拉起）；v1.5.13 的"每轮卡
  300s"未复现。

### 5.3 板块 A 精核（8 条）

| # | 仓库 / 类目 / 入口 | 证据要点 | 精核结论 |
|---|---|---|---|
| 1 | android-agent · arbitrary_file_delete · `explorer_delete` | `@router.delete("/delete/{name:path}")` + `shutil.rmtree(_EXPLORER_DIR / name)`，无路径规范化 | **较强**：`{name:path}` 允许 `/`，可穿越删任意目录；路由未见函数级鉴权 |
| 2 | tubecli · unrestricted_upload · `upload_media` | `filename = file.filename` 直接 `os.path.join(uploads_dir, filename)` 后 `open(...,"wb")`，无扩展名/内容校验 | **较强**：文件名可含 `../` 造成目录外写入，且任意类型可落盘 |
| 3 | android-agent · arbitrary_file_delete · `api_skill_delete` | `_SKILLS_DIR / name` + `shutil.rmtree`，仅拦 3 个内置名 | **中等**：`{name}` 单段路径，`..` 可越一级；是否受全局中间件保护需人工确认 |
| 4 | tubecli · arbitrary_file_delete · `api_delete_cookies` | `os.path.join(PROFILES_DIR, name, "cookies.json")` + `os.remove` | **中等偏弱**：单段 `name` 的 `..` 只能越一级，需确认目录结构 |
| 5 | tubecli · zip_slip · `api_download_engine` | 下载引擎 zip 后解压，未见逐条 `..` 校验 | **中等**：zip 来自厂商 CDN，需确认是否可被替换/中间人 |
| 6 | tubecli · ssrf · `api_download_engine` | URL 由 `sx.download_candidates(version)` / `archive_url(version)` 生成 | **建议人工复核**：主机固定 CDN，仅 `version` 参与路径拼接，不构成任意主机 SSRF |
| 7 | ai-agent-platform · ssrf · `enqueue_message` | `httpx.AsyncClient(base_url=os.getenv("RUNTIME_SELF_URL", "127.0.0.1"))`，path 拼 `thread_id`/`target_run_id` | **建议降级/复核**：主机来自环境变量而非请求，最多同服务路径注入 |
| 8 | tubecli · arbitrary_file_delete · `api_cookie_import` | `tempfile.NamedTemporaryFile` + `os.unlink(tf.name)` | **建议降级**：删除的是自己创建的临时文件，非用户可控路径 |

> 口径：A 板 = `ZERO_RECORD_FRESH`（四源查重 0 命中），不等于人工已核验；
> 以上为提交前的人工抽检结论，建议先交 1/2/3，4/5 补鉴权与暴露面证据，
> 6/7/8 降级复核。

## 六、门禁结果

| 项 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,731 项断言**（v1.5.13 为 1,718；`[337]` 12 项 + M311 1 项） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 七、已知边界与建议

1. **单仓克隆超时仍是 300s 硬上限**：本轮两个新仓各卡 300s（总耗时 29m）。
   失败冷却只能保证"下一轮不再卡同一仓"；若要压缩单轮时长，可把
   `--repo-timeout` 调低或按仓大小动态超时，需单独拍板。
2. **候选 14 vs 账本 13**：`scanned_slots >= limit` 后循环 break，剩余候选
   不入账（既有语义）。报告头部"候选仓"取账本数，JSON `daily.candidates`
   取 items 数，二者天然可能差 1~N；A/B 对账不受影响。
3. **动态顺延会持续消耗预算**：同日复跑会在"已缓存页全部命中"后继续翻新词，
   这是设计目标；若只想复用缓存、不发现新仓，可显式传
   `max_http_requests=0`。
4. **失败冷却只记 `last_failed_at`**：成功的扫描不会清除该字段，但 3 天后
   自动失效；如需"成功即清失败标记"，下一轮可加。

## 八、提交清单

- `core/context/target_scout.py` — M403 词索引步进/动态顺延 + M404 写盘守卫 + M405 回填分账/source
- `core/context/live_hunt_report.py` — M405 披露行两级分账
- `core/context/daily_hunt.py` — M405 失败入账 + 3 天冷却 + 头部/JSON 透传
- `benchmarks/smoke_test_chains.py` — M404 全局沙箱 + M406 `[337]` 12 项 + 旧断言对齐
- `LIVE_HUNT_REPORT.md` — 同日暖缓存实盘（14 候选 / 452 根因 / A=8）
- `STAGE_REPORT_2026-11-15_v1.5.14.md` — 本报告
