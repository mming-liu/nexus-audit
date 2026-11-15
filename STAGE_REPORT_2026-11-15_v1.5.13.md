# STAGE REPORT · v1.5.13（M399–M402：搜索预算 / 两级回填 / 安全删除隔离）

> 日期：2026-11-15 ｜ 基线：v1.5.12（`1f40c41`）
> 主题：09:00 定时巡猎不再必撞 `python: http_403`；缓存池回填不再被
> `min_stars=300` 整池滤空；`--evict-cache` 遇到本机 safe-delete 阈值不再
> 中断报告落盘。
> 结论：冷启动满额巡猎 **0 次 403**、候选 7/8；次日查询轮转探针 **2 次请求
> 拿到 24 个候选**并提前收手；`[336]` 19 项离线门禁全绿，冒烟 1,718 项。

## 一、M399：跨语言 Round-Robin 编排 + 单轮 HTTP 预算

### 1. specs 交织

`scout_daily()` 改为先按语言生成 `per_lang_specs[lang]`（新生代 + 传统），
再按轮次交织：

```
java #1 → python #1 → solidity #1 → java #2 → python #2 …
```

旧实现是 `for lang in langs: … specs.append(...)`，java 的新生代/传统两条轨
会先吃掉前几个搜索配额；无 Token 时预算只有 8 次，python/solidity 常整轮
轮不到。交织后每个语言都先拿到 1 次机会。

### 2. `max_http_requests` 预算门禁

- 新增参数 `max_http_requests: int | None = None`；默认值由
  `_default_http_budget()` 决定：`GITHUB_TOKEN` / `NEXUS_GITHUB_TOKEN` /
  `GH_TOKEN` 任一非空 → **24**，否则 **8**（10 次/分钟留 2 次余量）。
- `_fetch(url)` 重构为「缓存优先」：
  1. `_read_cache()` 命中 → `cache_hits += 1`，**不消耗预算**；
  2. 未命中且 `http_requests >= budget` → 置 `budget_exhausted=True`，返回
     `(False, None, "http_budget_exhausted")`；
  3. 否则真实 `_get()` 并 `http_requests += 1`，成功响应写回缓存。
- `http_budget_exhausted` **不写入 `errors`**（不产生假告警、不触发
  `rate_limited`）；主循环 `continue` 到下一个 spec，剩余 spec 仍会先查
  本地缓存。所有内层顺延/翻页/补拉循环遇到该哨兵立即停手。
- 返回字典新增 `http_requests` / `budget_exhausted`，便于实盘对账。

缓存读写同时拆成 `_read_cache()` / `_write_cache()`（`_get_cached()` 保留
原四元组语义，[335] 继续覆盖）。

### 3. 无 Token（预算 ≤ 8）收敛

| 维度 | 旧行为 | 预算 ≤ 8 |
|---|---|---|
| 新生代 `alt_kw` 顺延 | 最多 2 次 | **1 次** |
| 业务词兜底 | 最多 5 次 | **1 次** |
| 冷却翻页 `extra` | 最多 2 页 | **1 页** |

另加提前收手：`_candidate_count() >= limit` 且**每个语言至少 1 个候选**时，
主循环立即 break，把配额留给下一轮（次日）而不是在同一天烧光。

## 二、M400：两级回填分层 + 缓存池星标/语言修正

### 1. `_fill()` 星标分层

```python
def _fill(pool, needed, seen, *, min_s=min_stars, max_s=max_stars)
```

- **第一级缓存池**：`min_s = min(min_stars, NEW_GEN_STARS[0],
  CACHE_POOL_MIN_STARS)`，`max_s = max_stars`。
- **第二级离线种子**：`min_s = min_stars`，`max_s = max(max_stars, 100000)`。

> 偏差说明：规格写的是 `min(min_stars, NEW_GEN_STARS[0])`，但本仓 M342 已把
> 在线新生代下限抬到 **150**、传统桶抬到 **300**（`[317]` 有等值断言），
> 而规格同时要求 120 星缓存条目能回填。故新增常量
> `CACHE_POOL_MIN_STARS = 80`（M325 时代缓存页出现过的最低桶下界），
> 取三者最小。在线查询门槛不变，只放宽"已经抓到"的缓存页。

### 2. 缓存页语言归属

遍历 `cache_root.glob("*.json")` 时读取 `payload["url"]`，URL 解码后按
`language:([a-zA-Z0-9_+-]+)` 取查询语言，作为 `_parse_search(data, page_lang)`
的默认语言，**每页只解析 1 次**（旧实现按 `for lang in langs` 重复解析 N 次，
且把 Java 页按 python 再解析一遍）。候选仍按自身 `language` 过滤，缺省时回退
到 URL 语言。

### 3. 两级触发分层

- **第一级（缓存池）**：主循环结束后只要 `len(ordered) < limit` 就**无条件**
  回填 —— 403/429、预算耗尽、pass2 那种"缓存全命中但当页候选被
  `excluded`/`scanned_at` 清空"都走同一条路。
- **第二级（离线种子）**：仅当 `len(ordered) == 0` 且
  `(rate_limited or _rate_limited() or budget_exhausted or online_ok == 0)`
  时启用；有 1 个真实候选时不再混入老种子。
- 纯离线（`allow_online=False`）保持原语义：0 网络请求、直接返回种子，
  `queries` 仍填充全部 specs（`[297]` 依赖）。
- 种子池按 `max(max_stars, 100000)` 构建 —— 否则 `jeecgboot/JeecgBoot`
  （42k 星）等大仓在进 `_fill` 之前就被 `_offline(max_stars=10000)` 滤掉，
  第二级形同虚设（实盘暴露，已修）。

## 三、M401：`_evict` / `_force_rmtree` 异常隔离

- `_force_rmtree(path) -> bool`：`os.walk` / `os.chmod` / `shutil.rmtree`
  整段包 `try/except Exception`，失败返回 `False`。
- `_evict(slug, evicted, evict_skipped=None) -> bool`：删除失败时把 slug 记入
  `evict_skipped`，安全返回 `False`，不抛异常。
- `daily_hunt.run()` 的 `finally`：

```python
if evict_cache and not dry_run:
    try:
        _evict(slug, evicted, evict_skipped)
    except Exception:
        evict_skipped.append(slug)
```

- `daily_meta` 与 run() 返回值新增 `evict_skipped` 列表。
- `upstream_sync.sync_repo()` 第 117/134 行的 `shutil.rmtree(dest,
  ignore_errors=True)` 同样包 `try/except Exception: pass`，残留目录清理
  不再穿透。

本机 safe-delete 钩子在 `count=9580, threshold=50` 时会抛
`RuntimeError`；`[336]` 用同文案 mock 验证 `_evict → False`、`evict_skipped`
记录、报告与账本仍落盘。

## 四、M402：门禁 `[336]`

`benchmarks/smoke_test_chains.py` 末尾新增 `[336]`（纯离线，独立临时
`cache_dir`），共 18 项断言：

| 组 | 覆盖 |
|---|---|
| 交织 | 3 语言 × 2 轨前 3 条 = `[java, python, solidity]`；总条数守恒 |
| 预算 | 空页风暴下真实 `_get` ≤ 8；`http_requests == 8` + `budget_exhausted`；耗尽后仍命中预置缓存页；哨兵不进 `errors` |
| 回填 | 无 403、当页候选全被 `exclude_slugs` 清空 → 缓存池补 2；120 星条目不被 `min_stars=300` 误杀；不混入离线种子 |
| 删除 | `shutil.rmtree` 抛 safe-delete 异常 → `_evict` 返回 `False`、记 `evict_skipped`、`run()` 报告/JSON 仍落盘、扫描仍记 `SCANNED` |

同时更新两处旧门禁以匹配 M400 语义：

- `[335]` M396-2：403 场景改为"首条空页 → 第二级种子补满 4"；新增
  "已有 1 个真实候选时 `backfilled == 0`"（有货就不混种子）。
- `[320]` M346 与 `[316]` M339：补独立 `cache_dir`。M400 让第一级缓存池
  **无条件**扫描缓存目录，这两个用例此前会把 `acme/*` 夹具页写进实盘
  `.cache/scout_search`（见 §5.4）。

## 五、实盘验证

### 5.1 冷启动满额巡猎（M402 指定命令）

命令（清空 6h 搜索缓存，模拟次日 09:00 冷启动）：

```
python cli.py daily-hunt --languages java,python --days 21 --limit 8 \
  --min-stars 300 --max-roots 5 --cooldown-days 7 --repo-timeout 300
```

| 项 | 值 |
|---|---|
| 候选 / 实扫 / 跳过 / 失败 | **7 / 6 / 0 / 1** |
| 新增根因 | 22（板块 A **0** / 板块 B 22，全 `UNKNOWN`） |
| 侦察 | `source=github_search`，`scout_error` **空**（无 403），`cache_hits=0`，`backfilled=7` |
| 网络请求 | 写入 8 个缓存页 = 8 次真实请求，正好打满无 Token 预算 |
| 耗时 | 14:16:11 → 14:30:37（14m26s） |

账本：`macrozheng/mall`（0）、`jeecgboot/JeecgBoot`（10）、
`apolloconfig/apollo`（0）、`xuxueli/xxl-job`（0）、
`YunaiV/ruoyi-vue-pro`（FAILED：`TimeoutExpired`，300s 单仓超时）、
`elunez/eladmin`（12）、`linlinjava/litemall`（0）。

说明：8 次在线查询返回的 39 个候选**全部**落在 7 天冷却（38）或未变老仓
（1）里 —— 同一天 00:30/09:00 已扫过同一批查询结果。第一级缓存池按口径
跳过它们后，第二级离线种子补入 7 仓，报告头部如实披露
`限流回填 7 仓`。这正是"不混入无货假象"的设计：有真实在线候选时不会
触发种子；0 候选时用种子兜底而不是空轮。

### 5.2 次日查询轮转探针（供给能力）

同一套参数、`today=2026-11-16`（次日轮转词）单独跑 `scout_daily()`：

```
http_requests=2  budget_exhausted=False  cache_hits=0  items=24  error=""
```

第 1 次 java 新生代、第 2 次 python 新生代各回一批候选后，提前收手条件
（候选 ≥ limit 且每语言都有货）立即生效 —— **2 次请求拿到 24 个候选**，
证明预算/交织没有牺牲供给，且远低于 10 次/分钟。

### 5.3 暖缓存同日复跑（边界）

14:12 用同一命令复跑（缓存 22 页、9 页命中、0 网络请求）：候选 **0**。
逐页核对：46 个缓存候选全部处于 7 天冷却（62 仓）或未变老仓
（`scanned_at`）排除中，第一级缓存池无"未冷却、未排除"可补，第二级种子
因 `len(ordered)==0` 但无 403/预算未耗尽而未触发（`online_ok>0`）。
这是**同日重复跑的数据饱和边界**，不是回填失效：`[336]` 用含 120 星
可用条目的缓存页证明第一级能正常回填；次日 09:00 冷启动会走 §5.2 的
新查询轮转。

### 5.4 测试夹具污染事件（本轮抓到并修复）

M400 让第一级缓存池无条件扫描 `.cache/scout_search` 后，`[320]`/`[316]`
两个用例（`allow_online=True` 且未传 `cache_dir`）把 `acme/new1`、
`acme/admin` 等夹具页写进了实盘缓存。14:04 的首次实盘巡猎因此从缓存池
回填出 5 个 `acme/*` 假候选，全部 `clone_failed`。

修复：两个用例各传独立 `cache_dir`；清理 6 个污染缓存文件；重跑冒烟
1,718 项后复查缓存 22 页、0 个 `acme/*`。这也是 `[336]` 全部使用临时
`cache_dir` 的原因。

## 六、门禁结果

| 项 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,718 项断言**（v1.5.12 为 1,699；`[336]` 18 项 + `[335]` 净增 1） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 七、已知边界与建议

1. **同日重复跑仍可能 0 候选**：查询词按 `day_index` 轮转，同一天同一批
   查询的结果已被当天早先的巡猎扫过，缓存池与种子都处于冷却期。这是
   "一天只能发现一批新仓"的数据边界；若要在同日再开新供给，需要引入
   翻页/换星标桶的"深挖轮"，但会额外消耗配额，建议单独拍板。
2. **种子回填时 `source` 仍标 `github_search`**（因为在线页确实成功返回，
   只是候选被冷却过滤）。报告头部有 `限流回填 N 仓` 披露行可区分；若需要
   更精确的来源枚举（如 `offline_seed`），下一轮可加。
3. **单仓超时仍记 FAILED**：`YunaiV/ruoyi-vue-pro` 在 300s 内没克隆完，
   按既有 `--repo-timeout` 语义记账，不占后续名额。
4. **`--evict-cache` 未在实盘开启**：M401 已保证 safe-delete 拦截时不再
   中断落盘；实际删除仍受宿主钩子阈值限制，需要单独放宽/白名单。

## 八、提交清单

- `core/context/target_scout.py` — M399 交织/预算/收敛 + M400 两级回填/语言归属/星标分层
- `core/context/daily_hunt.py` — M401 `_force_rmtree`/`_evict`/`finally` 隔离 + `evict_skipped`
- `core/context/upstream_sync.py` — M401 两处 `rmtree` 包裹
- `benchmarks/smoke_test_chains.py` — M402 `[336]` 18 项 + `[335]`/`[316]`/`[320]` 语义对齐与缓存隔离
- `LIVE_HUNT_REPORT.md` — 冷启动实盘报告（7 候选 / 22 根因 / A=0）
- `STAGE_REPORT_2026-11-15_v1.5.13.md` — 本报告
