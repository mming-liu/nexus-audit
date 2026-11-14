# STAGE REPORT · v1.5.12（M395–M398：跨语言串扰根治 + 侦察缓存/限流回填）

> 日期：2026-11-14 ｜ 基线：v1.5.11（`3ef66e0`）
> 主题：规则层与降噪层**双端**语言隔离矩阵；GitHub Search 半途 403 不再让候选只剩 1 仓。
> 结论：11 个 Solidity 专属类目在 Python/Java 切片上全部退 `None`，`agenticos`
> B 板 Solidity 规则归零；搜索响应 6 小时缓存 + 两级回填已上线，报告头部可解释候选来源。

## 一、M395：双端语言隔离矩阵

### 规则层 `core/agents/rule_detectors.py`

1. 新增唯一真源 `SOLIDITY_ONLY_CATEGORIES`（11 项）：`reentrancy`、
   `access_control`、`broken_access`、`unchecked_low_level_calls`、`arithmetic`、
   `bad_randomness`、`tx_origin`、`delegatecall_untrusted`、`signature_replay`、
   `unchecked_erc20_return`、`oracle_stale_price`；跨语言白名单
   `SOLIDITY_SHARED_CATEGORIES = {hardcoded_secret, weakrand}`。
2. `verdict(category, source)` 在 `parse_config_block()` **之前**加双向门禁：
   - Web 切片（`_looks_solidity` 为 False）+ Solidity 类目 → `None`；
   - Solidity 切片 + 非 Solidity 且非白名单类目 → `None`。
   位置很关键：任何分支一旦进入就退不回 `None`。
3. `unchecked_erc20_return_verdict()` / `oracle_stale_price_verdict()` 函数体
   首行各加 `if not _looks_solidity(source): return None`。单函数直调同样被挡。

`watchtower` 只在 `rule_verdict(...) is True` 时立根因，所以门禁返回 `None`
是**连 B 板假根因都不产生**，不是"判完再降噪"。

### 降噪层 `core/context/wild_noise.py`

`SOLIDITY_ONLY` 从 M394 的 6 项同步扩为同一份 11 项集合。第二道闸按文件后缀
在 `classify()` 拦截，与规则层按切片内容拦截互补。冒烟 `[335]` 有**等值断言**
防止两端再次漂移。

根因：agenticos 的 `twilio_client.calls.transfer(call_sid, target_phone)` 与
`oracle.latestRoundData()` 本来是普通业务调用，却与 DeFi 规则的
`\w+\.transfer\(` / `\w*latestRoundData\(` 完全同形；M394 只堵了 2 个类目，
剩下 5 个仍会在 Python 切片上误命中。

## 二、M396：6 小时搜索缓存 + 半途 403 自动回填

### `core/context/target_scout.py`

1. `_get_cached(url, *, cache_dir=None, cache_ttl=21600) -> (ok, data, err, from_cache)`
   - 缓存键 `sha1(url)`，目录默认 `.cache/scout_search`，可用参数或
     `NEXUS_SCOUT_CACHE_DIR` 覆盖；文件体 `{"ts", "url", "data"}`；
   - 命中且 `time.time() - ts <= ttl` → 直接返回、`from_cache=True`、**0 网络请求**；
   - 未命中走 `_get()`，成功写盘用 `.tmp` + 原子替换；坏文件/目录不可写静默降级。
2. `scout_daily()` 新增 `cache_dir` / `cache_ttl` 参数，内部 `_fetch()` 统一
   接管主循环、关键词顺延、业务词兜底、翻页、M380 补拉共 **6 处**请求点，
   命中即累加 `cache_hits`。
3. **Partial Rate-Limit Backfill**：403/429 提前停手且
   `len(ordered) < limit` 时：
   - ① 遍历缓存目录所有 `.json`（按 `ts` 新→旧），用 `_parse_search()` 抽候选，
     按语言归属、`min_stars..max_stars`、`exclude_slugs`、`pushed_at <= last_scanned_at`
     四重过滤后轮转补入 `buckets`；
   - ② 仍不足则从 `OFFLINE_SEEDS` 按语言补差额；
   - 返回字典新增 `cache_hits` / `backfilled`。
4. M393 的"0 在线候选早退"分支不再提前 return，改为标注
   `source="github_search_rate_limited"` 后统一走回填，保证计数可解释。
   回填分支内才截断到 `limit`，正常路径保留 M293「纯库仓不占名额」语义。

### 报告侧

- `core/context/live_hunt_report.py` 新增唯一渲染点
  `scout_cache_line(cache_hits, backfilled)`，两者皆 0 时返回空串；
- `core/context/daily_hunt.py`：`_header()` 调用该函数输出
  `- 侦察缓存与回填：缓存命中 N 页 / 限流回填 M 仓`；`daily_meta`（JSON 侧
  daily 元数据）同源透传 `cache_hits` / `backfilled`。

## 三、M397：门禁 `[335]`（纯离线，0 网络调用）

`benchmarks/smoke_test_chains.py` 末尾新增 35 项断言：

| 组 | 覆盖 |
|---|---|
| 双端集合 | 11 项逐项相等、规模 == 11 |
| Web 切片 | Python / Java 各 5 条：`transfer(a,b)`、`latestRoundData()`、两个单函数直调、11 个类目全 `None` |
| Solidity 正例 | 漏检 ERC20 返回值 / 预言机新鲜度仍判 `True`；`sqli/xss/cmdi/pathtraver/authz` 全 `None` |
| 门禁顺序 | mock 掉 `sqli_verdict` 仍 `None`（证明门禁在分发前）；`hardcoded_secret` 白名单未被误拦 |
| 缓存 | 临时 `cache_dir`、sha1 文件名、`ts/url/data`、预置缓存后相同查询 **0 网络请求**、`cache_hits >= 1` |
| 回填 | 第 1 条回 1 个候选、第 2 条 `http_403` → `len(items)==4`、`backfilled>=3`、首位候选不被覆盖、来源可追溯 |
| 报告 | 披露行渲染、0/0 不输出、`_header` 带出、`daily` 元数据透传 |

## 四、M398：门禁全检

| 项 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,699 项断言**（`[335]` 新增 35 项；改前 1,664） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 五、实盘验证一：重扫 `vstorm-co/agenticos`

离线复用本地克隆 + 空账本重扫（`--max-roots 0 --offline-dedup --cooldown-days 0`），
避免账本 `exported_roots` 过滤掉历史根因，保证与 402 条基线可比。

| 指标 | v1.5.11 基线（M394 后） | v1.5.12 重扫 |
|---|---|---|
| 根因总数 | 402 | **401** |
| 板块 A | 0 | **0** |
| 板块 B | 402 | **401** |
| 11 个 Solidity 专属类目根因 | 1（`unchecked_erc20_return`） | **0** |

B 板剩余 401 条的类目分布：`authz` 395 / `log_injection` 5 / `cmdi` 1，
全部是 `UNKNOWN`（野仓自动降级口径），**与跨语言串扰无关**。唯一减少的 1 条
正是 M394 只压进 B 板、M395 从规则层根除的 ERC20 假根因。

> 偏差说明：首次重扫带 `--evict-cache` 时，本机 safe-delete 批量保护以
> `count=9580, threshold=50` 拦下 `.cache/upstream/vstorm-co__agenticos`
> 的清理并中断了写报告；去掉该参数重跑后成功。满额巡猎同样按无
> `--evict-cache` 执行，克隆缓存保留在 `.cache/upstream/` 供复核。

## 六、实盘验证二：满额巡猎（8 仓名额）

命令：`daily-hunt --languages java,python --days 21 --limit 8 --min-stars 300
--max-roots 5 --cooldown-days 7 --repo-timeout 300`（按第五节说明去掉
`--evict-cache`）。

### 第一轮（正式实盘，00:26–00:30，4m25s）

| 项 | 值 |
|---|---|
| 候选 / 实扫 / 跳过 / **失败** | 5 / 2 / 3 / **0** |
| 新增根因 | 3（板块 A **0** / 板块 B 3） |
| 侦察 | `source=github_search`，`scout_error` 空，`cache_hits=0`，`backfilled=0` |

账本：`GeoWebCache/geowebcache`（实扫，3 条）、`hiparker/opsli-boot`
（实扫，0 条）；3 个 SKIPPED 分别是 `yujian0815/fnmedia-ext`
（`all_local_or_demo`）、`apache/shiro`（`ZERO_ENTRY_LIB`）、
`jingsewu/open-wes`（`unchanged_head`）。本轮**没有撞到 403**，所以回填
未被触发——这正是健康路径的预期表现。

B 板 3 条全部是 `geowebcache` 的 `authz` UNKNOWN
（`SeedController.doFormGet` / `seedOrTruncateWithJsonPayload` /
`seedOrTruncateWithXmlPayload`），拦截原因
`UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口`，
**11 个 Solidity 专属类目 0 条**。

### 第二轮（缓存保护实盘，00:31，1 秒）

为验证 M396 的缓存通道，同参数立刻再跑一次（同一天，URL 与刚写入的
缓存键一致）：

```
- 侦察缓存与回填：缓存命中 9 页 / 限流回填 0 仓
```

`daily.cache_hits=9`、`backfilled=0`、**0 次网络请求**，1 秒结束。
`.cache/scout_search` 从 8 页增长到 17 页，头部披露行由
`live_hunt_report.scout_cache_line()` 渲染，四处计数同源。

该轮候选为 0：缓存页里的候选均处于 7 天冷却 / 未变老仓排除中，而回填
只在 403/429 时触发，故没有补仓。原始报告保存在
`.tmp/m398_pass2_LIVE_HUNT_REPORT.md`，主 `LIVE_HUNT_REPORT.md` 已回滚到
第一轮的有效巡猎结果；两轮 JSON 分别在 `.tmp/m398_pass1_daily_hunt.json`
与 `.tmp/m398_pass2_daily_hunt.json`（均为 gitignore 生成物）。

### 板块 A 精核

两轮 **A=0，无新出候选，无需精核**。按巡检自动复核协议核对
`LIVE_HUNT_REPORT.md` 与 `benchmarks/results/daily_hunt.json`：A 行数 0、
B 行数 3、状态计数 UNKNOWN 3，报告与 JSON 一致；未提交任何外部
advisory / CVE。

## 七、已知边界与建议

1. **回填触发条件仍限定 403/429**（M396 原样实现）。第二轮实证了另一种
   "候选不足"：缓存全命中但候选被冷却/未变排除清空，此时 `rate_limited`
   为假，不会回填。若要根治所有空轮，可把触发条件扩为
   「`len(ordered) < limit` 且在线/缓存供给已耗尽」，但会引入无 403 时
   也补离线老仓的副作用，需你决定是否放宽。
2. `--evict-cache` 在本机 safe-delete 批量保护下不可用（阈值 50，
   实际单仓 9,580 文件）。本轮未改动该安全机制；若要恢复即扫即焚，
   需要单独确认批量清理或调整保护阈值。
3. 跨过午夜后 `day_index` 变化会让关键词轮转，旧缓存页不会再命中；
   6 小时 TTL 之外属预期失效。

## 八、提交清单

- `core/agents/rule_detectors.py` — M395 双向门禁 + 两个单函数门禁
- `core/context/wild_noise.py` — M395 降噪层 11 项同步
- `core/context/target_scout.py` — M396 `_get_cached` + 两级回填 + 计数
- `core/context/live_hunt_report.py` — M396 披露行唯一渲染点
- `core/context/daily_hunt.py` — M396 头部输出 + daily 元数据透传
- `benchmarks/smoke_test_chains.py` — M397 `[335]` 35 项离线断言
- `STAGE_REPORT_2026-11-14_v1.5.12.md` / `LIVE_HUNT_REPORT.md` — M398 文档与实盘报告

代码提交：`be9ae57`（M395–M397）；文档与巡猎报告随本次推送一并入库。
