# STAGE REPORT · v1.5.18（M419–M422：词池扩容 / 三星标桶 / 顺延翻页 / 满额巡猎）

> 日期：2026-11-15 ｜ 基线：v1.5.17（`2d16f31`）
> 主题：解决 262 仓冷却基线下候选池枯竭 —— 词池翻倍、星标三桶覆盖
> 80..10000、顺延第 3 轮起翻 page=2、前置剔除 `agentkit/toolkit` 纯 SDK；
> 跑满额在线巡猎并对 7 条新 A 候选逐行白盒精核。
> 结论：候选池从 1 → **16**，实扫 4、A=7；**7 条 A 经白盒精核全部为假阳**
> （redir 守卫 / Jackson Map / Spring MVC 表单 / 泛化 `lookup`），本轮
> 无真实可交单 0-day，规则修复建议见 §4.3。

## 一、M419：词池扩容 + 三星标桶 + 顺延翻页

### 1. `BUSINESS_QUALIFIERS`

| 语言 | 原 | 新 | 追加词 |
|---|---|---|---|
| java | 11 | **24** | `ruoyi` `jeecg` `yudao` `springboot` `portal` `gateway` `console` `platform` `dashboard` `system` `shop` `pay` `hospital` |
| python | 7 | **23** | `fastapi` `django` `flask` `litestar` `sanic` `aiohttp` `tornado` `dashboard` `portal` `gateway` `panel` `studio` `console` `platform` `server` `webhook` |

### 2. `NEW_GEN_KEYWORDS` 15 → 30

两种语言在原有 15 词后同步追加：
`"ollama" "dify" "vllm" "openwebui" "comfyui" "langgraph" "crewai" "autogen" "studio" "panel" "gateway" "console" "portal" "nas" "webhook"`。
前 15 词顺序不变，既有索引断言兼容。

### 3. 星标三桶

```python
TRADITIONAL_STAR_BUCKETS = ((80, 450), (451, 2000), (2001, 10000))
```

`--min-stars 300 --max-stars 10000` 下完整覆盖 `300..450`、`451..2000`、
`2001..10000` 三个梯队（`_bounded_star_range` 夹取后分别得到
`(300,450)` / `(451,2000)` / `(2001,10000)`）。

### 4. 动态顺延

- `buffer_limit = max(1, limit) + (2 if limit >= 6 else 0)`：`limit>=6`
  时多备 2 个候选，防个别候选 `ZERO_ENTRY_LIB`/`low_units` 跳过导致名额空转；
  `limit<6` 的小样本行为不变。
- `extra_rounds >= 3` 时 `new_gen` 顺延查询带 `page=2`，翻开第 2 页新仓。

## 二、M420：前置剔除纯 SDK / 工具包

`_TOOL_LIB_RE` 词边界分支新增：
`agentkit|agent-kit|toolkit|toolkits|starter-kit|starterkit|dev-kit|devkit`。

`is_tool_lib("Hainrixz/whatsapp-agentkit", "WhatsApp AgentKit library")` → True；
`is_tool_lib("acme/webkit-crm-portal", "CRM web portal")` → False（`webkit`
不被 `toolkit` 误匹配）。

## 三、M421：门禁 `[341]`（9 项）

| 组 | 覆盖 |
|---|---|
| 工具库 | agentkit 判 True、webkit-crm-portal 不误杀 |
| 星标桶 | 含 `(2001,10000)`；`_bounded_star_range(300,10000,(2001,10000)) == (2001,10000)` |
| 词池规模 | python 业务词 ≥20、新生代词 ≥30 |
| 顺延实跑 | mock 网络下 `scout_daily(limit=8)` 的 query 覆盖 `stars:2001..10000`、新增业务词、`&page=2` |

同时更新 4 条与新设计冲突的旧断言（M298 panel、M325 分桶、M335 前 15 词
框架约束）。

## 四、M422：满额在线巡猎 + 7 条 A 候选白盒精核

### 1. 巡猎结果（对比 v1.5.17）

| 指标 | v1.5.17 | v1.5.18 |
|---|---|---|
| 候选仓 | 1 | **16** |
| 实扫 | 0 | **4** |
| 跳过 / 失败 | 1 / 0 | 8 / 4 |
| 新增根因 | 0 | **193** |
| 板块 A / B | 0 / 0 | **7 / 186** |

- 实扫 4 个仓（3 个仓产出记录）：`ai-git-bot` 60 条、`animaworks` 90 条、
  `MuckScraper` 43 条；
- 跳过 8：`all_local_or_demo` ×4（row-bot、captain-claw、hermes-life-os、
  llm-wiki-v2）、`ZERO_ENTRY_LIB` ×3（SILENTCHAIN、KaliGPT、freecad-ai）、
  `low_units_3` ×1（Hillock）；
- 失败 4：`pipeshub-ai`（TimeoutExpired）、`taskuary`/`MinusPod`/`laya`
  （clone_failed，网络/过滤失败）。

### 2. A 板 7 条逐行精核（全部假阳）

| # | 仓 / 类目 | 代码行 | 关键证据 | 结论 |
|---|---|---|---|---|
| 1 | MuckScraper / redir | `aggregator/blueprints/auth.py:162` `save_feed_defaults` | `@login_required`；`redirect(_local_next(request.form.get("next"), ...))`，`_local_next`（:152-159）校验 `startswith("/")`、非 `//`、无 `\`、无控制字符、`urlparse(...).netloc` 为空 | **FP**：开放重定向守卫完整 |
| 2 | ai-git-bot / deserial | `webhook/UnifiedWebhookController.java:65` `handleWebhook` | `objectMapper.readValue(rawBody, new TypeReference<>(){})` 解析为 `Map`，无 default typing / 多态类型；且 `WebhookSignatureVerifier.isValid` 对原始字节验签（HMAC，常量时间） | **FP**：Jackson→Map 非原生反序列化，无 gadget |
| 3 | ai-git-bot / xss | `admin/AiIntegrationController.java:72` `save` | `@Controller` + `@PostMapping` 表单保存，返回 `redirect:`/视图名；模板用 `th:text` 转义，`th:utext` 仅用于 `#{...}` 静态 i18n 文案；admin 走 `nativeWebSecurityFilterChain` 认证 | **FP**：无未转义回显 |
| 4 | ai-git-bot / xss | `admin/BotController.java:90` `save` | 同上 | **FP** |
| 5 | ai-git-bot / xss | `admin/GitIntegrationController.java:108` `save` | 同上 | **FP** |
| 6 | ai-git-bot / xss | `systemsettings/SystemSettingsController.java:93` `mcpToolSelection` | GET 返回视图 + `model.addAttribute("tools", ...)`，模板 `th:text` | **FP** |
| 7 | animaworks / jndi_injection | `server/routes/approve.py:26` `get_approval_page` | 无 `InitialContext`/`Context.lookup`；`rtr.lookup(callback_id)` 是普通方法名；magic-link `verify_approval_token(callback_id, token)` 先校验再渲染 | **FP**：泛化 `.lookup(` 被误当 JNDI |

**本轮无真实可交单 0-day。**

### 3. 规则修复建议（下一轮，不在本轮范围）

1. **redir**：识别 `_local_next` 这类 helper —— 参数经 `startswith("/")` +
   `urlparse(...).netloc` 空校验后再 `redirect()`，判安全。
2. **deserial**：Jackson `ObjectMapper.readValue(..., TypeReference/Map/JsonNode)`
   不算原生反序列化；仅 `ObjectInputStream.readObject` / `enableDefaultTyping`
   才判 True。
3. **xss**：Spring `@Controller` 返回 `redirect:`/视图名、模板无 `th:utext`
   用户数据时判 False；要求看到 `response.getWriter().write(input)` 或
   `th:utext="${userInput}"` 才判 True。
4. **jndi_injection**：要求出现 `InitialContext` / `Context` 变量或
   `lookup(` 的接收者是上下文对象；普通业务 `.lookup(` 退 None/False。

> 注：这 7 条已在 `cve_dedup` 缓存里判 `ZERO_RECORD_FRESH`，修复规则前
> 下一轮巡猎会重复出现在 A 板。

## 五、门禁结果

| 项 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,765 项断言**（v1.5.17 为 1,756；`[341]` 9 项 + 4 条旧断言更新） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 六、已知边界

1. **供给恢复但质量下滑**：词池扩容后候选从 1 → 16，但新捞回的仓以
   admin/bot/工具型为主，7 条 A 全是规则假阳；说明"扩词"解决了供给，
   下一轮要解决"扩词带来的误报"。
2. **克隆失败率仍高**（4/16）：`clone_failed` 多为网络/大仓超时；`clone_timeout=180`
   对大仓仍偏紧，可考虑按 `--repo-timeout` 联动或失败仓 3 天冷却。
3. **`--max-roots 5` 只约束 kept 根因**：blocked/noise 根因不占名额，
   `ai-git-bot` 单仓 60 条记录里绝大多数是 authz/log_injection 的 B 板噪声。
4. **词池中 `comfyui` 与 `_TOOL_LIB_RE` 冲突**：`comfyui` 关键词捞回的仓
   会被工具库规则丢弃，属预期（避免 ComfyUI 插件仓占名额），但该词实际
   产出为 0，后续可替换。

## 七、提交清单

- `core/context/target_scout.py` — M419 词池/三星标桶/顺延翻页/buffer + M420 工具库词
- `benchmarks/smoke_test_chains.py` — M421 `[341]` 9 项 + 旧断言更新
- `LIVE_HUNT_REPORT.md` — M422 巡猎结果（16 候选 / A=7 / 7 条 FP 精核）
- `STAGE_REPORT_2026-11-15_v1.5.18.md` — 本报告
