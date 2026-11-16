# STAGE REPORT · v1.5.19（M423–M426：4 类假阳根治 / A 板 7→0 / 新一轮巡猎）

> 日期：2026-11-16 ｜ 基线：v1.5.18（`90a971f`）
> 主题：从规则层与模板解析层根除 v1.5.18 暴露的 4 类（共 7 条）A 板假阳；
> 3 仓离线复扫验证 A 7→0；跑新一轮满额巡猎并对 11 条新 A 候选逐行精核。
> 结论：**A 7→0** 已验证；门禁 smoke 1,775 / triage 16/16 / doctor PASS；
> 新巡猎 A=11，其中 **9 条为假阳、2 条为真实未授权 SSRF**
> （`wwwzhouhui/dify-for-dsl` 的 `jm_image`，0.0.0.0 + 无鉴权 + 请求体 URL）。

## 一、M423：JNDI / Jackson / Python 跳转三类假阳

### 1. `jndi_injection` 语言隔离 + JNDI 上下文门禁

`jndi_injection_verdict()` 入口新增：

```python
if _looks_python(source) or _looks_solidity(source):
    return None
if not re.search(
        r"\b(?:InitialContext|DirContext|InitialDirContext|Context|"
        r"JndiTemplate|JndiObjectFactoryBean|JndiLookup|javax\.naming)\b",
        source):
    return None
```

`wild_noise` 新增 `JAVA_ONLY = frozenset({"jndi_injection", "spel"})`，
`classify()` 对非 `.java` 入口直接返回 `RULE_LANGUAGE_MISMATCH`。
`animaworks` 的 `rtr.lookup(callback_id)` → `None`。

### 2. Jackson `readValue` 无多态 `Map/List/JsonNode` 排除

`_TYPED_TARGET_SAFE` 从 11 项收敛为 `{"Object", "Serializable"}`；
`_typed_read_value_safe()` 增加菱形 `new TypeReference<>() {}` 的赋值左侧
类型判定（`Map/List/JsonNode` 等容器 → 安全，`Object/Serializable` → 仍不安全）。

- `objectMapper.readValue(rawBody, new TypeReference<>() {})`（`Map<String,Object>`）→ `False`
- `readValue(rawBody, Map.class)` → `False`
- `enableDefaultTyping()` + `Object.class` → 仍 `True`

### 3. Python 同源跳转 `_local_next` / `.netloc` 守卫

`_PY_REDIR_GUARD_RE` 扩充：

```python
r"\b_?(?:local|safe)_(?:next|redirect|url)\s*\(|"
r"\b(?:sanitize|validate)_(?:next|redirect|url)\s*\(|"
r"\.\s*netloc\b|"
```

`_py_redir_verdict()` 改为 `body` 或 `source` 命中守卫即 `False`（覆盖切片
附带的同文件 helper 实现体）；`wild_noise.classify()` 的 `redir` 分支增加
`SAFE_REDIRECT_GUARD` 兜底（Python 文件 + 守卫命中）。

`MuckScraper` 的 `save_feed_defaults` → `False`。

## 二、M424：Thymeleaf 模板解析 + `@Controller` 视图 XSS

### 1. `view_templates.find_render_points()`

- 键只匹配 `${k}` Model 表达式（`(?:\.[A-Za-z0-9_]+)?` 允许属性路径），
  **排除 `#{k}` i18n 词条**；
- `unescaped` 只在“不转义指令真正包裹 `${k}`”时为真：
  `th:utext="...${k...`、`v-html="...${k...`、`[(${k})]`、`<#noescape>…${k}`；
- `[[${k}]]` 按 Thymeleaf 语义视为**转义**内联（JS 上下文还会做 JS 转义），
  不再与 `th:utext="#{i18n.msg}"` 连坐；
- 删除不再使用的 `_NOESCAPE_RE` / `_ESCAPE_RE`（doctor 死正则检查）。

### 2. `xss_verdict()` 纯视图 `@Controller` 守卫

新增 `_view_only_controller()`：`Controller-Kind: @Controller` 且
（剔除注释后）无 `@ResponseBody`、无 `getWriter/getOutputStream`。
在 branch 2 / 2b 中，纯视图控制器只有关联模板存在不转义渲染才判 `True`。

复扫时额外暴露的 `SystemSettingsController.saveMcpToolSelection` /
`saveBotToolSelection` 也因切片注释里的 `// @ResponseBody` 被误判，
`_view_only_controller()` 已改为先剥离 `//` 注释再检查。

`ai-git-bot` 4 条 xss → `False`；`My-Blog-layui` 的 `gotoBlogEdit`
（模板含 `th:utext="${blogInfo.blogContent}"`）仍 `True`，16 靶场地板不变。

### 3. 词池冲突

`NEW_GEN_KEYWORDS` 的 `'"comfyui"'` 替换为 `'"fastgpt"'`（消除与
`_TOOL_LIB_RE` 的冲突）。

## 三、M425：3 仓离线复扫 A 7→0 + 门禁 `[342]`

### 1. 复扫对比

```
python cli.py daily-hunt --repos grregis/MuckScraper,tmseidel/ai-git-bot,xuiltul/animaworks \
  --offline --cooldown-days 0 --max-roots 0 --state .tmp/m425b_state.json \
  --report .tmp/m425b_LIVE_HUNT_REPORT.md --json .tmp/m425b_daily_hunt.json \
  --packs-dir .tmp/m425b_packs --repo-timeout 300
```

| 轮次 | 根因 | 板块 A | 板块 B |
|---|---|---|---|
| v1.5.18 巡猎 | 193 | **7** | 186 |
| v1.5.19 复扫 | 187 | **0** | 187 |

A 板 7 条（redir 1、deserial 1、xss 4、jndi 1）全部清零；复扫过程中额外
暴露的 2 条 xss（`saveMcpToolSelection` / `saveBotToolSelection`）也已
在规则层判 `False`（见 §2.2）。

### 2. 清理 `exported_roots` 脏记录

`benchmarks/results/daily_hunt_state.json` 中移除 7 条假阳写入的
`exported_roots`（MuckScraper 1、ai-git-bot 5、animaworks 1），保留
`authz|UsageController.usage` 等非假阳条目。

### 3. `[342]` 门禁（10 项）

| 组 | 覆盖 |
|---|---|
| redir | `_local_next` + `urlparse().netloc` 守卫 → `False` |
| deserial | 菱形 `TypeReference<Map>` / `Map.class` → `False`；`enableDefaultTyping` + `Object.class` → `True` |
| 模板 | `th:utext="#{i18n}"` 不连坐 `th:text="${form}"`；`th:utext="${form}"` 仍不转义 |
| xss | 纯视图 `@Controller` 返回模板名 → `False` |
| JNDI | Python `rtr.lookup(token)` / 无上下文 Java `router.lookup(id)` → `None`；`new InitialContext().lookup(name)` → `True` |

## 四、M426：门禁 + 新一轮巡猎

### 1. 门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,775 项断言**（v1.5.18 为 1,765；`[342]` 10 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

### 2. 巡猎结果

| 指标 | 数值 |
|---|---|
| 候选仓 | 13 |
| 实扫 / 跳过 / 失败 | 5 / 5 / 3 |
| 新增根因 | 173 |
| 板块 A / B | **11 / 162** |

### 3. A 板 11 条逐行精核

| # | 仓 / 类目 | 代码行 | 结论 |
|---|---|---|---|
| 1-5 | agentic-soc-platform / mass_assignment ×5（`SIEMKeywordSearchView.post` 等） | `backend/apps/agent_api/views.py:506-551`，`KeywordSearchInput(**request.data)` | **FP**：目标是 Pydantic 输入 DTO（`integrations/siem/models.py:98+`），不是 ORM 字段批量赋值；另发现根因 `line` 全被记成 343（`CommentView.post`），属行号归属 bug |
| 6 | dify-for-dsl / ssrf `generate_video` | `py/geekaiapp/g_jiekou.py:653-731` | **FP**：`generate_video_url = f"{video_api_base}/..."`，`video_api_base` 来自配置；路由还要求 `Depends(verify_auth_token)` |
| 7 | dify-for-dsl / ssrf `generate_video` | `py/geekaiapp/jimeng_video_service.py:73` | **FP**：只是包装函数，转发到固定 URL 的 `generate_video` |
| 8 | dify-for-dsl / ssrf `gjld_audio` | `py/geekaiapp/g_jiekou.py:172-191` | **FP**：`audiourl = siliconflow_api_url + "/audio/speech"`，config 常量 |
| 9 | dify-for-dsl / ssrf `jm_image` | `py/geekaiapp/g_jiekou.py:242-257` | **真实**：`requests.post(request1.image_generation_url, ...)`，URL 来自请求体；路由无 `Depends(verify_auth_token)`；`app.include_router(router, prefix="/api")`（:1040）；`uvicorn.run(app, host="0.0.0.0", ...)`（:1054） |
| 10 | dify-for-dsl / ssrf `jm_image` | `py/geekaiapp/wenshengtu1/jm1_jiekou.py:25` | **真实**：同一模式；该文件 `uvicorn.run(app, host="0.0.0.0", port=16004)`（:65） |
| 11 | product-apim / xss `PeopleRestService.addPerson` | `PeopleRestService.java:44-47` | **FP**：`@Produces(APPLICATION_JSON)` 返回 `Person` JSON；且位于 `modules/integration/tests-common/backend-service`，是集成测试后端而非生产入口 |

### 4. 真实候选：`wwwzhouhui/dify-for-dsl` 未授权 SSRF

- 仓库：`wwwzhouhui/dify-for-dsl`（3,884 stars，HEAD
  `d835ecfa6cbe45a70326e4e3336bbf73f2c68a17`，2026-11-11）；
- 入口：`POST /api/jimeng/img`（`g_jiekou.py:242`）、`/jimeng/img`
  （`jm1_jiekou.py:25`）；
- 根因：Pydantic `JMRequest.image_generation_url`（`g_model.py:57`）直接
  进入 `requests.post(...)`，无域名/协议白名单；路由无鉴权；服务监听
  `0.0.0.0`；
- 影响：未授权 SSRF（内网探测、云元数据访问），CVSS 3.1 粗估
  `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` ≈ **5.3（Medium）**；
- 处置：本轮只出精核报告，**未对外提交**；是否交单待你拍板。

## 五、已知边界

1. **`[[${...}]]` 语义调整**：按 Thymeleaf 规范视为转义内联（原实现误当
   不转义）；16 靶场地板已复跑确认不受影响。
2. **mass_assignment 规则仍过宽**：`**request.data` 到 Pydantic DTO 也判
   True；下一轮可要求“目标为 ORM/Entity 且存在字段白名单缺失”才判 True。
3. **根因行号归属 bug**：agentic-soc 的 5 条 SIEM 根因 `line` 全部指向
   `CommentView.post`（343），不是各自 `post` 行；影响报告定位，不影响结论。
4. **巡猎供给**：13 候选 / 5 实扫，仍有 3 条 clone_failed；`fastgpt` 词
   替代 `comfyui` 后暂未验证产出。

## 六、提交清单

- `core/agents/rule_detectors.py` — M423 jndi/deserial/redir + M424 视图守卫
- `core/context/wild_noise.py` — M423 `JAVA_ONLY` / `SAFE_REDIRECT_GUARD`
- `core/context/view_templates.py` — M424 `${}` / 不转义精确匹配 / 删除死正则
- `core/context/target_scout.py` — M424 `comfyui` → `fastgpt`
- `benchmarks/smoke_test_chains.py` — M425 `[342]` 10 项
- `benchmarks/results/daily_hunt_state.json` — 清理 7 条假阳 `exported_roots`
- `LIVE_HUNT_REPORT.md` — M426 巡猎结果（13 候选 / A=11）
- `STAGE_REPORT_2026-11-15_v1.5.19.md` — 本报告
