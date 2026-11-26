# STAGE REPORT · v1.5.33（M479–M482：11-26 八条规则假阳清零 + open-wes / youlai-boot / CourseArragement 白盒精核）

> 日期：2026-11-26 ｜ 基线：v1.5.32（`c777b58`，门禁 1,859）
> 主题：清零 11-26 巡猎 A 板 9 条（8 条规则上下文误判 + 1 条 `xss` 错标）；
> 白盒核查 `open-wes` 插件上传链、11-24 批次 `youlai-boot` ×4 与
> `CourseArragement` ×4；新增门禁 `[356]`。
> 结论：smoke **1,870** 项断言 PASS / triage **16/16** / doctor PASS；
> 9 条 A 板项重放 **9 → 0**，4 仓离线复扫 **A=0 / B=482**；
> 白盒产出 3 组候选结论（open-wes 相邻无鉴权插件安装端点、youlai-boot
> 认证后任意文件删除、CourseArragement 未授权 RBAC 篡改面），**均未外发**。

## 〇、背景（11-26 09:00 巡猎）

| 项目 | 数值 |
|---|---|
| 起止 / 耗时 | 09:01:03 → 09:09:00（约 8 分钟） |
| 候选 = 实扫 + 跳过 + 失败 | 11 = 4 + 6 + 1（跳过多为 `ZERO_ENTRY_LIB`；失败 1 个为 `travmiller/paper-console` 克隆 SSL 抖动） |
| 新增根因 | 489（A **9** / B **480**） |
| 状态计数 | ZERO_RECORD_FRESH 9 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / UNKNOWN 480 |
| 实扫仓根因数 | open-wes 74 / agent-foundation 263 / stackport 85 / OpenSRE 67 |

A 板 9 条（本轮修复对象）与真实根因：

| # | 仓库 | 类目 | 根因 | 命中位置 | 根因本质 |
|---|---|---|---|---|---|
| 1 | OpenSRE | ssrf | `memory_reextract` | `sre-agent/server_simple.py:1599` | URL 前缀是模块常量 `_CONFIG_SERVICE_URL`（`os.getenv(...)` 默认 `127.0.0.1`），非请求入参 |
| 2 | OpenSRE | zip_slip | `get_agent_performance` | `config_service/src/api/routes/team.py:1503` | `func.extract("epoch", …)` 是 SQLAlchemy 时间取值，不是解包 |
| 3–6 | agent-foundation | unsafe_reflection ×4 | `get_inbox_entry` / `get_run` / `get_trace` / `read_span_content` | `runs/routes.py:397,487`、`runs/trace_routes.py:129,228` | `getattr(x, section)` 的 `section` 是 `Literal[...]` 白名单形参 |
| 7 | open-wes | cmdi | `DictionaryController.refresh` | `…/wes-config/…/DictionaryController.java:75` | 无参入口里的 `method.invoke(...)` 是反射读枚举，不是命令执行 |
| 8 | open-wes | xss | `PluginManageController.uploadPlugin` | `…/plugin-core/…/PluginManageController.java:49` | JAR 上传只落盘+入库、返回 `void` 且不写响应体；错标成 XSS |
| 9 | stackport | unsafe_reflection | `run_operation` | `backend/routes/explorer.py:99` | `getattr(client, method_name)` 前有 `method_to_api_mapping.get(...) != operation` 白名单校验 |

## 一、M479：五处规则修复（`core/agents/rule_detectors.py`）

### 1) `zip_slip`：排除 SQL/ORM/DF 的 `extract` 同名调用

`.extract(` 被 SQLAlchemy（`func.extract`）、pandas（`.str.extract`）、正则
（`re.extract`）大量复用，不是归档解包。Python 分支现在只有出现**压缩包上下文**
（`zipfile`/`tarfile`/`shutil.unpack_archive`/`py7zr`/`rarfile`…）才按 Zip Slip
处理；没有上下文时排除这些"同名非同物"的命中。

| 切片 | 旧 | 新 |
|---|---|---|
| OpenSRE `get_agent_performance`（zip_slip） | True | **False** |

### 2) `unsafe_reflection`：`Literal`/`Enum` 形参 + 映射表白名单

- 入口签名里 `section: Literal["input", "output", …]` / `mode: XxxEnum` 的形参，
  取值在类型层已被限死一组字面量 → `getattr(value, section)` 不算动态反射；
- `_reflect_whitelisted()` 新增两类可核对形态：`mapping.get(var) != expected`
  查表校验（stackport 的 botocore `method_to_api_mapping`）、枚举/操作名白名单
  容器（`operation_names` / `api_mapping` 等）。

| 切片 | 旧 | 新 |
|---|---|---|
| agent-foundation `get_inbox_entry` / `get_run` / `get_trace` / `read_span_content` | True ×4 | **False ×4** |
| stackport `run_operation` | True | **False** |

### 3) `cmdi`：无参入口的反射 `invoke` 不判命令注入

`CMDI_SINK_RE` 里的 `method.invoke(...)` 是为 JavaSecLab 的反射执行样本保留的
（污点在第 2 个实参）。新增一条前置判据：**入口无任何形参 + 不读请求 +
全部 sink 命中都是 `method.invoke(...)`** → 只是反射读数据，判 False。
带形参的 `method.invoke(null, new String[]{payload}, …)` 仍判 True（`[356]` 防放宽）。

| 切片 | 旧 | 新 |
|---|---|---|
| open-wes `DictionaryController.refresh`（cmdi） | True | **False** |

### 4) `ssrf`：前导下划线的全大写配置常量

`_url_var_is_config()` 的全大写常量匹配从 `^[A-Z][A-Z0-9_]+$` 放宽为
`^_?[A-Z][A-Z0-9_]+$`，覆盖 `_CONFIG_SERVICE_URL = os.getenv(...)` 这类模块私有
配置常量；真正的请求入参 URL 仍判 True。

| 切片 | 旧 | 新 |
|---|---|---|
| OpenSRE `memory_reextract`（ssrf） | True | **False** |

### 5) `xss`：`void` 上传入口不判回显型 XSS

带 `MultipartFile`/`@RequestPart` 入参、返回 `void`、且全程不写响应体
（无 `getWriter`/`getOutputStream`）的入口，落点是磁盘+DB，不是 HTML 回显面
（open-wes 的 JAR 上传原来被 2b 的 DB 串接链误判）。返回 String 的反射回显
仍判 True（`[356]` 防放宽）。

| 切片 | 旧 | 新 |
|---|---|---|
| open-wes `PluginManageController.uploadPlugin`（xss） | True | **False** |

→ **9 条规则根因全部消失**（8 条 FP + 1 条错标）。

## 二、M480：白盒精核（0 外部提交）

### 1. `open-wes` `uploadPlugin`：假阳/死代码，但同模块存在真实无鉴权插件安装端点

- `uploadPlugin`（`plugin-core` 模块）：
  - `settings.gradle:22` 仅 `include`，全仓无 `modules-plugin:plugin-core`
    消费者的构建依赖；`wes-server/build.gradle:20` 只依赖 `plugin-sdk`；
    `Dockerfile` 只 COPY 三个 server jar —— 该模块**不进镜像**；
  - 官方规划文档 `docs/superpowers/plans/2026-10-08-script-plugin-phase0-fixes.md:19`
    明写 "The legacy `plugin-core` module is dead code — do not touch it"；
  - 链路止于 `PluginManagementServiceImpl.addPlugin` 的查重+`save`（状态 NEW），
    全模块无 `loadPlugin`/PF4J，落盘目录 `/local-storage/plugins/` 无静态映射。
  - → **该 A 板项是假阳/不可达**。
- **相邻真端点候选**：`plugin-sdk` 的 `PluginController.install`
  （`POST /plugin/install`，`PluginController.java:40-53`）→
  `PluginService.install`：`loadPlugin` + `startPlugin`
  （`PluginService.java:32,38`）→ `PluginRegister` 对插件 `scanPackages` 做
  `AnnotationConfigApplicationContext.scan + refresh`；
  - 无 `@PreAuthorize`/profile 门禁；应用内 Spring Security 为
    `.anyRequest().permitAll()`（`SecurityConfiguration.java:53-54`），
    真实鉴权只在网关，而 `docker-compose.yml:77` 把 wes-server 的
    **9010 端口直接发布到宿主机**（绕过网关）—— 静态推断可无鉴权上传 JAR →
    PF4J 实例化 → **潜在 RCE**；
  - 该端点正好是 11-33 最严 FRESH 模式复扫下冒出的潜在候选
    （`pathtraver PluginController.install`），与本白盒结论互相印证；
  - **证据强度：中高**（静态、构建图/端口/文档互证；未启动服务动态验证，
    生产是否另加边界封禁未知）。**暂不外发**，建议下一轮按部署面复核后立项。

### 2. 11-24 批次 `youlai-boot` ×4（全 HIGH）：1 真 + 3 假阳

- 鉴权基线：`SecurityConfig.java:62-70` 白名单外 `anyRequest().authenticated()`，
  4 条 URL 均不在免登录清单（`application.yml:51-68`）→ 不存在未授权访问。
- **`FileController.deleteFile`（`DELETE /api/v1/files`，`:55-63`）—— 真洞
  （认证后功能级授权缺失 + 对象级越权）**：类/方法无 `@PreAuthorize`，`filePath`
  直接来自 `@RequestParam`（`:59`），`LocalFileServiceImpl.java:66-73` 直接
  `path + filePath` 删除且无规范化/根校验；S3/阿里云实现按 URL 截 key 删对象，
  桶策略允许匿名 Get/List（`S3FileServiceImpl.java:159-169,180-186`）。
  任一低权账号可删任意文件/他人对象。建议：删除接口限管理员 + 登记文件 owner
  + canonicalize 前缀校验。
- `uploadFile`（`:38-53`）：上传是登录用户通用能力，文件名服务端 UUID、目录固定、
  prod 有扩展名白名单 → **假阳（鉴权维度）/预期功能**；附带建议：限定
  Content-Type、关闭匿名 ListBucket。
- `bindOrChangeEmail`（`:277-284`）/`bindOrChangeMobile`（`:250-257`）：
  表单无 userId，服务端以 `SecurityUtils.getUserId()` 取当前人，校验当前密码+
  验证码+唯一性，仅更新本人 → **假阳/自服务预期功能**；附带风险：验证码硬编码
  `123456`（`UserServiceImpl.java:599,507`），建议随机化+限频。

### 3. 11-24 批次 `CourseArragement` ×4：2 真 + 2 假阳

- 鉴权基线：Sa-Token 拦截器 `SaTokenConfigure.java:18-31` 只写了
  `SaRouter.match("/**").notMatch(...)`，**缺 `.check(r -> StpUtil.checkLogin())`**，
  且白名单里还是已不存在的旧路径；除 `/api/auth/*` 与 dashboard 外业务接口
  **匿名可访问**；全仓仅 1 处 `@SaCheckPermission`。
- **`RbacAssignController.assignRoleMenus`（`:42`）/`assignRolePermissions`（`:48`）
  —— 真洞（未授权管理操作/提权面）**：无鉴权注解，服务实现只校验 role/menu/
  permission 存在性（`RbacAssignServiceImpl.java:119-154,182-188`），不校验操作人、
  不校验 roleId 归属（`sys_role` 无归属字段）——任何可达者都能整体重写角色-菜单/
  角色-权限映射（含给 ADMIN 角色挂权限）。
- `AdminClassOptionController.create/update`（`:45`/`:53`）—— **假阳（XSS 不成立）**：
  `className` 仅 `trim` 入库，输出是 `@RestController` JSON；前端 Vue 文本插值/
  `:label` 自动转义，全仓无 `v-html`（仅 Excel errors 用 `dangerouslyUseHTMLString`，
  与班级名无数据流）。但这两个写接口同样无鉴权、无校验注解（数据完整性风险，另计）。

## 三、M481：门禁 `[356]`（11 项，纯离线）

| 组 | 断言 | 结果 |
|---|---|---|
| ① | SQLAlchemy `func.extract` 不判 `zip_slip` | ✅ |
| ① | 真实 `zipfile.extractall` 仍判 True（防放宽） | ✅ |
| ② | `Literal` 白名单形参的 `getattr` 不判 `unsafe_reflection` | ✅ |
| ② | 映射表校验后的 `getattr` 不判 `unsafe_reflection` | ✅ |
| ② | 无白名单的 `getattr` 仍判 True（防放宽） | ✅ |
| ③ | 无参入口的反射 `invoke` 不判 `cmdi` | ✅ |
| ③ | 带形参的反射 `exec` 仍判 True（防放宽） | ✅ |
| ④ | 前导下划线全大写配置常量不判 `ssrf` | ✅ |
| ④ | 形参 URL 仍判 `ssrf` True（防放宽） | ✅ |
| ⑤ | `void` 上传入口不判 `xss` | ✅ |
| ⑤ | 返回 String 的反射回显仍判 True（防放宽） | ✅ |

## 四、M482：复扫与全套验证

### 1. 9 条 A 板项逐条重放（真实切片）

| 11-26 A 记录 | 旧 | 新 |
|---|---|---|
| OpenSRE `ssrf` `memory_reextract` | A | **False**（规则层） |
| OpenSRE `zip_slip` `get_agent_performance` | A | **False** |
| agent-foundation `unsafe_reflection` ×4 | A | **False ×4** |
| open-wes `cmdi` `DictionaryController.refresh` | A | **False** |
| open-wes `xss` `PluginManageController.uploadPlugin` | A | **False** |
| stackport `unsafe_reflection` `run_operation` | A | **False** |

→ **A 板 9 → 0**。

### 2. 4 仓离线复扫（`daily_hunt.run(offline=True, dedup_online=False)`，空 state）

```text
summary: {"total": 482, "board_a": 0, "board_b": 482}
daily  : {"candidates": 4, "processed": 4, "scanned": 4, "skipped": 0,
          "failed": 0, "new_roots": 482, "board_a": 0, "blocked": 482}
by repo: OpenSRE 65 / agent-foundation 259 / stackport 84 / open-wes 74
by cat : authz 442 / log_injection 40
noise  : UNVERIFIED_WILD_AUTHZ 365 / LOCAL_LOOPBACK_ONLY 66 /
         LOW_SEVERITY_LOG_INJECTION 39 / TEST_FIXTURE_ONLY 10 /
         AUTHZ_CLASS_OR_BASE_GUARD 2
```

> 最严口径（注入 FRESH 查重桩）复扫：A 板 = 1，为
> `open-wes|pathtraver|PluginController.install` —— 不是本轮 9 条，而是上节
> 白盒点名的相邻真端点候选（实盘查重未给 FRESH 所以没进 A）；见遗留。

### 3. 全部门禁

| 门禁 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,870 项断言**（v1.5.32 为 1,859，+11 即 `[356]`） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 地板全绿** |
| `python cli.py doctor` | **PASS（12 段全绿）** |

## 五、说明与遗留

- **11-24 批次 A=9 的白盒结论已补齐**（youlai-boot ×4、CourseArragement ×4）：
  其中 3 条真洞候选（youlai-boot `deleteFile` 认证后任意文件删除、
  CourseArragement `assignRoleMenus`/`assignRolePermissions` 未授权 RBAC 篡改），
  其余 5 条为假阳/预期功能；`RoboHarness` `pathtraver` 1 条尚未白盒。
  **均暂不外发**，按披露流程需用户确认后再决定是否交单/补规则。
- **下一轮规则收口候选**（本轮只记录不修，避免把真洞洗成假阳）：
  - `xss`：`@RestController` JSON 输出 + 前端 Vue 文本插值（`CourseArragement`
    `create/update` 形态）——需要"响应侧无 HTML sink"证据；
  - `authz`：自服务接口（取当前登录人 + 密码/验证码校验，`bindOrChangeEmail`/
    `bindOrChangeMobile` 形态）与"无鉴权管理分配接口"要分开判；
  - `pathtraver`：`FileUtils.saveFile` + `Paths.get(filePath)` 的落盘归属
    （open-wes `PluginController.install` 形态）。
- **open-wes `PluginController.install`**：静态判断可无鉴权上传 JAR → PF4J 加载，
  但需确认生产部署是否直连 9010、是否另有边界封禁；**先作为待验证高危候选**，
  不做外发。
- 11-25 遗留的 `yu-picture` 最严口径 4 条（`hash` ×2、`mass_assignment` ×2）
  仍未处理，与本轮无关，继续挂账。
- 11-26 巡猎失败 1 个（`travmiller/paper-console` 克隆 SSL 抖动）为瞬时网络问题，
  不影响结论。

## 六、提交清单

- `core/agents/rule_detectors.py` — M479 五处规则修复
- `benchmarks/smoke_test_chains.py` — M481 门禁 `[356]` 11 项
- `LIVE_HUNT_REPORT.md` — 11-26 巡猎产物（docs 提交）
- `STAGE_REPORT_2026-11-26_v1.5.33.md` — 本报告

> 验证用 `.cache/upstream/` 为巡猎即时缓存（`.gitignore` 已排除），不进入提交。
