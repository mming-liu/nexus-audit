# STAGE REPORT · v1.5.21（M431–M434：hash 入口域 / redir 仓储取址 / 权限分配防误压 / vLLM 降噪）

> 日期：2026-11-17 ｜ 基线：v1.5.20（`51c72ba`）
> 主题：清零 11-17 定时巡猎 A 板 6 条中的 4 条 hash + 1 条 redir 假阳；
> 权限分配写接口不再被裸 authz 误压；vLLM 推理引擎 fork 前置降噪；
> 3 仓离线复扫 + 白盒精核。
> 结论：qihang 4 条 hash、SPMS 1 条 redir 全部清零；EAF 的 spel 经白盒
> 核实为假阳（业务方法 `evaluate` 被 `ex` 前缀误命中）并已修复；M433 按
> 设计把 SPMS 2 条权限分配接口保留在 A 板待人工复核（框架 `@Permission`
> 继承，非未授权远程 0-day）。最终 **A=2**（不是预期的 1，原因见 §5）。

## 一、M431：hash 规则入口域归属门禁

`verdict()` 的 `hash` 分支此前只做 `extract_hash_alg(source, cfg)`，没有像
`crypto`（M122）那样核对入口域。切片把 Hop 2/3 的 `MD5Utils`/`MessageDigest`
证据贴进来后，入口 Controller 即使没有任何哈希调用也会判 True
（qihang-erp-open 4 条）。

修复：

1. `hash` 分支取 `_entry_region(source)` + `entry_body()`，要求入口域真实
   出现哈希/摘要/口令编码调用：
   `MessageDigest.getInstance` / `DigestUtils.` / `MD5Utils.` / `Hashing` /
   `hashlib.` / `hmac.` / `PasswordEncoder` / `md5*` / `sha1*` / `hash*` /
   `digest(` / `encrypt*` / `encodePassword`；零命中 → `None`。
2. `extract_hash_alg()` 增加工具类调用名识别
   （`MD5Utils.MD5Encode` / `DigestUtils.md5Hex` → `MD5`），否则这类入口
   连算法都提取不到。

验证：qihang `PurchaseOrderController.add` / `ShipRecordController.recordList`
/ `ShopOrderController.pullDetail` / `ShopRefundController.pullDetail`
→ 全部 `None`。

## 二、M432：redir 数据库/仓储取址排除

`redir_verdict()` 在 `sendRedirect` / `"redirect:" + target` 命中后直接判
True；SPMS `FileController.getFileUrl` 的目标是
`fileHelper.getPlatform(file.getPlatform()).getUrl(file.getUrl(), 3000)`，
其中 `file = service.get(fileId)` 来自数据库，不是外部 URL。

修复：新增 `_redir_repo_sourced(body)`：

- 入口无 `getParameter/getHeader/getQueryString`；
- 目标表达式（或其一跳变量、或目标里引用的局部变量）出现
  `*Service.*` / `*Mapper.*` / `*Dao.*` / `*Repository.*` 调用；
- 命中则判 `False`（服务端内部资源查找跳转）。

验证：SPMS `getFileUrl` → `False`；`[344]` 的
`fileService.getById(id).getUrl()` 夹具 → `False`。

## 三、M433：权限分配接口防误压 + vLLM fork 降噪

### 1. 权限分配写接口

`daily_hunt.py` 新增 `_PRIV_ASSIGN_RE` / `_is_privilege_assignment()`：

```
authorizeMenu|authorizePermission|grantRole|assignPermission|assignRole|
/role/|/permission/
```

`is_bare_wild_authz()` 与 `downgrade_wild_authz()` 命中即返回 `False`
（不按裸 authz 压 B，保留人工复核入口）。

### 2. vLLM 推理引擎 fork

`target_scout._TOOL_LIB_RE` 增加
`vllm|sglang|tensorrt-llm|llama\.cpp`，纯推理引擎 fork 在侦察阶段直接
`dropped_tool`，不再占克隆/实扫名额。

验证：`is_tool_lib("org/vllm-deepseek-v4-sm89", "vLLM fork")` → `True`。

## 四、M434：门禁 `[344]` + 3 仓复扫 + 白盒精核

### 1. `[344]`（4 项）

| 组 | 覆盖 |
|---|---|
| hash | MD5 仅在 Hop 证据段 → `None`；入口 `MD5Utils.MD5Encode` → `True` |
| redir | `fileService.getById(id).getUrl()` → `False` |
| 工具库 | vLLM fork → `True` |

### 2. 3 仓离线复扫

```
python cli.py daily-hunt --repos zeasin/qihang-erp-open,s-pms/SPMS-Server,w8123/EnterpriseAgentFramework \
  --offline --cooldown-days 0 --max-roots 5 --state .tmp/m434b_state.json \
  --report .tmp/m434b_LIVE_HUNT_REPORT.md --json .tmp/m434b_daily_hunt.json \
  --packs-dir .tmp/m434b_packs --repo-timeout 1800
```

| 轮次 | 根因 | 板块 A | 板块 B |
|---|---|---|---|
| 11-17 巡猎 | 33 | **6** | 27 |
| v1.5.21 复扫 | 13 | **2** | 11 |

- qihang：0 根因（4 条 hash 清零）；
- SPMS：9 根因，A=2（`authorizeMenu` / `authorizePermission`），B=7；
- EAF：4 根因，全部 B（spel 清零）。

> EAF 951 个入口，`--repo-timeout 600` 会 `TimeoutExpired`；复扫需
> `--repo-timeout 1800`。

### 3. 白盒精核

#### 3.1 qihang 4 条 hash

`PurchaseOrderController.add` 等入口只做订单/发货业务调用，无
`MessageDigest` / `MD5Utils` / `hash*` 调用；MD5 来自切片附带的 Hop 证据段。
**结论：规则假阳，已由 M431 清零。**

#### 3.2 SPMS `FileController.getFileUrl`（redir）

```java
FileEntity file = service.get(fileId);
...
response.sendRedirect(fileHelper.getPlatform(file.getPlatform())
        .getUrl(file.getUrl(), 3000));
```

目标 URL 来自数据库实体 `file`（`service.get(fileId)`），入口只接收
`id` 并解析为 `long`，不读取外部 URL 字符串。**结论：服务端内部资源查找
跳转，不是开放重定向；已由 M432 判 False。**

#### 3.3 EAF `RuntimePageWorkbenchInternalController.executionReadiness`（spel）

```java
@GetMapping("/internal/runtime/page-workbench/projects/{projectCode}/execution-readiness")
public ResponseEntity<ExecutionReadinessView> executionReadiness(...) {
    return ResponseEntity.ok(executionReadinessService.evaluate(...));
}
```

- 入口与 `evaluate()` 实现体内均无 `SpelExpressionParser` /
  `parseExpression` / `StandardEvaluationContext`；
- 误报根因：`EXPR_SINK_RE` 的接收者前缀 `ex\w*` 把
  `executionReadinessService.evaluate(` 当成 SpEL；
- **结论：假阳**。已把接收者收紧为
  `(?:ex|exp|expr|expression|spel|parser)\d*`（只允许数字后缀），
  EAF 复扫 spel → `None`。

#### 3.4 SPMS `RoleController.authorizeMenu` / `authorizePermission`

```java
@Api("role")
public class RoleController extends BaseController<RoleEntity, RoleService, RoleRepository> {
    @PostMapping("authorizeMenu")
    public Json authorizeMenu(@RequestBody @Validated RoleEntity role) { ... }

    @PostMapping("authorizePermission")
    public Json authorizePermission(@RequestBody @Validated RoleEntity role) { ... }
}
```

- `BaseController` 类级标注 `@Permission`
  （`cn.hamm.airpower.curd.permission.Permission`），AirPower 框架对继承
  方法统一做权限校验；全仓 19 个 `@Permission` 使用点，`getFileUrl` 还带
  `@Permission(authorize = false)` 说明权限框架确实生效；
- 两个接口是 POST + `@RequestBody RoleEntity`，需要已登录且具备角色管理
  权限；服务 `server.port: 8080`（默认监听 0.0.0.0），但鉴权框架在位；
- **结论：不是未授权远程 0-day**。按 M433 设计保留在 A 板供人工复核
  （框架级权限是否覆盖到具体 API code 需维护者确认），不建议对外提交。

## 五、为什么最终 A=2 而不是预期的 1

- 4 条 hash + 1 条 redir 已清零；
- EAF spel 经白盒核实为假阳，已修复 → 清零；
- M433 按设计把 SPMS 2 条权限分配接口从 B 板提到 A 板待人工复核
  （这是"防误压 B 板"的直接结果）；
- 因此 6 → 2，而不是 6 → 1。若后续确认 AirPower 的 `@Permission`
  已覆盖这两个 API code，可在 M433 中增加"类级 `@Permission` 存在即允许
  裸 authz 降噪"的细化规则，届时 A 可归零。

## 六、门禁结果

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,787 项断言**（v1.5.20 为 1,783；`[344]` 4 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 七、其他

- `benchmarks/results/daily_hunt_runs/` 已加入 `.gitignore`（M427 快照是
  运行产物，不入库）；11-17 09:01 的定时巡猎快照
  `20261117_090102_*` 已确认生成，M427 在生产环境生效。
- 11-17 09:00 巡猎主报告已被定时轮次覆盖为最新（19 候选 / A=6），
  符合 M427 的"主报告最新 + 快照留史"设计。

## 八、提交清单

- `core/agents/rule_detectors.py` — M431 hash 入口域 + M432 redir 仓储取址 + M434 spel 收紧
- `core/context/daily_hunt.py` — M433 权限分配接口防误压
- `core/context/target_scout.py` — M433 vLLM/sglang/tensorrt-llm/llama.cpp 降噪
- `benchmarks/smoke_test_chains.py` — M434 `[344]` 4 项
- `.gitignore` — `daily_hunt_runs/`
- `LIVE_HUNT_REPORT.md` — 11-17 定时巡猎结果（19 候选 / A=6）
- `STAGE_REPORT_2026-11-17_v1.5.21.md` — 本报告
