# STAGE REPORT · v1.5.22（M435–M438：类级/基类级 @Permission 鉴权识别，SPMS A=2 → 0）

> 日期：2026-11-17 ｜ 基线：v1.5.21（`d4df3ba`）
> 主题：识别 AirPower `@Permission` 与父类 `Base*Controller` 继承鉴权注解，
> 把 SPMS-Server `authorizeMenu` / `authorizePermission` 从 A 板归零；
> 3 仓离线复扫 + 全套门禁。
> 结论：`wild_noise` 新增 `AUTHZ_CLASS_OR_BASE_GUARD`；3 仓复扫
> **A 2 → 0 / B 13**；门禁 smoke 1,789 / triage 16/16 / doctor PASS。

## 一、M435：类级/基类级鉴权注解识别

### 1. 新噪声码

```python
AUTHZ_CLASS_OR_BASE_GUARD = "AUTHZ_CLASS_OR_BASE_GUARD"
```

### 2. 识别逻辑（`core/context/wild_noise.py`）

新增：

- `_JAVA_AUTHZ_ANN_RE`：`@Permission` / `@SaCheckLogin` / `@PreAuthorize` /
  `@RequiresPermissions`；
- `_JAVA_ANON_ANN_RE`：`@Anonymous` / `@IgnoreToken` / `@PermitAll`，以及
  `@Permission(authorize = false)`（显式放行，不是漏鉴权）；
- `_java_annotations_before()`：回扫声明行之前的注解块（含多行注解）；
- `_java_method_and_class()`：定位方法行、所属类声明行、类名与 `extends` 父类；
- `_repo_has_authz_framework()`：仓内 `@Permission`/`@SaCheckLogin` 文件数
  `>= 3`，或 `pom.xml`/`build.gradle` 出现 `airpower` / `spring-security`；
- `_java_authz_class_guard()`：方法无匿名注解、且当前类或其 `extends Base*`
  父类文件带类级鉴权注解，并且仓内确有鉴权框架线索 → 返回 True。

`classify()` 的 authz 分支新增（在 WebSocket 前置鉴权之后）：

```python
if (record.get("category") == "authz" and file.endswith(".java")
        and _java_authz_class_guard(repo_root, str(record.get("file") or ""), unit)):
    return {"blocked": True, "code": AUTHZ_CLASS_OR_BASE_GUARD,
            "reason": "当前类或继承基类挂有类级 @Permission/鉴权注解，框架已在类层面鉴权"}
```

### 3. 为什么不会误伤 ruoyi 真洞

规则要求**当前类或父类**有类级鉴权注解。ruoyi 的 `SysUserController` 等
没有类级 `@PreAuthorize`，只是"兄弟写方法有、目标方法没有"——`_java_annotations_before`
对类声明行回扫不到鉴权注解，`_java_authz_class_guard` 返回 False，
`classify` 继续走原有 `UNVERIFIED_WILD_AUTHZ`/A 板逻辑。已用
`reference_repos/RuoYi-master` 的 `SysUserController.add` 实测
`blocked=False`。

## 二、M436：门禁 `[345]`（2 项）

| 夹具 | 断言 |
|---|---|
| `BaseController.java` 类级 `@Permission` + `RoleController extends BaseController` 含 `authorizeMenu`/`authorizePermission`，同仓另有 2 个 `@Permission` 类 | `classify` → `blocked=True, code=AUTHZ_CLASS_OR_BASE_GUARD` |
| `ApiController` 无类级注解、同文件 `safe()` 有 `@PreAuthorize` 而 `vulnerable()` 没有 | `classify` → `blocked=False` |

## 三、M437：3 仓离线复扫

```
python cli.py daily-hunt --repos zeasin/qihang-erp-open,s-pms/SPMS-Server,w8123/EnterpriseAgentFramework \
  --offline --cooldown-days 0 --max-roots 5 --state .tmp/m435_state.json \
  --report .tmp/m435_LIVE_HUNT_REPORT.md --json .tmp/m435_daily_hunt.json \
  --packs-dir .tmp/m435_packs --repo-timeout 1800
```

| 轮次 | 根因 | 板块 A | 板块 B |
|---|---|---|---|
| v1.5.21 复扫 | 13 | **2** | 11 |
| v1.5.22 复扫 | 13 | **0** | 13 |

SPMS 两条目标根因：

```
RoleController.authorizeMenu      → UNKNOWN  AUTHZ_CLASS_OR_BASE_GUARD
RoleController.authorizePermission → UNKNOWN  AUTHZ_CLASS_OR_BASE_GUARD
```

qihang（0 根因）与 EAF（4 根因全 B）保持不变。

## 四、M438：门禁结果

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,789 项断言**（v1.5.21 为 1,787；`[345]` 2 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 五、已知边界

1. **仅覆盖 Java 类级注解**：Python 的全局鉴权中间件由
   `AUTHENTICATED_LOCAL_ONLY`/`WS_AUTH_PRESENT` 等既有规则处理。
2. **父类文件需在 `repo_root` 内**：`extends` 的父类若来自外部依赖 jar
   （如 Spring 基类），规则找不到源码，保持原判（保守）。
3. **`@Permission(authorize = false)` 视为匿名**：语义上是显式放行，
   不按"漏鉴权"处理；若某框架把 `authorize=false` 当默认值而非放行，
   需按框架语义再评估。
4. **`>= 3` 文件阈值**：单文件小项目若只有 1–2 个 `@Permission`，
   即便类级注解存在也不会触发（避免把偶然出现的注解当框架线索）；
   可在后续按项目规模调整。

## 六、提交清单

- `core/context/wild_noise.py` — M435 `AUTHZ_CLASS_OR_BASE_GUARD` + 类级/基类鉴权识别
- `benchmarks/smoke_test_chains.py` — M436 `[345]` 2 项
- `STAGE_REPORT_2026-11-17_v1.5.22.md` — 本报告
