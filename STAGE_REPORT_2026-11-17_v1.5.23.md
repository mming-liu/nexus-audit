# STAGE REPORT · v1.5.23（M439–M442：泛化 Controller 类名降噪 / sources.total 对齐 / 外部 AirPower 基类）

> 日期：2026-11-17 ｜ 基线：v1.5.22（`d037faa`）
> 主题：消除全网 Issue 查重的泛化 Controller 类名跨仓噪音；把
> `sources[*].total` 对齐 M365 过滤后的真实证据命中数（原始命中留
> `raw_total`）；支持外部 Jar 的 AirPower 基类鉴权识别；跑新一轮在线巡猎。
> 结论：门禁 smoke **1,793** / triage 16/16 / doctor PASS；在线巡猎
> 候选 1 / 实扫 0 / 跳过 1（`ZERO_ENTRY_LIB`）/ **A=0**，无新 A 可精核；
> 当前 309 仓账本 + 7 天冷却导致候选池枯竭，需在下一轮调整供给参数。

## 一、M439：泛化 Controller 类名 + `sources.total` 对齐

### 1. `_GENERIC_CLASSES` 扩充（5 → 17）

```python
_GENERIC_CLASSES = frozenset({
    "BaseController", "CommonController", "IndexController",
    "ApiController", "TestController", "FileController",
    "UserController", "RoleController", "AuthController",
    "LoginController", "UploadController", "AdminController",
    "SystemController", "MenuController", "DictController",
    "DeptController", "ConfigController",
})
```

`FileController.getFileUrl` 这类组合不再走"不带仓库名裸搜全网 Issue"，
`_is_distinctive()` 返回 `False`，退化为带 `repo_name` 的精确检索，
避免 SPMS 场景捞回 47 条跨仓无关 PR。

### 2. `sources[*].total` 与 M365 过滤后口径对齐

`dedup()` 中在 `issue_hits` / `_gissue_hits` 过滤后：

```python
issues["raw_total"] = int(issues.get("total") or 0)
issues["total"] = len(issue_hits)
issues["ids"] = [x.get("id") for x in issue_hits][:5]

global_issues["raw_total"] = int(global_issues.get("total") or 0)
global_issues["total"] = len(_gissue_hits)
global_issues["ids"] = [x.get("id") for x in _gissue_hits][:5]
```

`status == STATUS_FRESH` 时 `total` 恒为 0（真实安全重复命中数），原始
搜索命中数保留在 `raw_total` 供审计溯源，彻底消除巡检"`total>0` 却判
FRESH"的假警报。

验证（`[346]`）：`github_issues` 返回 1 条标题 `"支持ip和jimeng"` 的普通
功能 Issue → 最终 `status=ZERO_RECORD_FRESH`、
`sources.github_issues.total=0`、`raw_total=1`。

## 二、M440：外部 Jar 的 AirPower 基类鉴权

`wild_noise._java_authz_class_guard()` 在本地找不到 `extends` 父类 `.java`
源码时，新增分支：

- 当前控制器源码含 `import cn.hamm.airpower.`；
- 类声明含 `extends \w*Controller`；
- 当前类与方法均未标 `@Anonymous` / `@IgnoreToken` / `@PermitAll` /
  `login = false` / `authorize = false`；

→ 返回 True，归入 `AUTHZ_CLASS_OR_BASE_GUARD`。

`_JAVA_ANON_ANN_RE` 同步补充 `login\s*=\s*false` / `authorize\s*=\s*false`，
避免把显式放行接口误拦。

验证（`[346]`）：无本地 `BaseController.java`、仅
`import cn.hamm.airpower.curd.CurdController;` +
`public class RoleController extends CurdController` 的控制器 →
`AUTHZ_CLASS_OR_BASE_GUARD`；同文件 `@Permission(login = false)` 方法 →
`blocked=False`。

## 三、M441：门禁 `[346]`（4 项）

| 断言 | 结果 |
|---|---|
| `_is_distinctive("FileController", "getFileUrl")` | `False` |
| 1 条普通功能 Issue → FRESH、`total=0`、`raw_total=1` | ✅ |
| 外部 AirPower 基类控制器 → `AUTHZ_CLASS_OR_BASE_GUARD` | ✅ |
| `@Permission(login = false)` 显式放行不拦截 | ✅ |

## 四、M442：全套门禁 + 在线巡猎

### 1. 门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,793 项断言**（v1.5.22 为 1,789；`[346]` 4 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

### 2. 在线巡猎（`--repo-timeout 600`）

```
python cli.py daily-hunt --languages java,python --days 21 --limit 8 \
  --min-stars 300 --max-roots 5 --cooldown-days 7 --repo-timeout 600
```

| 项 | 结果 |
|---|---|
| 候选 | 1 |
| 实扫 | 0 |
| 跳过 | 1（`nokia-applied-research/AnyJev` → `ZERO_ENTRY_LIB`） |
| 失败 | 0 |
| 新增根因 | 0 |
| 板块 A / B | **0 / 0** |

无新 A 候选，未触发白盒精核。

### 3. 候选池枯竭说明

- 账本已累计 **309** 个仓，`--cooldown-days 7` 把绝大多数近期仓排除；
- 本轮侦察只回 1 个候选（`github_search`，缓存命中 0、回填 0），
  且该仓无 Web 入口（`ZERO_ENTRY_LIB`）；
- `--repo-timeout 600` 本身无失败，说明超时不是瓶颈，供给才是。

**建议**（未改代码/参数）：下一轮改用 `--days 30` 或放宽星标下限/换
侦察词池，或在有 GitHub Token 时提高搜索配额；09:00 定时轮若继续
沿用 `--days 21 --cooldown-days 7`，大概率仍是空轮。

## 五、提交清单

- `core/context/cve_dedup.py` — M439 `_GENERIC_CLASSES` 扩充 + `total/raw_total` 对齐
- `core/context/wild_noise.py` — M440 外部 AirPower 基类识别 + `login/authorize=false` 放行
- `benchmarks/smoke_test_chains.py` — M441 `[346]` 4 项
- `LIVE_HUNT_REPORT.md` — 本轮巡猎结果（候选 1 / A=0）
- `STAGE_REPORT_2026-11-17_v1.5.23.md` — 本报告
