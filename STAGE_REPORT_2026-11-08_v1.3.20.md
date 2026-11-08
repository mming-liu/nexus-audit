# STAGE REPORT · v1.3.20（M323/M324 续：今日 2 条 A 板块复核）

> 日期：2026-11-08 ｜ 基线：M324（206f736）
> 结论：A 板块 2 条全部假阳，均已按根因修复并加冒烟。

## 一、今日巡检

候选 31 ｜ 实扫 8 ｜ 跳过 21（冷却 20）｜ 失败 2 ｜ A=2 ｜ B=38。

## 二、MiniMax-H3-Prompt-Rewriter-ComfyUI（nosqli）—— 假阳（已修）

```python
@routes.get(f"{PREFIX}/refmods/preview")
async def refmod_preview(request):
    def picture():
        item = refmods.find(request.query.get("name") or "")
        return refmods.preview_bytes(item) if item else None
```

`refmods.find` 是列表等值查找（`item.name == name`），不是 Mongo 查询文档：

```python
def find(name: str) -> Item | None:
    return next((item for item in listing() if item.name == name), None)
```

修复：`.find()` 的直接实参是 `request.query/args/form.get(...)`（标量查名）→ 不判 nosqli。

## 三、funchole InvocationActivityController.list（sqli）—— 假阳（已修）

```java
@GetMapping
public ApiResponse<...> list(@AuthenticationPrincipal AppUserPrincipal principal,
        @RequestParam(required = false) String source, ...) {
    return ApiResponse.success(activityService.list(principal.getId(), source, flowId, page, size));
}
```

服务层全部走命名参数绑定：

```java
where.append(" AND i.source = :source");
params.addValue("source", source.toUpperCase());
...
jdbc.queryForObject("SELECT count(*) FROM invocations i " + where, params, Long.class);
```

修复：`_sql_builder_placeholder_only` 接受 `:name` 字面量；JDBC 与 helper 两条
分支检测到 `addValue/setParameter/parameters.add` 时判 False。

## 四、B 板块 38 条

- Imagination-Studio 20 条：`LOCAL_LOOPBACK_ONLY`（本机回环 UI，无对外面）；
- Java-Agent-Study 5 条：`DEMO_CONTROLLER`；
- 其余 `UNVERIFIED_WILD_AUTHZ` 为本地脚本/演示仓，无生产入口。

## 五、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,914 项**（新增 [309] 3 项） |
| cli.py doctor | PASS（12 段全绿） |
