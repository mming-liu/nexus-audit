# STAGE REPORT · v1.5.26（M451–M454：仓级多源查重补齐 / 在线巡猎 / ModelAndView XSS 假阳）

> 日期：2026-11-19 ｜ 基线：v1.5.25（`1e93ee5`）
> 主题：补齐上轮截断的 `dedup_repo_level` 数据源（本地种子 + CIRCL +
> 仓公告 + 全局 GHSA），逐条 `_unit_in_text` 精确匹配；跑新一轮在线巡猎，
> 对 2 条新 A 做白盒并清零。
> 结论：门禁 smoke **1,809** / triage 16/16 / doctor PASS；在线巡猎
> 13 候选 / 5 实扫 / 0 失败 / **A=2**（pig xss，白盒为 FreeMarker
> `?html` 假阳）→ 修复后 pig 复扫 **A=0**。

## 一、M451：`dedup_repo_level` 零配额多源比对

`core/context/cve_dedup.py` 重写 `dedup_repo_level()`：

1. **本地种子优先**：`_local_match(slug, aliases, category, unit)`，命中
   直接返回 `STATUS_CVE`（CVE-*）或 `STATUS_ISSUE`（GHSA-*），带
   `matched_ids` / `evidence_urls`，0 网络；
2. **在线三源（0 次 Search 配额、0 次 NVD）**：
   - `query_circl(slug)`（CIRCL 按仓，`_REPO_MEMO` 缓存）；
   - `query_github_advisories(slug)`（`/repos/{slug}/security-advisories`）；
   - `query_github_global_advisories(slug, unit, file)`（全局 `/advisories`，
     按方法名收窄）；
3. **逐条精确匹配**：对三源 `items` 逐条
   `_unit_in_text(unit, file, x["text"])`，不再用整块拼接 `t in text`；
   - 命中 `CVE-*` → `STATUS_CVE`，`reason = "REPO_LEVEL_CVE: ..."`；
   - 仅命中 `GHSA-*` → `STATUS_ISSUE`，`reason = "REPO_LEVEL_GHSA: ..."`；
   - 均未命中 → `STATUS_UNKNOWN`，`coverage["checked"]` 如实列出
     `local_seed` / `circl` / `repo_advisories` / `github_global_advisories`
     中 `ok=True` 的来源，`failed` 列出失败源。
4. 同仓多根因只打一次底层源：新增 `_REPO_LEVEL_SRC`（按 slug 缓存
   CIRCL/仓公告结果），配合 24h 磁盘缓存。

## 二、M452：门禁 `[349]`（3 项）

| 断言 | 结果 |
|---|---|
| CIRCL 返回含 `upload_chat_document` 的 `CVE-2026-108110` → `DUPLICATE_CVE` 且 `matched_ids` 含该 CVE | ✅ |
| 同仓未命中方法 → `UNKNOWN` 且 `coverage.checked` 含 `circl` | ✅ |
| 连续 10 次 + 同仓另一方法 → `query_circl` / `query_github_advisories` 各只调用 1 次 | ✅ |

## 三、M453–M454：在线巡猎 + 白盒精核

### 1. 在线巡猎（参数不变，`--repo-timeout 600`）

| 项 | 结果 |
|---|---|
| 候选 | 13 |
| 实扫 | 5 |
| 跳过 | 8 |
| 失败 | 0 |
| 新增根因 | 263 |
| 板块 A / B | **2 / 261** |

### 2. 新 A 白盒（2 条，同一入口族）

`pig-mesh/pig`（`PigTokenEndpoint.require` / `.confirm`）：

```java
@RestController
public class PigTokenEndpoint {
    @GetMapping("/token/login")
    public ModelAndView require(ModelAndView modelAndView,
            @RequestParam(required = false) String error, ...) {
        modelAndView.setViewName("ftl/login");
        modelAndView.addObject("error", error);
        return modelAndView;
    }
    @GetMapping("/oauth2/confirm_access")
    public ModelAndView confirm(... @RequestParam String state, ...) {
        modelAndView.setViewName("ftl/confirm");
        modelAndView.addObject("state", state);
        return modelAndView;
    }
}
```

- 返回 `ModelAndView` + FreeMarker 模板，不是直接 HTML 回显；
- 模板 `pig-auth/src/main/resources/templates/ftl/login.ftl`：
  `${error?html}`、`${authClientId?html}`；
- `confirm.ftl`：`${clientId?html}`、`${state?html}`、`${scope?html}`、
  `${principalName?html}` —— 全部 `?html` 转义；
- **结论：假阳**。M453 在 `xss_verdict` 中增加：返回
  `ModelAndView/ModelMap/View` 且 `setViewName(...)`、无
  `getWriter()/getOutputStream()` 时返回 `None`（模板转义交由
  `view_templates` 单独判定）。

### 3. pig 离线复扫

```
python cli.py daily-hunt --repos pig-mesh/pig --offline --cooldown-days 0 \
  --max-roots 5 --state .tmp/m454_state.json ...
```

| 轮次 | 根因 | 板块 A | 板块 B |
|---|---|---|---|
| 在线巡猎 | 263 | **2** | 261 |
| pig 复扫 | 168 | **0** | 168 |

## 四、门禁结果

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,809 项断言**（v1.5.25 为 1,805；`[349]` 4 项含 M453） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 五、说明

- `dedup_repo_level` 的"均未命中"按 M451 规格返回 `UNKNOWN`（不再返回
  FRESH）：仓级三源只能证明"没有匹配的公告"，不能证明"全网无重复"，
  保留 `coverage.checked` 供人工判断。
- 在线巡猎的 B 板已接入仓级查重（M448/M451）：命中仓级 CVE/GHSA 的
  短路记录会标 `DUPLICATE_CVE`/`DUPLICATE_ISSUE_OR_GHSA`，本轮 B 板
  261 条中未出现仓级命中（均为规则降噪项）。
- `pig` 的 2 条 XSS 若后续要交单，应先确认 FreeMarker 模板是否还有
  其它未转义输出点；本轮按"模板全部 `?html`"判假阳。

## 六、提交清单

- `core/context/cve_dedup.py` — M451 `dedup_repo_level` 多源比对 + `_REPO_LEVEL_SRC`
- `core/agents/rule_detectors.py` — M453 `ModelAndView` 视图返回不判 XSS
- `benchmarks/smoke_test_chains.py` — M452 `[349]` + M453 回归
- `LIVE_HUNT_REPORT.md` — 本轮在线巡猎（13 候选 / A=2）
- `STAGE_REPORT_2026-11-18_v1.5.26.md` — 本报告
