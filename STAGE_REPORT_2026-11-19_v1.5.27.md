# STAGE REPORT · v1.5.27（M455–M458：关闭 GitHub Actions 自动触发 + 修复 STATUS_CVE 同步）

> 日期：2026-11-19 ｜ 基线：v1.5.26（`c7baca9`）
> 主题：三个 GitHub Actions 工作流改为仅 `workflow_dispatch`（push 不再
> 触发 CI 邮件）；`noise_record()` 补齐 `STATUS_CVE` 与
> `sources`/`checked_at`/`matched_ids`/`evidence_urls` 留证字段。
> 结论：远端三个工作流已 `disabled_manually`（token 缺 `workflow` scope，
> 文件改动待补 scope 后提交）；门禁 smoke **1,812** / triage 16/16 /
> doctor PASS；本地 `pre-push` 门禁保留不变。

## 一、M455：关闭 GitHub Actions 自动触发

| 文件 | 修改前 | 修改后（本地） |
|---|---|---|
| `.github/workflows/nexus-audit-ci.yml` | `pull_request` + `push: branches: [main]` + `workflow_dispatch` | 仅 `workflow_dispatch` |
| `.github/workflows/nexus-audit.yml` | `on: [push, pull_request]` | 仅 `workflow_dispatch` |
| `.github/workflows/nexus-audit-pr.yml` | `pull_request: branches: [main, master]` | 仅 `workflow_dispatch` |

- 本地 `.git/hooks/pre-push` 未改动，全量门禁仍在推送前离线执行；
- **推送限制**：当前 GitHub OAuth token 只有 `repo`/`gist`/`read:org`，
  缺少 `workflow` scope，GitHub 拒绝推送 `.github/workflows/*` 的改动
  （`refusing to allow an OAuth App to create or update workflow ...`）。
  因此文件改动保留在工作树中待补 scope 后提交；
- **远端已实际关闭**：用 `gh workflow disable` 将三个工作流全部置为
  `disabled_manually`（`nexus-audit` / `nexus-audit-ci` /
  `nexus-audit PR scan`），push/PR 不再触发，CI 邮件停止；
- 补 scope 后执行 `gh auth refresh -s workflow`，再提交这三个文件即可
  把「手动触发」固化进仓库。

## 二、M456：`STATUS_CVE` 同步进主状态

### 1. `cve_dedup.dedup_repo_level()`

`_finish()` 统一补齐：

```python
res.setdefault("checked_at", time.strftime("%Y-%m-%d %H:%M:%S"))
res.setdefault("sources", {})
```

本地种子命中、离线、三源失败、命中、未命中的所有返回分支都带
`checked_at` 与 `sources`（每个已查源的 `ok`/`total`/`ids`/`url`/`error`）。

### 2. `daily_hunt.noise_record()`

```python
if repo_dedup:
    rec["coverage"] = dict(repo_dedup.get("coverage") or rec["coverage"])
    if repo_dedup.get("sources"):
        rec["sources"] = dict(repo_dedup["sources"])
    if repo_dedup.get("checked_at"):
        rec["checked_at"] = str(repo_dedup["checked_at"])
    rec["repo_dedup"] = {"status": ..., "reason": ...}
    if repo_dedup.get("status") in (cve_dedup.STATUS_CVE,
                                    cve_dedup.STATUS_ISSUE):
        rec["status"] = repo_dedup["status"]
        rec["matched_ids"] = list(repo_dedup.get("matched_ids") or [])
        rec["evidence_urls"] = list(repo_dedup.get("evidence_urls") or [])
        rec["reason"] = f"{rec['reason']}（{repo_dedup.get('reason') or rec['status']}）"
```

- 修复前只判 `STATUS_ISSUE`，`STATUS_CVE` 被漏掉，报告头 `DUPLICATE_CVE`
  恒为 0、B 表 `sources:{}` 留空；
- 修复后 `DUPLICATE_CVE` 进入主状态计数，B 表带
  `matched_ids`/`evidence_urls`/`sources`/`checked_at`，`noise_code`
  保留原降噪码。

## 三、M457：门禁 `[350]`（3 项）

| 断言 | 结果 |
|---|---|
| 三个 workflow 仅含 `workflow_dispatch:`，无 `push:` / `pull_request:`（读本地文件） | ✅ |
| `noise_record(repo_dedup=DUPLICATE_CVE)` → `rec["status"]="DUPLICATE_CVE"`、`matched_ids` 保留 | ✅ |
| `sources` / `checked_at` 非空且 `noise_code` 保留 | ✅ |

> `[350]` 读的是本地工作树文件，因此与远端文件状态解耦；远端工作流已
> 通过 API 置为 `disabled_manually`。

## 四、M458：门禁全检

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,812 项断言**（v1.5.26 为 1,809；`[350]` 3 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

### 关于 pig 的 16 条 `DUPLICATE_CVE` 复核

用当前 CIRCL 数据实测 `dedup_repo_level("pig-mesh/pig", "xss",
"PigTokenEndpoint.require")`：

```
status = UNKNOWN
reason = REPO_LEVEL_NO_MATCH
sources: local_seed ok / circl ok total=10 / repo_advisories ok total=0 /
         github_global_advisories ok total=0
coverage.checked = [local_seed, circl, repo_advisories, github_global_advisories]
```

CIRCL 的 10 条 pig CVE 描述里没有出现 `require`/`PigTokenEndpoint`
（只有 `attackRequirements`/`privilegesRequired` 这类字段名），
`_unit_in_text()` 按标识符边界匹配返回 False，因此当前数据下是
`UNKNOWN` 而非 16 条 `DUPLICATE_CVE`。M456 的传播逻辑已由 `[350]`
用构造的 `DUPLICATE_CVE` 覆盖；若后续 CIRCL 数据或匹配口径变化，
报告会正确计入 `DUPLICATE_CVE`。

## 五、提交清单

- `.github/workflows/nexus-audit-ci.yml`、`nexus-audit.yml`、`nexus-audit-pr.yml` — M455 仅手动触发
- `core/context/cve_dedup.py` — M456 全分支 `checked_at`/`sources`
- `core/context/daily_hunt.py` — M456 `noise_record` 接 `STATUS_CVE` 与留证字段
- `benchmarks/smoke_test_chains.py` — M457 `[350]` 3 项
- `STAGE_REPORT_2026-11-19_v1.5.27.md` — 本报告
