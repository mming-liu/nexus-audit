# STAGE REPORT · v1.5.3（M365：Issue 假重复门禁）

> 日期：2026-11-13 ｜ 基线：v1.5.2（0b0d20c）
> 结论：今日巡猎 10:24:29 落盘（A=0 / B=38）。查重把 **201 条** Dependabot /
> awesome-list / 功能 issue 当成"已报过"，真根因被静默压掉；已在证据层修掉，
> 并清理了这批污染缓存。

## 一、今日巡猎实况

| 项 | 值 |
|---|---|
| 起止 | `09:02:10` → `10:24:29`（82 分钟） |
| 候选 / 实扫 / 跳过 / 失败 | 24 / 10 / 7 / 0 |
| 根因 | 38（A=**0**，B=38，全部 UNKNOWN） |
| 原因 | NVD **515/515 全部 `nvd_circuit_open`**；按 v1.5.1 门禁，FRESH 一律压 B |

A=0 是"NVD 查不到就不宣称首杀"的诚实结果，不是漏报。

## 二、新问题：201 条假 `DUPLICATE_ISSUE_OR_GHSA`

今日 dedup 缓存里 201 条判重，命中证据全不是漏洞报告：

| 仓库 / 方法 | 被当成"已报过"的证据 | 实际 |
|---|---|---|
| `apowerb` `list_tool_configs` | `Agenta-AI/awesome-ai-agent-platforms#29 Add apowerb` | awesome-list 收录 |
| `MimirQ` `update_dataset` | `#63 Bump the python group across 1 directory with 52 updates` | Dependabot |
| `backlot` `get_block` | `#1098 notion: a page, a block and a data source answer…` | 功能 issue（分词命中） |
| `docling-Studio` `preview` | `#318 [ENHANCEMENT] Cache preview renders…` | 功能需求 |

来源分布：`github_global_issues` 109 条、仓库内 `github_issues` 90 条、
`github_advisories` 2 条。

**根因**（三处叠加）：

1. 仓库内 Issue 分支只判 `total > 0` 就定 `DUPLICATE_ISSUE_OR_GHSA`，
   而同函数的 GHSA / CIRCL 分支都做了 `_unit_in_text` 过滤 —— 唯独这里漏了；
2. 全网 Issue 分支同样只看 `total > 0`（`_gissue_hit`），而 GitHub 搜索按
   token 分词（`get_block` → `get` + `block`），"命中"不等于"在说这个漏洞"；
3. v1.5.1 新增的"泛化方法名 → 文件名退化搜索"（`"MimirQ" "datasets"` /
   `"apowerb" "tools"`）把命中面进一步放大。

后果：真根因被压成"重复"后**直接不进报告**（B 板也没有），比"查不到"更危险。

## 三、M365 修复：Issue 证据门禁

`core/context/cve_dedup.py`：

| 改动 | 说明 |
|---|---|
| `query_github_issues` / `_search_global_issues` 透传 `items` | 每条保留 `{id, title, text(title+body)}`，否则没法核对 |
| `_issue_dup_evidence()` | 三条件缺一不可：① 标题不是 `Bump`/`chore(deps)`/`dependabot`/`awesome-`/`Add X to Y`/docs 噪音；② 标题含安全语义词（CVE/GHSA/injection/bypass/unauthorized/…）；③ 方法名或文件名在标题+正文里**逐字**出现（`_unit_in_text`） |
| 两个分支接入 | 仓库内 `issue_hits` 与全网 `_gissue_hits` 都先过滤，再判 `DUPLICATE_ISSUE_OR_GHSA` |
| `_GENERIC_FILE_STEMS` 扩充 | `tools/utils/config/datasets/pipeline/…` 不再作为退化检索词 |

实测（`[326]` 门禁）：awesome 收录 / Dependabot / 功能 issue / 分词误命中 →
全部 `False`；真 `SQL injection in list_tool_configs` 与
`Unauthenticated access to update_dataset` → `True`。端到端：假 issue 场景
状态回到 `ZERO_RECORD_FRESH`，真 issue 仍判 `DUPLICATE_ISSUE_OR_GHSA`。

## 四、数据处置

清掉今日 201 条假重复缓存（`.cache/cve_dedup/`，gitignored），避免 24h 内
继续复用；下次扫描会按新门禁重新查。

## 五、门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,603 项**（+8：`[326]`） |
| `triage_fallbacks.py --check-floor` | 16/16 |
| `cli.py doctor` | PASS |
| `.githooks/pre-push` | exit 0 |

## 六、明日预期与遗留

1. 假重复归零后，同样的仓应能正常进入 B（NVD 熔断时）或 A（NVD 恢复时）。
2. **NVD 仍是主瓶颈**：今日 515/515 熔断，需要换出口或加 NVD API key。
3. **GitHub 403 限流 171 次**：全网 Issue 搜索在无 token 下被限流，建议配
   `GITHUB_TOKEN`，否则 `github_global_issues` 的证据缺口会长期存在。
4. 今日报告不重生成：38 条 UNKNOWN 是真实结果；被压掉的 201 条需重扫才能
   回到报告（`daily-hunt --cooldown-days 0`）。
