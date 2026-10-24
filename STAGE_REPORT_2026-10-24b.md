# 阶段报告 M55–M62：野战模式收官（2026-10-24）

> 承接 M54（GPTScan-Top200 四类目 FPR 0.00% / smartbugs 205/205）之后的
> 八模块收官单：M55→M62 一次跑完，`cli.py scan <repo> --auto --fix --html`
> 成为可对任意野生项目开猎的实战入口。

## 本轮模块一览

| 模块 | 内容 | 提交 |
|---|---|---|
| M55 | `--fix` 第 13/14 类补丁器（arithmetic 守卫注入 / unchecked require 包裹），doctor 升 14 类 | 771289e |
| M56 | PoC 合成器 arithmetic / unchecked_low_level_calls 两类 Foundry 模板 | 88e5aea |
| M57 | 零外部依赖单文件 HTML 报告（`scan/pr-scan --html`），html.escape 严格转义 | b78f392 |
| M58 | `scan --auto` 野战模式：全类目毫秒级普查 + Sink 门控漏斗 | d8c0204 |
| M59 | LLM 响应内容寻址磁盘缓存（断点续扫，失败不缓存，`--no-llm-cache` 禁用） | e295d98 |
| M60 | 报告 P0/P1/P2 三档分桶（Markdown 分区 / HTML 排序 / SARIF properties） | e295d98 |
| M61 | 野战一键组合 E2E 演习（三语言混合仓，四类产物落盘） | 3232047 |
| M62 | 全量门禁总验收 + 文档封版 | 本提交 |

## 野战两级漏斗（M58）

- 第一级：按语言自动遍历全部类目跑规则 —— True→**P0 实锤**（不调模型），
  False→静默排除；
- 第二级：None 对用 `build_rule_diagnostic` 门控（外部输入行 + 敏感 Sink 行
  双事实），无事实直接过滤。E2E 实测过滤率 **100%**、均值 3–4 ms/单元。

## P0/P1/P2 三档（M60）

- **P0 [Confirmed]**：规则层确定性 True；附 `--fix` 自检通过标注；
- **P1 [High-Confidence]**：模型 Cite-Before-Verdict 双引证 + Skeptic 未推翻
  （模型阶段产出，offline 留空段）；
- **P2 [Review-Needed]**：Sink 门控候选 / 被质疑项，归底部折叠区。
  Markdown 分区序、HTML 排序、SARIF `properties.priority` 三通道同口径。

## M61 E2E 演习数据

smartbugs reentrancy + vulpy 路由 + Hello-Java-Sec JDBC 三语言混合仓：
12 入口 × 174 判对（54 ms）→ Java SQLi ×3 + Solidity 重入 4 条 P0；
HTML / SARIF / Mermaid / PoC（3 Java MockMvc + 1 Solidity Foundry）全部落盘；
补丁自检报告 `fix_report_auto.md` 生成；漏斗过滤率 100%。

## 回归与门禁

- 冒烟 [1]–[101] 全 PASS（百组里程碑，新增 [96]–[101] 共 29 项）；
- `run_all.py --offline --jobs 4`：21 PASS / 0 FAIL（详见 SCOREBOARD.md）；
- `cli.py doctor`：21 类规则注册表 + 14 类补丁器 + 正则卫生全绿；
- Top200 四类目 FPR 0.00% / smartbugs decided 205/205 维持不回退。

## 本轮工程教训（已入工作记忆）

- Git Bash heredoc 会把 `\` 后跟 `:`/`]` 的 `\s`/`\w` 静默转成 `/s`/`/w`
  —— 含正则的补丁一律用文件编辑工具；
- `_reslice_for_fix` 是 Java 专用（JavaSlicer），Solidity 补丁器必须用
  `SoliditySlicer(repo).extract_entry_units(repo)`；
- WebTreeSitterSlicer 只切带路由装饰器的入口 —— 野战夹具必须带
  `@app.route` / `@WebServlet`；
- SCOREBOARD 刷新存在"run_all 全绿才刷板 ↔ 冒烟依赖 doctor 查板同步"
  的死锁，数据核实后手动 `build_scoreboard()` 刷一次解锁。
