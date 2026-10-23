# 阶段报告 STAGE_REPORT_2026-10-23c（M44 → M51）

延续 M43 收割线，本轮八个模块（M44-M51）一次连跑完成，全程零停顿、零门禁回退。

## 模块成果

| 模块 | 内容 | 结果 |
|---|---|---|
| M44 | 刺破 422 退回桶 | access_control 增加"调用者自域状态写"三档早退（纯自域写 / 自域外转 / 对等转账），全部要求"无特权 Sink"；**值位置**判据（外转金额须绑定自域槽位，形参金额形态不算）。退回桶 **422 → 330**（-92，21.8%）；smartbugs decided 177 → 180，地板同步上调 |
| M45 | 第四层 PoC Harness 合成器 | `core/sandbox/poc_synthesizer.py`：Solidity Foundry `.t.sol` / Python pytest / Java MockMvc 三语言模板 + 三语言自检（ast.parse / 括号配平+结构完整度）；`cli.py scan --emit-poc <dir>` 接线。只翻译"规则层已判 True"的，不自己判定；失败退回不抛异常 |
| M46 | 第 18 基准靶场 WebGoat | 教学关卡成对真值（攻击关 True / 修复关 False）；sqli 门 5 True + 1 False 全判对，**其余四门不登记**（pathtraversal/xxe/ssrf/idor 口径冲突或 sink 跨文件不可判）。新增"整句 SQL 由用户控制"分支（Java 四道闸门） |
| M47 | SHA-256 切片温缓存 | 两段式指纹：切片器源码**内容**哈希 ⊕ 靶场文件清单哈希 ⊕ bench 名；只存切片产物，判定永远现算。JavaSecLab 4.13s → 0.02s，4 靶场 32s → 0.03s；温冷 units 与判定逐位一致 |
| M48 | `--fix` 第 11/12 类补丁 | Solidity 补挂 onlyOwner modifier（modifier 定义从**文件**读，切片里没有）+ Python `yaml.safe_load`。两类 E2E 闭环：命中 True → 写入 → 重切片 → 规则翻 False → finally 字节级还原 |
| M49 | Mermaid 污点链路图 | `core/context/taint_graph.py` + `cli.py --graph`：段解析（entry/hop/impl/helper/context）+ Sink 行号**回源文件查**（切片片段基准只对入口段可靠）+ 标签转义（花括号用 `&lbrace;` 实体） |
| M50 | doctor 升五段 + 死正则清理 | 新增 `core/agents/regex_audit.py`（AST 口径三类正则卫生检查）；**死正则清理 12 处** + **内联遮蔽修复 6 处**；doctor 第五段含 PoC 合成器 / 覆盖地板 / SCOREBOARD 同步 / 正则卫生四项只读检查 |
| M51 | 全量冷重建 + 文档收口 | 清空切片缓存后冷重建 **21 PASS / 0 FAIL / 0 SKIP**；README 同步；MEMORY.md 压至 **2992 字符**（≤3000）；本报告；push |

## 回归状态

- 冒烟 `[1]`-`[93]`：**PASS ✔**（新增 [93] 12 断言：全量正则审计零问题 / 审计器三类阳性对照 / 自引用包装假阳性排除 / 11 个死正则名 `git grep -w` 空 / doctor 五段全绿）
- run_all `--offline --jobs 4`：**21/21 PASS / 0 FAIL / 0 SKIP**（冒烟 96.3s + 并发 18 项 15.5s）
- OWASP 全量回归：规则层判定 **1352 条**，与 M49 基线逐项一致（cmdi 0/126/0、crypto 130/0/116、hash 129/0/107、ldapi 0/27/0、pathtraver 9/124/23、securecookie 36/0/31、sqli 90/182/81、trustbound 0/83/0、weakrand 218/0/275、xpathi 0/15/20、xss 3/243/84）
- SCOREBOARD 十行全在，**误报 0 · 判反 0**；覆盖地板 10 项达标
- `cli.py doctor` 五段全绿，exit 0（隔离 venv；系统 Python 因缺 httpx 会报 FAIL，属环境缺件）
- 提交链：4b6b4f9 (M44) → 4c03449 (M45) → d3bec19 (M46) → 19af99a (M47) → 99c1859 (M48) → 786a325 (M49) → 5a77aca (M50) → M51 收口，全部推送

## 全语言计分板（规则层 · 离线可复现）

| 靶场 | 单元 | 规则判定 | 判对 | 误报 | 判反 | 覆盖率 |
|---|---|---|---|---|---|---|
| smartbugs-curated (Solidity) | 641 | 180 | 180 | 0 | 0 | 28% |
| DeFiVulnLabs (Solidity) | 323 | 9 | 9 | 0 | 0 | 3% |
| not-so-smart-contracts (Solidity) | 208 | 7 | 7 | 0 | 0 | 3% |
| vulpy (Python) | 33 | 6 | 6 | 0 | 0 | 18% |
| RuoYi (Java 多模块) | 305 | 159 | 159 | 0 | 0 | 52% |
| pygoat (Python Flask labs) | 119 | 9 | 9 | 0 | 0 | 8% |
| eladmin-mp (MyBatis-Plus) | 65 | 53 | 53 | 0 | 0 | 82% |
| VAmPI (Connexion/OpenAPI) | 14 | 7 | 7 | 0 | 0 | 50% |
| mall (生产级多模块对照) | 246 | 16 | 16 | 0 | 0 | 7% |
| WebGoat (教学关卡成对真值) | 179 | 6 | 6 | 0 | 0 | 3% |

**合计：误报 0 · 判反 0**（A/B 方向错误 = 0）

## 本轮新增机制要点

1. **早退判据按"值位置"**（M44）：形参金额形态（`msg.sender.transfer(amount)`）不算自域写 —— 金额可能来自合约整体资产；只有外转金额绑定自域槽位（`uint refund = refunds[msg.sender]`）才算。这一条把首版误伤的 smartbugs 官方真值 `wallet_04_confused_sign.withdraw` 拉回正确档位。
2. **"整句 SQL 由用户控制"四道闸门**（M46）：JDBC 执行方法 / 实参是标识符 / String 型形参（数字型注入不了）/ 形参来自外部输入（含 Spring MVC 默认绑定）。只认 True，绝不覆盖任何 False —— mall 全库零 True 的基线未被破坏。
3. **缓存指纹两段式**（M47）：切片器源码哈希 ⊕ 靶场清单哈希 ⊕ bench 名。此前 mtime 指纹会假失配 → 12 分钟假重建。
4. **补丁闭环里 modifier 定义必须从文件读**（M48）：切片只拼"本函数用到的"修饰符 —— 漏挂的那个在切片里没有定义。
5. **正则卫生三类**（M50）：死正则（顶层预编译零引用）/ 遮蔽冲突（顶层同名多次）/ 内联遮蔽（函数体内 `re.<fn>("字面量")` 与顶层正则同 pattern）。两个反直觉点：**自引用包装不算遮蔽**（`X = _CompatPrompt(X)` 是刻意包装），**内联遮蔽必须含类方法**（只看模块顶层函数会漏掉最常见形态）。
6. **SCOREBOARD 同步要比"现算"而非"找关键词"**（M50）：标签措辞会变（`eladmin-mp` vs json 键 `eladminmp`），按名字做子串匹配必假阳性；正确口径是"用当前 json 现算一遍再比表体"。这一条当场查出 M46 遗留的 WebGoat 行缺失。

## 遗留

- 退回桶 330 条（较上轮 422 降 92），剩余集中在"缺 Sink / 缺 Source"（xxe 1935、ssrf 1934、cmdi 1933 等均为跨靶场合计口径）与"含未知安全包装"（access_control 330、reentrancy 27）。确定性子簇已收割殆尽，进一步下压需模型层或人工标注。
- tree_sitter / pyyaml / slither 在 venv 中为可选依赖（正则降级路径工作正常），doctor 以"提示(可选)"报告不拦截。
- WebGoat 的 pathtraversal / xxe / ssrf / idor 四门口径未统一，暂不纳入真值表；待教学意图与 authz 判据对齐后再补。
- `cli.py doctor` 在系统 Python 下因缺 httpx 报 FAIL（环境缺件非代码问题），需用隔离 venv 运行。
