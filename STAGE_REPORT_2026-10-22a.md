# STAGE REPORT — Module 9→16（2026-10-22）

## 总览

九个模块（9/10/11/12/13/14/15/16）一次性施工完毕。`nexus-audit` 从"Java 单语言
强底座"升级为 **Java / Python / Solidity 三语言、8 个真实外部靶场、64 组冒烟
断言、全离线一键门禁**的完整审计引擎。

| 门禁（`benchmarks/run_all.py --offline`） | 结果 | 耗时 |
|---|---|---|
| 冒烟测试 [1]–[64] | PASS | 34.8s |
| 争议登记核对 | PASS（4 条逐字对上源码） | 0.5s |
| OWASP 全量 2,740（缓存重建） | PASS，规则层判定 1,352 条 | 660.3s |
| java-sec-code / HJS / JavaSecLab / msseclab | PASS | <7s each |
| newbee-mall / newbee-mall-api（--strict） | PASS | 2.4s each |
| **vulpy（Python，--strict）** | **6/6 全对，零误报/零静默/零退回** | 0.6s |
| **smartbugs-curated（Solidity，--strict）** | **48/48 全对，零误报/零判反** | 0.6s |

**合计 11 PASS / 0 FAIL / 0 SKIP。**

## 各模块落地

- **Module 9**：`OpenAICompatClient` 硬超时 45s / 重试 1 次 / 连续 3 次整体超时
  熔断（`ModelCircuitOpen` 快速失败，非超时错误不喂计数）。JavaSecLab 挂起
  26 分钟的问题从根上收口。`build_rule_diagnostic` 正式接入 `ScenarioMatcher`
  （按类目局部 code，不变异 `unit.source_code`）。
- **Module 10/11**：`vulpy` 第 7 靶场（bad/ vs good/ 成对真值，真值来源=逐文件
  diff）。蓝图路由、跨文件 Hop、`request.form.get` 外部输入识别全部打通；
  新增 `python_xss_verdict`（render_template_string/Markup vs render_template）。
- **Module 12/13**：`smartbugs-curated` 第 8 靶场（官方漏洞行号 → 函数级真值，
  safe 分母 198）。老语法 `call.value()()`、无参 modifier、修饰符实现体核验、
  错名构造函数（Rubixi 判 True）、tx.origin 不算保护——五个真实形态全部收口。
  parity 两文件 `kill` 官方真值自相矛盾 → DISPUTED 剔除（不为分数改判据）。
- **Module 14**：`--fix` 语言路由 `_verify_fixes_any`；Python ast 参数化补丁
  （四种拼接形态 → `execute("... ?", (x,))`）；Solidity CEI 紧邻反序行交换。
- **Module 15**：`run_all.py --offline` 计分板；`.github/workflows/nexus-audit-ci.yml`
  （冒烟 + 争议核对 + cli 导入自检）；pre-push 追加 vulpy/smartbugs 两道门禁。
- **Module 16**：本报告 + 全量回归 + 合规提交推送。

## 本轮最有价值的六个工程发现（真实靶场抓出来的）

1. **`_looks_solidity` 不认函数级切片**（无 pragma/contract 头）→ Solidity 规则
   在 smartbugs 上**全部**静默退 None。识别门必须覆盖"切片里没有文件头"的形态。
2. **`SymbolIndexer.DEF_RE` 的 `\s*` 跨行吞空行** → `m.start()` 落在空行、
   indent 判成 2、符号段吞到文件尾 → **未调用函数的 sink 污染切片**，vulpy
   good（参数化）被判 True。教训同"扫描范围比判据更容易错"：缩进捕获只许
   `[ \t]*`。
3. **SQL 字符串里的 `%s` 占位符劫持 % 运算符切分** → 引号感知的顶层 `%` 定位。
4. **f-string 判定必须要求 f 前缀**：`"... '{}'".format(x)` 的花括号占位符会把
   `.format` 调用误路由进 f-string 分支返回 None。
5. **modifier 保护看实现体不看名字**，且纯状态门（`only_uninitialized` 查
   `m_numOwners`）不是身份检查——拿它判安全会把 parity `initWallet` **判反**；
   判反比退回恶劣，宁退 None。
6. **非超时错误不得喂熔断计数**；探针夹具必须真实——本机 `127.0.0.1:1` 因防火墙
   静默丢包抛的是 ReadTimeout，"连接拒绝"夹具要用 accept-即断服务器。

## 遗留与下一步

- smartbugs/vulpy 规则层退回样本（198+ 条 None）目前无 Python/Solidity 模型
  阶段跑分——可仿 Java 基准接入 `ScenarioMatcher`（`code_language` 已就位）。
- GitHub Actions 上无靶场仓库（reference_repos 不入 git），CI 只跑不依赖外部
  仓库的门禁；如需 CI 全量，可加缓存或 artifact 分发靶场。
- `wallet_04_confused_sign` 等 access_control FN 形态（签名混淆）未实现判据，
  目前退模型。
