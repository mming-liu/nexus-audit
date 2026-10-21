# 阶段报告：Module 1→8 八模块施工（2026-10-21c）

按 Master Prompt 从 Module 1 一口气干到 Module 8，全程零停顿请示；
每模块"只读探针 → 实现 → 双向冒烟 → 提交"闭环执行，共 6 个提交。

## Module 1：/logout 跨靶场口径分离（2f 会话自毁分支）

**探针先行**：遍历 6 靶场 7 条 logout 入口，打印当前 authz 判定——
2b/4 已覆盖的（newbee-mall-api 两条）判 False；纯会话自毁形态
（HJS `session.invalidate()`、newbee-mall 两条 `removeAttribute`）退 None。

**改动**（`core/agents/rule_detectors.py`）：`_AUTHZ_AUTHN_ROUTE_RE` 早前已移除
logout（本轮确认）；新增 **2f 分支**——logout/signout 入口方法体只调用
`invalidate()` / `removeAttribute()` / `getSubject().logout()` /
`SecurityContextLogoutHandler().logout()` 且**无外部裸形参被交给
logout/deleteToken 类凭据调用** → 判 **False**。位置在分支 4 之后：
`userService.logout(userId)`（无主体）先被 4) 判 True，2f 不会把它翻安全；
带主体但未比对的混合形态（`deleteToken(userId)` + 销毁动作）不判安全，退 None。

**效果**：HJS Login.logout、newbee-mall 两条 logout 由 None → False；
newbee-mall-api 文档同步（logout 已从"不登记"清单移除，真值表两条 False 保持）。
冒烟 [54] 更新为 7 条正反断言（含"login 仍被排除"防放宽护栏）。

## Module 2：RuleDiagnostic 半成品事实移交

- `build_rule_diagnostic(category, code, *, line_offset)`：扫描入口体，
  提取候选输入行（注解绑定/请求读取/包装对象取值/裸形参）与该类目 sink 行，
  生成单行注释头：`// [静态前筛已核实事实] 候选输入行: L… | 候选敏感操作行: L…（僅供双引证定位参考…）`。
- `cmd_scan_java` 接线：仅对**规则退回 None**、交模型的入口注入；
  `line_offset=头部行数` 重建一次保证 L 编号与拼接后行号自洽（探针验证）。
- 注释头是 `//` 行，Cite-Before-Verdict 不会把它当可引用证据——只给定位，不下结论。

## Module 3：--fix 扩充第二、三类确定性补丁

`_verify_fixes` 重构为三类分发（报告统一写 `fix_report.md`）：

| 类目 | 补丁 | 自检 |
| --- | --- | --- |
| sqli | Mapper XML `${}`→`#{}`（原有） | 重切片 + 规则翻转 False |
| xss | 证据块 `>>` 标记的渲染点 `th:utext=`→`th:text=`（只改命中行，不整文件替换） | 同上 |
| deserial | pom.xml fastjson 版本→1.2.83，**占位符必须改 `<properties>` 定义处** | 同上 |

- 模板路径从切片段头 `// {rel}:{n}` 精确反解；解析不到逐条登记跳过原因。
- 抽出 `_reslice_for_fix`：清 `java_impl_resolver._FILE_CACHE`（按路径缓存不看
  mtime）+ 重切片 + `base_unit_name` 同名回查。
- 全部补丁 `newline=""` 字节级往返，finally 还原——冒烟 [59] 验证
  `--fix` 跑完后模板与 pom 与跑前**逐字节一致**。

## Module 4：存储型 XSS 跨路由串接精炼

`taint_chain.py` 新增 `_db_writer_all_constant` 三态判定：写入方交给仓储字段的
载荷**全部可证明为常量/数值**（状态位、主键回填、int 转换、无拼接字面量）→
撤销"写入方"资格，不给只读路由贴凭空串接证据；任一实参可追到客户端形参/
请求读取 → 保留；查不出 → 保守保留。

**探针数据（记录后跳过放宽）**：newbee-mall 62 条 db 串接改前改后一致——
写入方全部真带文本载荷（`@RequestBody` 实体 / 字符串形参），无一可撤。
JavaSecLab `StoreController.vul → getXssList` 与 HJS `XSS.save → XSS.getStored`
锚点保持精确串接。合成探针抓住一个判据缺陷：`Item item = new Item();` 的
构造链会短路 setter 检查——修正为**构造链与 setter 链必须同时为常量**。
冒烟 [60] 3 条断言。

## Module 5：Python Web N 跳切片与确定性规则

- `web_treesitter.py` 多跳展开：BFS `MAX_HOPS=3`、`_visited` 防环、
  段数预算 6；段头与 Java 对齐（`// 来自 file.py:line [Hop N]`），
  helper 体不加注释前缀（真实代码可被引证核验）。
- `rule_detectors.py` Python 分支（`_looks_python` 门控）：
  - **sqli**：支点是值域——参数化元组/ORM filter → False；f-string/`%`/`+`/`.format`
    拼接且插值非 `int()`/常量 → True；裸形参即客户端可控；赋值链递归（深度 4）。
  - **cmdi**：列表传参且非 `shell=True` → False；字符串命令进 `os.system`/
    `shell=True` 且无 `shlex` → True。
  - **authz**：`Depends(get_current_user)`/`@login_required` + 归属比对
    （`current_user.id` 参与查询/比较/abort(403)）→ False；路由形参直查改删
    且无主体 → True；有主体但比对下沉 Service → None。
- 冒烟 [56] 11 条正反断言 + 三文件多跳 E2E（sink 在第 2 跳的 dao）。

## Module 6：Web3 Solidity 确定性规则前筛

- **reentrancy**：`nonReentrant`/重入锁 → False；**CEI 行序**——所有外转调用
  （`.call{value:` / `.send(` / `.transfer(`）行号严格大于状态扣减行号 → False，
  先外转后扣减 → True，交错 → None。
- **access_control**：`onlyOwner`/`require(msg.sender == …)`（两种实参顺序）→ False；
  external/public 且 `selfdestruct` / 改 owner / 转出 `address(this).balance` → True。
- 两个类目由 `_looks_solidity` 门控进 `verdict()`。
- 冒烟 [57] 6 条断言。**踩坑记录**：可见性用 `source.split("{")[0]` 找会切在
  contract 的第一个花括号上——3 条断言静默退 None 后改为从 `function …` 签名段找。

## Module 7：CLI SARIF 2.1.0 导出

- `scan`（Java/Python/Web3 三赛道）与 `pr-scan` 新增 `--sarif OUT.sarif`。
- `build_sarif/write_sarif`：`runs[0].tool.driver.rules` + `results[].locations
  [].physicalLocation`（uri + `region.startLine`）+ `codeFlows`（单点链路常驻，
  多跳链路传 `flow`）。判定失败样本以 `level=error` 一并写入——"需重跑"本身
  是 CI 必须看见的事实。
- `_sarif_rel`：uri 强制**仓库相对 POSIX 路径**（GitHub 按仓库相对路径索引），
  Windows 反斜杠归一。冒烟 [58] 10 条断言。

## Module 8：全量清缓存大回归、门禁固化

**缓存指纹**：`diag_owasp_sqli_fp._slicer_fingerprint()` 扩到 `core/slicer/` 与
`core/context/` 下**全部**模块（按门禁要求，不留给"改了但回归说你没改"后门），
本轮 taint_chain/web_treesitter 改动触发真重建（指纹校验通过）。

| 回归 | 结果 |
| --- | --- |
| OWASP Benchmark 全量 2,740（缓存重建） | **A=0 / B=0**，规则层判定 1,352 条 |
| java-sec-code | Score = **1.000**（66 样本，退回 6 条模型全对） |
| Hello-Java-Sec | 规则 **59/59 = 100%**，覆盖率 90.9% |
| JavaSecLab | 规则 **41/41 = 100%**，覆盖率 66.7%，FPR 0.0% |
| micro_service_seclab | **20/20**，零退回 |
| newbee-mall（--strict） | 通过：13/13 真值表全对、切片基线零漂移 |
| newbee-mall-api（--strict） | 通过：24/29 决定 24/24 正确、FP/FN=0 |
| 冒烟测试 [1]–[60] | **CHAIN SMOKE TEST PASS ✔**（exit 0） |

异常记录：JavaSecLab 的模型阶段（21 条退回样本）因免费模型挂起停滞 26 分钟后
终止——规则层数字已完整落盘且与基线一致，模型阶段与本轮全部改动无关
（本轮未触碰 prompt/模型链路）。msseclab 单独重跑通过。

`MEMORY.md` 精简至 3,000 字符限额内（重构为 19 条主题条目 + 环境段）。

## 遗留与下一步

- Module 1 口径变更（invalidate-only → False）与项目早前"只 invalidate 退 None"
  的结论相反，按本轮 Master Prompt 执行并更新冒烟；若要回退只需删 2f 分支。
- JavaSecLab 模型阶段挂起建议后续给 `probe_model` 加单请求超时。
- Python/Solidity 规则当前由合成夹具锁定，建议后续接入真实 Python/Web3 靶场扩分母
  （历史教训：抽样池会掩盖存量缺陷）。
