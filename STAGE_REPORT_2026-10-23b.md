# 阶段报告 STAGE_REPORT_2026-10-23b（M36 → M43）

延续 M35 收割线，本轮八个模块（M36-M43）一次连跑完成，全程零停顿、零门禁回退。

## 模块成果

| 模块 | 内容 | 结果 |
|---|---|---|
| M36 | 432 退回桶确定性子簇收割 | 430→422（onlyOwner 成员检查家族 8 条）；DeFiVulnLabs 9/9 满贯（ERC777 claim reentrancy：映射索引写必为状态变更 + 双参 token.transfer 钩子可回调 + CEI 反序） |
| M37 | 第 16 基准 erev0s/VAmPI | Connexion/OpenAPI 路由通道（yml `operationId` 零装饰器函数）+ JWT 主体链/BOLA 判据；14/14 入口全切出、7/7 STRICT PASS |
| M38 | 第 17 基准 macrozheng/mall | MBG `Example` 参数化判据（`setOrderByClause` 非字面量→True）+ `getCurrentMember` 主体链（2g-2）+ 仓库级全局鉴权豁免（`[global-authz]`）；16 条真值全判对 + 全库 246 单元零 True |
| M39 | web3 跨文件父合约 modifier 继承 | `_build_parent_index` + BFS 防环 `_inherited_mods`；证据段贴 `// ---- 父合约继承证据 [Base.onlyOwner] ----`；抓不到保持缺证退 None |
| M40 | `--fix` 第 9/10 类补丁 | Solidity executeOperation initiator `require(== address(this))`；Python `shell=True` → `shlex.split` 列表；两类 E2E 闭环（命中→补丁→重切片翻 False→finally 字节级还原） |
| M41 | 覆盖地板门禁 | `triage_fallbacks.py --check-floor`：FLOORS 硬编码 9 真值靶场 decided 下限，接 run_all 第 20 项 + pre-push；判定挂 results/*.json 不挂脚本 |
| M42 | `cli.py doctor` 子命令 | 四段只读自检：依赖（python/httpx 必需，tree_sitter/pyyaml/slither 可选降级）、19 类 verdict 路由（空源码必 None）、缓存指纹两次一致、10 补丁器就位；exit 0。README 同步 17 靶场/20 项/19 判据/10 补丁 |
| M43 | 全量收口 | run_all --offline 20 项全绿；SCOREBOARD/triage 刷新；MEMORY.md 压至 2770 字符（≤3000）；本报告；push |

## 回归状态

- 冒烟 `[1]`-`[86]`：**513 OK**（新增 [80]-[86] 共 28 断言）
- pre-push 13 段基线全绿（含 VAmPI / mall 基线段 + 覆盖地板门禁）
- run_all `--offline` 20/20 项 PASS（结果见 SCOREBOARD.md）
- 提交链：8fef4c5 (M36) → 8f4fa01 (M37) → dacb561 (M38) → f788466 (M39) → 24e2a23 (M40) → d5e3a07 (M41) → 8e1e819 (M42) → M43 收口，全部推送

## 本轮新增机制要点

1. **映射索引写即状态变更**：Solidity `x[k] += / -=`（映射不可能是局部变量）——机制层证据不依赖命名关键词，收割 onlyOwner/余额家族的关键支点。
2. **值域支点的第 4 形态**：MBG `Example` + `setOrderByClause` 字面量判定，Java 分页排序注入的唯一出口是 XML `${orderByClause}`。
3. **值位置精确判定**（VAmPI BOLA）：成对双形态 `= str(形参)` / `= 形参` / 位置实参才算；键名同名不算（`username=resp['sub']` 形参名与 ORM 键同名的陷阱）。
4. **仓库级豁免的切片标记**：`[global-authz]` 方括号标签——`// ---- ` 形态恰是 entry_body 分隔符会吞掉整个方法体。
5. **覆盖地板与严格门禁分工**：strict 锁误报/判反；地板锁 decided 覆盖率下限——两条独立护栏，覆盖率下滑不再无人拦。
6. **doctor 的"空源码必 None"自检**：19 类逐一 `verdict(cat, "")`，任何一类在空源码上给出 True/False 即注册表腐烂。

## 遗留

- 退回桶 422 条，剩余多为"跨文件链路未闭合 / 未知安全包装"类，确定性子簇已收割殆尽，进一步下压需模型层或人工标注。
- tree_sitter / pyyaml / slither 在 venv 中为可选依赖（正则降级路径工作正常），doctor 会以"提示(可选)"报告不拦截。
