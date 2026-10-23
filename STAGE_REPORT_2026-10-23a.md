# Module 28 → 35 阶段报告（2026-10-23）

一次性全自动连跑。最终回归 **run_all --offline --jobs 4 = 17 PASS / 0 FAIL / 0 SKIP**，
SCOREBOARD 七个真值型靶场合计**误报 0 · 判反 0**，冒烟 [1]-[79] 全绿（486 OK）。

## 一、Module 28：RuoYi 剩余命中收口（2h 判据）

探针核查 18 条剩余 True 命中：11 条 `checkXxxUnique`（boolean 存在性、无写操作、
无实体回显）被新增 **authz 2h 只读唯一性校验豁免** 消解（三事实缺一不可：签名
返回 boolean / 无写操作 / 全部 Service 调用都是 check*Unique 形态）。无注解
True 面 16 → 5。其余 7 条不收真值、单列在案：5 条未标注实体读取、
GenController.create（SqlUtil.filterKeyword 是黑名单，铁律黑名单只能 None）、
updateAvatar（服务端路径常量 + 扩展名白名单）。M23 DTO 守卫夹具改非 Unique
形态（原夹具即 checkLoginNameUnique，被 2h 正当豁免，守卫意图保留）。

## 二、Module 29：第 15 靶场 eladmin-mp（MyBatis-Plus + Spring Security EL）

53 条 `@PreAuthorize("@el.check('...')")` 垂直授权声明全部直判 False，零误报
零判反。sqli 新增 **C3/C4**：Wrapper 拼接出口（`.apply/.last/.inSql/.orderBySql`
实参含拼接或裸变量）→ True；纯参数化 Wrapper → False（放在 MyBatis 判定之后，
避免与集合 `.in(` 同貌打架）。探针实测 `.apply/.last` 拼接在靶场内 **0 命中**、
占位符绑定 `.apply("col = {0}", x)` 不算拼接——True 侧机制由冒烟 [75] 夹具锁定，
不凑分母。authz 新增 `@AnonymousAccess` 显式匿名声明 → None。9 条未标注授权面
（AliPay/Verify/Generator）单列。run_all 第 17 项 + pre-push 基线接入。

## 三、Module 30：Solidity 三大确定性规则

- **tx.origin 鉴权**（access_control）：require/if 恒等比较且无 msg.sender
  保护 → True；两者并存时保护优先。
- **任意 from 的 transferFrom**：签名收 `address from` 形参 + 直转 + 无保护
  → True；`require(_isApprovedOrOwner(...))` 认作保护（机制与 msg.sender 恒等
  检查等价）→ False。
- **unchecked_low_level_calls 新类目**（smartbugs 登记 393 条）：按调用点逐个
  判——调用点位于控制关键字**条件括号平衡区间内**才算被检查（`if (cond)
  owner.send(...)` 的调用是语句体，未检查——finalize 判反教训）；语句头可能是
  行注释，用**等长空白替换**保偏移量（TownCrier request 误报教训）。
- smartbugs 确定性判定 **101 → 175**；DeFiVulnLabs txorigin + NFT transferFrom
  成对真值 3 条转确定性。

## 四、Module 31：--fix 第 7/8 类补丁（家族扩至八类）

第 7 类 `_fix_solidity_txorigin`：tx.origin → msg.sender，重切片 + access_control
翻 False 自检；第 8 类 `_fix_mp_concat`：`.apply("col = '"+x+"'")` →
`.apply("col = '{0}'", x)`（单变量拼接），重切片（清 _FILE_CACHE）+ sqli 翻 False
自检。均 finally 字节级还原，E2E 闭环入冒烟 [77]。

## 五、Module 32：OWASP 回归并行化（探针修正施工单假设）

- **施工单热点假设不成立**：verdict 温路径仅 2.4s（4 worker 并行无收益）；
  真热点是 12 分钟级**冷缓存重建**。
- 落地：verdict 分片并行（`--workers N`，主进程按 sorted(truth) 原序聚合）+
  冷缓存按 `_iter_java_files` 原序分片并行 `_slice_file`、主进程全量
  `_attach_chains`（跨文件语义不出 worker）。
- 实测：冷重建 647s vs 串行 721s（**~10%，未达 50-75% 目标**）——瓶颈疑似每
  worker 重复构建全仓懒加载索引，按约束 2 记录事实。正确性已证：units 5483 项
  逐位一致、A/B 输出 diff 为空、1352 条判定不变。
- **额外收获（M35）**：定位到假重建根因——缓存指纹用 `mtime_ns`，任何进程触碰
  文件都造成假失配（实测连撞三次 12 分钟假重建）。改为**内容哈希**，两方向都
  正确：内容没变必命中（现 2.4s），内容变了必失效。

## 六、Module 33/34：退回池剖析与精准收割

`triage_fallbacks.py`（只读）：7 靶场全单元 × 10 类目，None 退回按 缺Sink/
缺Source/跨文件链路未闭合/含未决Helper/含未知安全包装 五桶聚类。全池 Top 是
各语言通类目的"缺 Sink"（预期噪声）；可收割面榜首 = access_control/含未知安全
包装（432）。其中确定性可证子簇 = **借贷池回调 initiator 校验**：Aave flashLoan
协议回调 `executeOperation` 带 initiator 形参——`require(initiator ==
address(this))` → False（成对修复形态），无 initiator 比较 → True。
DeFiVulnLabs 确定性判定 6/9 → **8/9**（仅剩 ERC777 claim 退回），smartbugs/nssc
零漂移。

## 七、门禁现状

- run_all **17 项**全 PASS（新增 eladmin-mp）；OWASP 1352 条 A=0/B=0。
- SCOREBOARD 七行（新增 eladmin-mp 82% 覆盖）：**合计误报 0 · 判反 0**。
- 冒烟 [1]-[79]（486 OK）：新增 2h、MP Wrapper、@el.check/@AnonymousAccess、
  Solidity 三规则、补丁 7/8 类闭环、分片不变性、initiator 判据。

## 八、提交清单（本地 8 笔，本报告随 M35 收口笔一并 push）

914458d M28 / 64b8d91 M29 / cd54aac M30 / 832c043 M31 / f6a8f7b M32 /
0798735 M33 / 22329bb M34 / M35 收口 = 本报告 + 指纹修正 + push。
