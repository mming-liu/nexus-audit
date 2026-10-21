# 阶段报告 2026-10-21（b）：Step 7 · PR 增量审计打通

起点 `0403ed9`。目标：`pr-scan` 从"能跑"到"能信"—— 改第 2/3 跳（ServiceImpl /
Mapper XML）的 diff，必须在数秒内反向定位受影响入口；对确定性检出的 sqli 给出
补丁并自检。

---

## 一、先跑 E2E 探针，四个缺口全部现形

在 newbee-mall 的 git 副本上构造四种 diff（基线 73 入口）：

| 场景 | 改动 | 期望 | 修复前 | 修复后 |
|---|---|---|---|---|
| A | 入口方法体（`PersonalController.logout`） | hot=1 | hot=1 + **误拉同名入口** | **hot=1 / dep=0** ✔ |
| B | 第 2 跳 `ServiceImpl.getMyOrders` | 反向 1 条 | ✔ | **1 条**（orderListPage）✔ |
| C | 第 3 跳 `NewBeeMallOrderMapper.xml` 语句 | 反向订单域 | **0 条（`无代码变更，跳过`）** | **6 条**（订单域全覆盖）✔ |
| D | 与入口无关的枚举（负样本） | 0 条 | 0 ✔ | **0** ✔ |

耗时全部 **~3 秒**。

## 二、四个缺口与修法

### 2.1 `.xml` 根本不在代码扩展名白名单里（最致命）

`code_exts = (".py", ".java", ..., ".sol")` —— XML 在进入任何逻辑**之前**
就被当"非代码"过滤掉，改 Mapper 的 PR 直接报"无代码变更，跳过"。
SQL 注入真值的所在地被增量扫描整体无视。加上 `.xml`。

### 2.2 Mapper XML 变更的反向依赖两层接住

* **精确层**：从 diff 增删行抓语句 id（`<select|insert|update|delete|sql id="x">`，
  `resultMap` 不收 —— 太宽，交给兜底），命中"切片里贴进了这条语句"的入口；
* **兜底层**：解析不出 id 时，凡切片引用了该 XML 文件名的入口全部拉入
  （`// 来自 NewBeeMallOrderMapper.xml [Hop 2]` 段头就是现成的引用证据）。

场景 C 实测：语句 id `findNewBeeMallOrderList` → 6 条反向依赖，
恰好是订单域的全部入口（管理端 list/update/info + 用户侧 orderListPage/selectPayType/payOrder）。

### 2.3 反向依赖只看第 1 跳

`called_symbols` 只来自入口自身方法体 —— 改 ServiceImpl 深层方法只有当
入口直调同名方法时才命中。改为**整份切片**取调用集：`[Hop N]` 段里的调用
正是"该入口可达"的证据（切片穿透 = 依赖关系，不需要再造 SymbolIndex）。
同时把**自己的方法名**从调用集剔除：切片签名行 `public String logout(` 会被
抓成一次 `logout` 调用，把同名入口全串进来（场景 A 实测多拉 1 条）。

### 2.4 切片器真 bug：同文件同名方法遮蔽 Mapper XML

`index.get(name)` 命中**同文件**方法后直接 `continue`，永远走不到 impl 查找 ——
控制器方法叫 `list()`、Mapper 语句也叫 `list`（CRUD 命名常态）时，SQL 段整段丢失。
迷你仓库合成复现后修复：同文件命中改为落空到 impl 查找，同名 XML 语句照样注入。

**七个靶场基线一个数都没动** —— 说明真实仓库里恰好没有这种遮蔽样本
（newbee/newbee-mall-api 的方法名都带了业务前缀）。但 `list`/`save`/`delete`
这种通用 CRUD 名迟早撞上，属于"探针构造出来才看见"的缺陷。

## 三、`--fix`：补丁自检

`pr-scan --fix`：对规则层判 True 的 sqli 命中，定位切片里的 Mapper XML，
生成 `${x}` → `#{x}` 补丁，**写进被审计仓库重切片、重跑规则**：

* 验证过（False）→ 输出 unified diff 到 `fix_sqli.md` + 人工确认提示
  （order by / 列名等标识符拼接场景不能这样修，应改白名单）；
* 验证不过 → 明确写"不推荐该补丁"。**验证不过的补丁比不修更危险。**

只处理规则层确定性命中 —— 让 LLM 生成补丁再让 LLM 验收，等于自己给自己判卷。

自检机制本身踩了两个坑，都被 E2E 探针当场抓住：

| 坑 | 症状 |
|---|---|
| 还原用默认文本模式 | Windows 上 LF 被写成 CRLF，"还原"变成一次真实行尾篡改（`git status` 直接变 M）→ 读写一律 `newline=""` 字节级往返 |
| `java_impl_resolver._FILE_CACHE` 按路径缓存、不看 mtime | 补丁后重切片读到旧内容，"补丁后仍 True"是缓存造出来的假结论 → 写补丁/还原后都清缓存 |
| `re.sub` 替换串写 `r"#\{\1\}"` | `\{` 原样保留，产出 `#\{name\}` —— **坏补丁还通过了规则验证**（规则只看没有 `${`）→ 替换必须用函数 |

第三条值得记住：**验证器只能验证"规则层收口了"，验证不了"补丁语义正确"** ——
如果 diff 不打出来给人看，坏补丁就静默上线了。

## 四、全量回归（切片器动了，全部真重建）

| 靶场 | 结果 |
|---|---|
| OWASP 2740 规则层 | **A=0 / B=0**，1352 条逐类目一致（缓存真重建） |
| java-sec-code | Score **1.000** |
| Hello-Java-Sec | **59/59**（covered 60） |
| JavaSecLab | 覆盖 42、**41/41** |
| micro_service_seclab | **20/20** |
| newbee-mall | 73 入口、authz 13 对、sqli 0 误报、后缀截断 2/2 |
| newbee-mall-api | 基线 62/59/59/52/56 全同、authz **24/24** |

冒烟新增 **[55] 3 条**（XML 语句 id 提取 + 全文调用集），共 55 节全过。

## 五、方法论沉淀

1. **切片穿透就是依赖关系**。pr-scan 不需要再造 SymbolIndex —— 切片里的
   `[Hop N]` 段是"该入口可达第 N 跳代码"的直接证据，全文调用集 + 语句 id
   匹配就是反向调用链。
2. **E2E 探针比单测贵重**：`code_exts` 漏 `.xml`、坏补丁骗过验证器、还原变成
   行尾篡改 —— 三个都是端到端跑一遍才现形，任何一个单测都测不出来。
3. **验证器有边界**："规则层收口"≠"补丁正确"。修复建议必须把 diff 原文打给
   人，验证通过只说明"可以进入人工确认队列"。
