# 阶段报告 2026-10-20（d）：后缀截断转正 / DTO 主体载体 / 依赖版本证据

起点提交 `e13fef4`。本轮执行 Step 1 → Step 2 → Step 3，并跑了 Step 4 的零改动探针。

## Step 1 · `upload` 路径穿越存疑转正

**先核事实**：两条 `upload` 的落盘名 = `时间戳 + 随机数 + suffixName`，
`suffixName = fileName.substring(fileName.lastIndexOf("."))`。

**为什么这是确定性安全，而不是"看起来没事"**：`lastIndexOf(".")` 定位的是
**最后一个点**，截出的串必然是「`"."` + 一段不含点的尾巴」。

* 尾巴里没有点 ⇒ 拼不出 `..`；
* 以 `"."` 开头 ⇒ 不可能是绝对路径。

所以无论原始文件名塞多少 `../`，落盘名最多带 `/`（进子目录），无法上跳常量
基目录。这是字符串几何，可逐字符核对。

**但截断必须真的把值挡在门外**，三条同时成立才算（`_path_suffix_cut_masks_taint`）：

| 条件 | 含义 | 反方向护栏（冒烟 [49] 锁死） |
|---|---|---|
| ① 存在 `S = F.substring(F.lastIndexOf("."))` | 确实做了后缀截取 | 没有截断 → 维持 True |
| ② 除该赋值与 `F` 的定义外，`F` 不再出现 | 原文名没被另外拼进路径 | `new File(DIR + fileName)` → 维持 True |
| ③ 文件 API 实参的动态变量都能沿赋值/append 链走到 `S` | 截断结果真的进了 sink | 目录前缀来自请求参数 / 截断只为打日志 → 维持 True |

结果：`newbee ④ 后缀截断（转正）2 条必须判 False` ✔，
`pathtraver` 分布 `0 True / 61 False / 12 None`。

## Step 2 · 主体 ID 赋给 DTO 属性

**先核事实**：73 个入口里 `.setUserId(` 只有 **2 处**，都在
`ShoppingCartController`（save / update），且都跟一句
`cartService.saveNewBeeMallCartItem(item)`。

旧判据 2b 的第二条分支只要求「setter 右式来自会话主体」，**不要求 DTO 真的
进 Service** —— 只 set 不传也会判安全。本轮按双事实收紧：

```
item.setUserId(user.getUserId());      ← 右式必须是会话/Principal 主体变量
cartService.save(item);                ← 且该 DTO（或被 new X(item) 包一层）真进了 Service
```

抽出 `_container_flows_to_service()`，`params.put(...)`（2c）与 setter（2b-2）
共用同一段"容器 → 包裹 → 实参"判定。冒烟 [50] 三条断言：

* 主体入 DTO + DTO 进 Service → False
* 只 set 不传 → None（**不许**判安全）
* 右式是客户端自带的 `order.getUserId()` → None（**不许**判安全）

newbee authz 维持 **13/13 = 100%**。

## Step 3 · pom.xml 依赖版本证据（SCA 融合层）

新增 `core/context/dependency_versions.py`：

* 扫全部 `pom.xml`（父模块优先），还原 `<properties>` 占位符（限深 3 次，
  还原不了就**不记假版本**）；
* 只收版本敏感组件（fastjson / shiro / jackson / snakeyaml /
  commons-collections / xstream / log4j / struts2）；
* 只渲染该仓库真有的那几个，切片尾部加 `// ---- 依赖组件版本 ----`。

`deserial_verdict` 新增 fastjson 分支，**三态写死**：

| 证据 | 结论 |
|---|---|
| `fastjson < 1.2.83` + `JSON.parseObject` + 外部输入 | True |
| `fastjson >= 1.2.83`（safeMode 默认开） | False |
| 代码里显式 `setSafeMode(true)` / `setAutoTypeSupport(false)` | False |
| **没有版本证据** | **None** |

各仓库提取结果（实测）：

| 仓库 | 提取到 |
|---|---|
| micro_service_seclab | `fastjson = 1.2.31` |
| Hello-Java-Sec | fastjson 1.2.41 / xstream 1.4.10 / shiro-spring 1.2.4 / jackson-databind 2.11.0 / snakeyaml 1.27 / log4j-core 2.8.2 |
| JavaSecLab | fastjson 1.2.37 / xstream 1.4.14 / log4j-core 2.8.2 / shiro-spring 1.2.4 / commons-collections 3.2.1 |
| newbee-mall | （无敏感组件，**一块都不注入**） |
| BenchmarkJava | jackson-databind 2.22.3 |

`msseclab` 覆盖率 **19/20 → 20/20（100%）**，退回率 5% → 0%。

`core/context/dependency_versions.py` 已加进
`diag_owasp_sqli_fp._slicer_fingerprint()` —— 这次回归耗时 11 分钟（重建缓存），
不是 3 秒"假通过"。

## 全量回归

| 基准 | 结果 | 与上轮比 |
|---|---|---|
| OWASP 2740 全量 | **A = 0 / B = 0**，1352 条确定性判定 | 不变 |
| java-sec-code | Score **1.000**（65 样本） | 不变 |
| Hello-Java-Sec | 130 入口、60 覆盖、**59/59** | 不变 |
| JavaSecLab | 227 入口、42 覆盖、**41/41** | 不变 |
| micro_service_seclab | 20 入口、**20/20（100%）** | 覆盖 19 → 20 |
| newbee-mall（第 5 基线） | 73 入口、authz **13/13**、sqli 误报 0、后缀截断 **2/2** | 存疑 2 条转正 |

冒烟新增 **[49][50][51] 共 13 条断言**，`pre-push` 三项全绿。

## Step 4 · newbee-mall-api 零改动探针（只观测，未改代码）

详见 `PROBE_newbee_mall_api_2026-10-20.md`。三个数：

* **穿透不需要动**：62 入口 / 59 条有 Service 调用 / **59 条全部带进实现体** /
  52 条含 Mapper SQL；Mapper XML 里 `${}` **0 次**。
* **authz 18 条判 True，17 条同一个机制误报**：主体改为注解注入形参
  `@TokenToMallUser MallUser loginMallUser`，`_AUTHZ_SUBJECT_RE` 不认识它。
* **1 条真漏洞**：`/api/v1/paySuccess` 不取主体、不比 `userId` ——
  与 Web 版同构，未登录即可把任意订单置为已支付。

修法已定（本轮不动）：扫 `implements HandlerMethodArgumentResolver` 的类，
从 `supportsParameter` 取它支持的注解，建「注解 → 主体类型」索引并注入证据，
再让 `has_subject` 认这些形参。**不用"注解名里带 User 就当主体"那种名字启发式。**
第 6 靶场在修好之后再固化 —— 否则等于把 17 条已知误报写进基线。

## 未做的（明确挂起）

| 事项 | 状态 |
|---|---|
| 单接口多 `*Impl` 消歧 | 五个靶场 + newbee-mall-api 全部唯一实现，**零样本**，继续挂起 |
| `@TokenToMallUser` 主体识别 | 探针已确认撞上，实现留给下一轮 |
| 第 6 靶场固化 | 等主体识别落地 |
| `Map.of` / builder 主体载体 | 无真实样本 |
