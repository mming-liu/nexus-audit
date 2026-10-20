# 阶段报告 2026-10-20（三）：同名重载 / Map 主体判据 / 别名路由

承接 `2726432`。本轮按既定顺序做完三步，全部改动都在"证据层"与"判据层"，
未引入新模型调用、未新增任何 LLM 提示词。

## 一、同名重载不再丢入口（会改分母的那一步）

**根因**：`_slice_file` 用 `methods: dict[name]` + `setdefault` 收集方法。
RESTful 控制器里同名重载是常态（`PUT /shop-cart` 与 `DELETE /shop-cart/{id}`
都叫 `updateNewBeeMallShoppingCartItem`），后定义的那条入口**静默消失** ——
不报错、不进日志、指标上看不出来，只有人工数入口才会发现。

**改法**：收集改为 `list[(name, start, end, src, anns)]`，按源码顺序排序，
`occur` 计数生成唯一名：裸名留给第一个定义，后续 `#2`/`#3`。
唯一性只影响 `unit_name`，**没动任何"唯一定义"的入口名**，
五个靶场里按 `类.方法` 硬编码的真值表全部保持有效。

**真值表一侧**：新增 `core/models.base_unit_name()` 剥 `#N` 后缀。
凡"拿 unit_name 去对表"的地方都接上了它：`benchmark_newbeemall._lookup_truth`、
`benchmark_hellojavasec.classify`、`benchmark_javaseccode.classify`、
`benchmark_owasp`/`diag_owasp_xss` 的 doPost 筛选、`benchmark_msseclab` 的
endswith 兜底、`cli.py` 的增量扫描方法名比对。

**实测找回 5 条**（与上一轮预估完全一致）：

| 靶场 | 入口数 | 找回的重载 |
| --- | --- | --- |
| newbee-mall | 70 → **73** | `AdminController.login#2`（POST /admin/login）、`NewBeeMallGoodsController.edit#2`（POST 编辑）、`ShoppingCartController.updateNewBeeMallShoppingCartItem#2`（DELETE /shop-cart/{id}） |
| Hello-Java-Sec | 128 → **130** | `SSTI.getDocument#2`（safe 分支）、`MyBatis.queryById#2`（safe 分支） |
| java-sec-code / JavaSecLab / msseclab | 132 / 227 / 20 不变 | 无同名重载 |

`KNOWN_MISSING` 换成反向护栏 `RECOVERED_OVERLOADS`：这 5 条一旦再次消失，
`--strict` 直接非零退出 —— 免得哪天又退回"按名字去重"而没人发现。

**这一条会改分母，所以同步更新了基线**：newbee 73 / 55 / 54 / 58 / 37；
authz 真值 12 → 13（新增的 DELETE 也是"主体值参与资源定位"，判 False）。
13/13 全对，FP 0，FN 0。

## 二、`/orders`：主体值写进查询容器

`OrderController.orderListPage` 的写法是三步：

```java
NewBeeMallUserVO user = (NewBeeMallUserVO) httpSession.getAttribute(...);
params.put("userId", user.getUserId());
PageQueryUtil pageUtil = new PageQueryUtil(params);
orderService.getMyOrders(pageUtil);          // → where user_id = ?
```

主体**确实**参与了资源选择，但旧判据只看"Service 实参里出现
`user.getUserId()`"（2b 分支），主体值被搬进 Map 之后实参里只剩 `pageUtil`，
于是整条落空、退回模型。这是本轮唯一一条规则覆盖缺口。

新增 2c 分支，两个事实缺一不可：
① 主体 id 被 `put` 进某个容器；② 该容器（或被 `new Xxx(params)` 包了一层
的那个对象）确实作为实参进了 Service/Mapper 调用。只放不传说明不了任何查询范围。

结果：newbee authz 覆盖 12/13 → **13/13（100%）**，13/13 判定正确。

## 三、类级 `@RequestMapping` 的数组形式

`@RequestMapping({"/admin", "/manage"})` 让同一个方法在两条路径上都可达。
旧实现取第一个字面量当前缀，route_path 是对的，但**装配查询只查那一条** ——
只给 `/admin/**` 挂拦截器时，切片里会写着"本路由受 /admin/** 保护"，
而攻击者走 `/manage/...` 就绕过了。方向性错误，比漏报更危险。

改法：
- `route_path` 仍取第一个（字段只能存一个），另记 `Alias-Route:` 首行注释列出全部可达路径；
- 装配证据改走 `describe_aliases()`：对全部别名取**交集**，只有都被同一个
  组件覆盖才渲染保护证据；部分覆盖时给一条**不含 `addPathPatterns` 原文**的提示
  （否则 `_AUTHZ_GLOBAL_GUARD_RE` 会把提示本身读成"受全局拦截"）；
- 路径字面量解析先定位 `value=` / `path=` 的取值段、截到顶层逗号为止 ——
  `produces = "application/json"` 这类媒体类型不许被当成别名。

冒烟新增 [47]/[48] 共 14 条断言，覆盖：重载不丢、裸名归属、`#2` 路由正确、
`base_unit_name` 往返、别名 2×2 展开、produces 不误收、部分覆盖不报保护。

## 四、回归

见下表（离线规则层，不调模型）：

| 靶场 | 入口 | 真值 | 规则覆盖 | 正确率 | 方向性错误 |
| --- | --- | --- | --- | --- | --- |
| java-sec-code | 132（不变） | 65 | 63/65 | 31TP+34TN, Score **1.000** | 0 |
| Hello-Java-Sec | 130（+2） | 66（+1） | 60/66（90.9%） | **59/59** | 0 |
| JavaSecLab | 227（不变） | 63 | 42/63（66.7%） | **41/41** | 0 |
| micro_service_seclab | 20（不变） | 20 | 19/20（95%） | **19/19** | 0 |
| newbee-mall | 73（+3） | authz 13 | 13/13（100%） | **13/13** | sqli 误报 0 |
| OWASP 全量 2740 | — | — | 1352 条确定性判定 | A=**0** / B=**0** | 逐类目与上一轮一致 |

## 五、一次假回归：量错了对象

改完切片器的输出顺序后，OWASP 回归第一次跑出 **A=264（全是 xss）**。
基线是 0，看上去是灾难性回归。

实际是回归脚本自己的问题：

```python
hit = [k for k in units if name in k]     # 一个用例类有 doGet + doPost 两条入口
src = units[hit[0]]                        # 取第一个 —— 取决于 dict 顺序
```

旧切片器按方法体长度倒序收集方法，doPost 更长所以排在前面，`hit[0]` 恰好是
doPost；改成按源码顺序输出后 doGet 排到了前面，规则审的是"只做转发的 doGet"，
自然一路判 False。**真值标注的是 doPost 那条链路**（`benchmark_owasp.py` 里
写得很清楚："只保留 doPost 入口"）。

已抽成 `pick_unit()`（`diag_owasp_sqli_fp.py`）显式锁 doPost，四处调用点
（回归 + 三个 diag）统一改掉，A/B 回到 0/0、1352 条判定逐类目一致。

教训与第 34 条同类：**"用 `in` 找入口"必须说清命中的是哪一条**。
`'X' in src` 只证明存在，不证明取到的是要审的那个。

