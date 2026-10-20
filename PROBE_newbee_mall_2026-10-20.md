# newbee-mall 零改动盲测报告

**日期**：2026-10-20
**目标**：`newbee-ltd/newbee-mall`（真实电商后台，70 个入口，标准 4 层
`Controller → Service(接口) → ServiceImpl → Mapper.java → Mapper.xml`）
**做法**：先跑零改动探针，只按探针显示的事实动刀。探针脚本：`benchmarks/_probe_newbee.py`

---

## 一、探针结果（零改动时）

| 指标 | 改前 | 改后 |
|---|---|---|
| 入口总数 | 70 | 70 |
| 有跨文件 Hop 段的入口 | — | **55** |
| 切片里含 ServiceImpl 方法体 | 见 §二 | **46** |
| 切片里含 Mapper XML 语句 | 11（且多数是**错的**） | **36** |
| 有 service 调用的入口 | 53 | 53 |
| 其中链路穿透到实现体 | — | **52**（唯一未穿透：`CommonController.defaultKaptcha`，
调的是第三方 Kaptcha bean，本就没有实现类） |

改前那 11 条 XML 里有一部分是**贴错的**：`login` 在仓库里有 4 处同名定义
（`AdminUserMapper.xml` / `AdminUserServiceImpl` / `NewBeeMallUserServiceImpl` /
`AdminController` 自己），实现体索引按名字取第一个，于是把 Mapper 的 SQL
贴到了 Controller 的登录调用上 —— 证据看起来"有 SQL"，但那不是这条链路的 SQL。

---

## 二、三处真实断链（都是机制层面，不是样本特例）

### 1. 嵌套实参吃掉了内层调用的接收者

旧正则：

```python
r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(([^()]{0,120})"
```

`[^()]` 遇到内层 `(` 就停，但 `finditer` 从**停止处**继续扫：

```java
request.setAttribute("pageResult", newBeeMallGoodsService.searchNewBeeMallGoods(pageUtil));
// └─ 匹配 setAttribute，实参一路吃到 "...searchNewBeeMallGoods" 的 '('
//    下一轮从 '(' 开始扫 → `newBeeMallGoodsService.` 再也不会被匹配
```

真实业务里几乎所有 service 调用都嵌在 `return Result.success(...)` /
`request.setAttribute(...)` 里。实测 **8 个入口、8 个 service 调用点丢失**，
而这 8 个恰好是：`searchPage`（商品搜索）、`orderListPage`（我的订单），
以及 6 个后台分页列表（轮播/分类/商品/首页配置/订单/用户）——
**全是分页查询，最可能出 SQLi 的那批**。

修法：正则只匹配调用头，实参用 `_call_args()` 配平取（能穿过嵌套调用与
字符串里的括号）。

### 2. 第 2 跳的预算被零参读写器吃光

`searchPage` 的第 2 跳原本是：

```
getCategoryId / getCategoryLevel / getCategoryName / getLevel   ← 4 个名额全在这
```

方法体只有 `return 字段;`。真正含 SQL 的 `findNewBeeMallGoodsListBySearch`
一个名额都没有。加 `_TRIVIAL_ACCESSOR_RE`：只匹配**两端都是裸标识符**的
`return x;` / `this.x = y;`，`return "bob";`（常量来源证据，OWASP `getTheValue`
那类跨方法常量回溯靠它）不受影响。

### 3. Mapper 语句只有声明，`_method_index` 天生看不见

`_method_index()` 只收有方法体的 Java 方法。修完 1、2 之后，`searchPage` 的切片
到了 `ServiceImpl.searchNewBeeMallGoods`，但下一跳的
`goodsMapper.findNewBeeMallGoodsListBySearch(pageUtil)` 仍然断在这里。

三件事要同时做，缺一条都还是断：

1. **每跳也查 `impl_resolver`** 的 `mybatis_xml / mybatis_anno`，不再只查方法体索引；
2. **重名不猜，但按接收者消歧**：`selectByPrimaryKey` / `insert` 这类通用 CRUD
   名在 9 个 Mapper 里重名，只有「接收者后缀唯一匹配 XML 文件名」时才注入
   （`goodsMapper` ↔ `NewBeeMallGoodsMapper.xml`）；
3. **判据要读得到**：`_impl_segment` 从「跨文件证据：以下为实现体」起截，
   而 Hop XML 段的段头是 `// 来自 XxxMapper.xml [Hop 2] —— mybatis_xml`，
   在它**前面**。切片里有 `#{}`、判据读不到 → 70/70 全退回模型。
   新增 `_mybatis_text()` 把两类段合并。

做完后 `searchPage` 的切片：

```
[Hop 1] NewBeeMallGoodsServiceImpl.searchNewBeeMallGoods
[Hop 1] NewBeeMallCategoryServiceImpl.getCategoriesForSearch
[Hop 2] NewBeeMallGoodsMapper.xml —— mybatis_xml   (findNewBeeMallGoodsListBySearch)
[Hop 2] NewBeeMallGoodsMapper.xml —— mybatis_xml   (getTotalNewBeeMallGoodsBySearch)
```

sqli 判据结果：**13 条判安全（全部 `#{}` 参数化），0 条判漏洞**。

---

## 三、authz：真实业务上 6 条误报，0 条漏报

`authz_verdict` 原本只认 `request.getSession().getAttribute(...)`。
真实 Spring MVC 项目的写法是**把 `HttpSession` 当方法形参注入**：

```java
NewBeeMallUserVO user = (NewBeeMallUserVO) httpSession.getAttribute(Constants.MALL_USER_SESSION_KEY);
```

于是**所有主体获取都看不见**，6 条安全路由被判越权。补了四条判据，
全部挂在可逐行核对的事实上：

| 判据 | 事实 | 效果 |
|---|---|---|
| 会话主体 | `\w*Session.getAttribute(` / `@SessionAttribute` | 认出主体 |
| 主体作资源键 | `svc.get(orderNo, user.getUserId())` / `setUserId(user.getUserId())` | 判安全（校验下沉到 SQL 的 `where user_id=?`） |
| 认证入口 | `@PostMapping("/login")` 等 | 不做授权判定 → None |
| 前缀级拦截器 | `addPathPatterns("/admin/**")` | 全局鉴权覆盖 → None |

最终分布（30 条判定）：**11 False / 1 True / 18 None，0 条误报**。

逐条核对过的 False：`orderDetailPage`、`cancelOrder`、`finishOrder`、`payOrder`、
`saveOrder`、`selectPayType`、`cartListPage`、`settlePage`、购物车增改 ——
它们把 `user.getUserId()` 传进 Service，由 Service 比对
（`getOrderDetailByOrderNo` 里 `if (!userId.equals(order.getUserId())) fail(...)`），
或先 `setUserId(session 里的 userId)` 再落库。

### 唯一的 True 是真漏洞

```java
@GetMapping("/paySuccess")
@ResponseBody
public Result paySuccess(@RequestParam("orderNo") String orderNo,
                         @RequestParam("payType") int payType) {
    String payResult = newBeeMallOrderService.paySuccess(orderNo, payType);
    ...
}
```

- 方法内**没有取主体**，`orderNo` 原样进 Service；
- Service 的 `paySuccess` 只查订单状态，**不比 userId**；
- 更关键：`/paySuccess` **不在登录拦截器的 `addPathPatterns` 里**
  （配置只覆盖 `/goods/detail/**`、`/shop-cart/**`、`/orders/**`、`/personal/**`、
  `/selectPayType`、`/payPage`、`/saveOrder`）。

即：未登录即可把任意订单置为"已支付"。这是本次盲测挖到的第一条真实越权。

---

## 四、被事实推翻的两个假设

1. **`<include refid>` 里藏 `${}`** —— 不成立。9 个 Mapper 文件里 `${}` 出现
   **0 次**，`<sql id>` 片段全是列名清单（`Base_Column_List`）。
   展开 `<include>` 对注入判定没有价值，**不写**（与 FastJson 版本判据同一条纪律）。
2. **"70 个入口 ServiceImpl 命中 0"** —— 有一半是探针自己的 bug。
   切片里没有字段声明（`_entry_only` 只留方法体），探针拿不到
   `newBeeMallGoodsService` 的类型，于是把"探针查不到"读成了"切片没进来"。
   修正探针后重测，才拿到真实的 8 个受影响入口。**探针写错和切片写错症状一样。**

---

## 五、发现了但**没修**的（都有量化事实）

| 问题 | 事实 | 为什么不修 |
|---|---|---|
| 跨路由串接证据噪声 | 70 入口共 12442 行，串接段 **3206 行 = 26%**；只读的 `searchPage` 被标成"写入 → 后台删除路由读出"（`db` 介质按"接触过同一 Service"对称配对） | 要动 stored-XSS 判据（写入侧必须真调 write 动词），属独立一轮 |
| 类级 `@RequestMapping("/admin")` 不在切片里 | 后台路由只能靠 `/admin/**` 拦截器证据间接判 None | 需要把类级映射纳入切片段，会影响路由归一化 |
| 通用 CRUD 名消歧 | `selectByPrimaryKey` 在 9 个 Mapper 里重名，仅当接收者后缀唯一匹配才注入 | 已按"唯一才注入"保守处理，更激进的模糊匹配就是猜 |
| 接口多实现消歧 | newbee-mall 的 Service 接口全是唯一实现 | 仍然没有真实样本 |

---

## 六、回归（五靶场）

| 靶场 | 结果 | 与改前 |
|---|---|---|
| OWASP Benchmark（全量 2740，**重建缓存**） | A 方向 0 / B 方向 0，确定性判定 1352 条 | 逐类目完全一致 |
| java-sec-code | Score 1.000（31 TP / 0 FN / 0 FP） | 一致 |
| Hello-Java-Sec | 59 覆盖 / 58 判对 | 一致 |
| JavaSecLab | 42 覆盖 / 41 判对 / safe 13 全对 | 一致 |
| micro_service_seclab | 19/20 覆盖 / 19 判对（safe 4/4） | 一致 |

冒烟：`smoke_test_chains.py` 新增 11 条断言（含 5 条方向护栏），
`week1` / `week2` 全过。

**缓存指纹**：本轮踩到一个陷阱 —— OWASP 切片缓存只看文件存在与否，改了 slicer
仍命中旧切片，回归 3 秒"通过"但跑的是改动前的代码。已在
`diag_owasp_sqli_fp.load_units` 加 `_slicer_fingerprint()`
（slicer/resolver/taint_chain 的 mtime+size），缓存自动失效。

---

## 七、下一步建议

1. **把 newbee-mall 做成第 5 个跑分脚本**的前提是有逐路由真值 —— 现在只有
   `paySuccess` 一条能确证。可行路径：只对 `authz` 与 `sqli` 两类，
   按"人工核对过的 30 条 authz 判定"建真值表（本轮已逐条核完，可直接落表）。
2. **串接证据噪声**（26%）是下一个对真实项目影响最大的问题，但它会动
   stored-XSS 判据，必须单独一轮 + 全量回归。
3. **`<include refid>` 与接口多实现**仍然等真实样本，不为想象中的敌人造武器。

---

## 附：本轮改动的文件

- `core/slicer/java_servlet.py`：`DATA_CALL_RE` + `_call_args` / `_iter_data_calls`、
  `_TRIVIAL_ACCESSOR_RE`、`_pick_impl`（接收者消歧）、每跳 Mapper XML 桥接
- `core/agents/rule_detectors.py`：`_mybatis_text`、`authz_verdict` 四条新判据
- `benchmarks/diag_owasp_sqli_fp.py`：缓存指纹
- `benchmarks/smoke_test_chains.py`：11 条新断言
- `benchmarks/_probe_newbee.py`：零改动探针（新）
