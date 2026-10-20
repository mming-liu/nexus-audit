# 阶段报告 · 2026-10-20（第二轮）

承接 `3d892d6`（newbee-mall 零改动盲测）。本轮做的是**收口**：把盲测暴露的三处
结构问题按"先补事实、再压噪声、最后固化"的顺序落掉，并把 newbee-mall 变成第 5 个
回归基线。

---

## 一、三件事与结果

| # | 事项 | 关键改动 | 实测效果 |
|---|---|---|---|
| 1 | 补类级路由前缀 | `CodeUnit.route_path` + 切片首行 `// Full-Route:` + `excludePathPatterns` | `/admin/login` 不再被判成"受 `/admin/**` 保护" |
| 2 | 收紧 DB 串接方向 | `_db_direction`：只连 写内容 → 读内容 | newbee-mall 422 → **60** 条，串接段 26% → **6%** |
| 3 | 固化第 5 靶场 | `benchmarks/benchmark_newbeemall.py` | 切片基线 + 12 条 authz 真值 + sqli 方向护栏 |

附带修掉一处跨项目误报（`ImageIO.read` / `.getInputStream()` 被判 SSRF），
并发现一处**静默丢入口**（同名重载，全仓 5 条）。

---

## 二、类级路由：为什么它不只是"显示用"

后台路由的鉴权写在拦截器里：

```java
registry.addInterceptor(adminLoginInterceptor)
        .addPathPatterns("/admin/**")
        .excludePathPatterns("/admin/login")
        .excludePathPatterns("/admin/dist/**")
        .excludePathPatterns("/admin/plugins/**");
```

两处缺陷，方向相反，都出在"拿什么去比"：

1. **没有类级前缀**：方法级注解只给 `/goods/list`，拿它去比 `/admin/**` 永远不匹配。
   以前只有 `route_path` 局部变量（够查装配索引），现在它是 `CodeUnit` 的字段，
   并写成切片首行 `// Full-Route: /admin/goods/list`，判定层和模型都读得到。
2. **`excludePathPatterns` 从未参与判断**：`/admin/login` 明明被排除，
   切片却写着"受 `/admin/**` 拦截器保护" —— 一条**无保护**的后台路由
   被当成"受保护"而退回 `None`。`Wiring` 现在记 `exclude_patterns`，
   `for_url` 先匹配再加减法。

判定层的 `_AUTHZ_GLOBAL_GUARD_RE` 因此自动生效：被排除的路由**拿不到**
`addPathPatterns("/admin/**")` 这行证据，也就不会被误判成"全局鉴权覆盖"。

一个细节：类级注解取**紧邻 class 声明的那一个**，不是文件里第一个。
一个 `.java` 里两个类时（内部类 / 同文件 DTO），取第一个会把前一个类的
`/admin` 扣到后一个类头上，前台路由被算成后台路由 —— 比没有前缀更危险。

---

## 三、DB 串接方向：422 → 60

旧实现对 db 是**对称配对**：同一仓储字段被两个不同路由调用，就连一条，
谁写谁读交给判定层。在 4 个路由的靶场里成立，在 70 个入口的真实电商项目里：

```
数据库持久层 "adminUserService"：AdminController.login 写入 → AdminController.profile 读出
数据库持久层 "newBeeMallGoodsService"：GoodsController.searchPage 写入 → ...CarouselController.delete 读出
```

`login` 不写、`searchPage` 只读、`delete` 也不写内容。**方向是错的**，
而串接证据只贴在"写入方"上 —— 于是每条反向连接都变成一份凭空多出来的
存储型漏洞候选，同时把切片撑大三倍。

方向其实是可逐行核对的事实，只问一句话：**这一侧往库里塞内容，还是从库里取内容**。

| 方法名 | 判定 | 依据 |
|---|---|---|
| `saveNewBeeMallGoods` / `insertOne` / `add` / `safeSave` / `batchUpdateSellStatus` | `w` | 写入内容 |
| `getXssList` / `list` / `page` / `searchNewBeeMallGoods` / `getSavedList` | `r` | 读出内容 |
| `deleteById` / `deleteBatch` / `cancelOrder` / `login` / `paySuccess` | `None` | 状态变更，既非写内容也非读内容 |

先判读前缀再判写：`getSavedList` 是"读一个叫 save 的东西"，顺序反了会被当成写入方。

| 仓库 | 改前 db 连接 | 改后 | 串接段占切片 |
|---|---|---|---|
| newbee-mall | 422 | **60** | 26% → **6%**（3206 → 616 行） |
| Hello-Java-Sec | 152 | **6** | — |
| java-sec-code | 44 | **0** | 全是 `selectUserByUsername` 被当成写入方 |
| JavaSecLab | 10 | **1** | 留下的正是 `StoreController.vul → getXssList` |

---

## 四、顺带修掉的跨项目误报：弱 sink 必须带旁证

`ImageIO.read(...)` 和 `.getInputStream()` 曾直接写在 `SSRF_SINK_RE` 里
（为 java-sec-code 的 `URL u = new URL(url); ImageIO.read(u);` 加的）。
后果：**任何文件上传接口都被判 SSRF** —— newbee-mall 的
`/admin/upload/file`、`/admin/upload/files` 两条纯本地图片上传判 `True`。

靶场永远测不出来，因为靶场里没人写上传。

修法不是删 sink，而是要求弱 sink 带 URL 旁证（方法体内出现过
`new URL(` / `openConnection()` / `URL x =`）。这与 `encodeBase64` 不是输出编码
是同一条原则：**方法名相同不代表机制相同，要看接收者和实参。**

---

## 五、第 5 靶场：newbee-mall

`benchmarks/benchmark_newbeemall.py`。**它不出 Score** —— 这个仓库没有逐路由
漏洞真值，硬造一个分数只会制造虚假安全感。它锁三件确定的事：

### ① 切片穿透基线（数字掉了就是切片器退化）

| 指标 | 值 |
|---|---|
| 入口数 | 70 |
| 含 Service 调用的入口 | 53 |
| 其中真的带进跨文件实现体 | 52 |
| 含跨文件实现体（任一形式） | 56 |
| 含 Mapper XML SQL | 36 |

### ② authz 真值表：12 条，逐条人工核对

真值不来自任何漏洞报告，来自三条代码事实：**主体从哪取**、**主体值是否参与
资源定位**、**是否显式比对归属并终止请求**。

| 路由 | 真值 | 依据 |
|---|---|---|
| `/orders/{orderNo}` | safe | `getOrderDetailByOrderNo(orderNo, user.getUserId())` |
| `/orders/{orderNo}/cancel` · `/finish` | safe | 同上 |
| `/orders` | safe | `params.put("userId", user.getUserId())` |
| `/selectPayType` · `/payPage` | safe | 显式比对 + `NewBeeMallException.fail` |
| `/shop-cart`（GET/POST/PUT） | safe | 主体值作查询条件 / `setUserId(...)` |
| `/shop-cart/settle` | safe | 主体值作查询条件 |
| **`/paySuccess`** | **vul** | 不取主体、不比对归属，`orderNo` 直接进 Service |

规则：**11/12 覆盖，11/11 正确，FP 0，FN 0**。唯一退回的是 `/orders`
（`params.put("userId", ...)` 不在判据里，属未覆盖，不是判错）。

### ③ sqli 方向护栏

9 个 Mapper XML 里 `${}` 出现 **0 次** ⇒ 没有任何一条路由存在 SQL 注入面
⇒ 任何一条 `sqli=True` 都是误报。当前 **0 条**，判安全的 13 条。

### 存疑单列（不进分母）

`UploadController.upload` / `uploadV2` 的 pathtraver 判 `True`。写入路径是
**常量目录 + 生成的文件名**，用户可控部分只是 `fileName.substring(lastIndexOf('.'))`。
它能含 `/`，但要逃出基目录需要存在一个名为 `<时间戳><随机数>.` 的中间目录
（`mkdir` 只建常量目录）。静态既证明不了可利用、也证明不了绝对不可利用
→ 单列，不改判据。

---

## 六、新发现：同名重载静默丢入口

`ShoppingCartController` 的 PUT `/shop-cart` 与 DELETE `/shop-cart/{id}`
**同名**（都叫 `updateNewBeeMallShoppingCartItem`），而切片器按方法名建索引，
`setdefault` 只保留第一条 → DELETE 那条入口**消失**，不报错、不留痕。

全仓实测丢 **5 条**：newbee-mall 3 个文件、Hello-Java-Sec 的
`SSTI.java` 与 `MyBatis.java` 各 1 条。

修法是按 `(name, start_line)` 建索引并给 `unit_name` 加后缀 —— 会改变入口分母，
属独立一轮。本轮把它写进 benchmark 的 `KNOWN_MISSING` 常量（不是注释），
修好后断言会失败，逼人回来改掉它。

---

## 七、回归

| 靶场 | 结果 |
|---|---|
| OWASP 全量 2740（重建缓存） | **A=0 / B=0**，1352 条确定性判定逐类目与改前一致 |
| java-sec-code | Score 1.000（TP 31 / FN 0 / FP 0 / TN 34） |
| Hello-Java-Sec | 59 覆盖，58/58 = 100% |
| JavaSecLab | 42 覆盖（66.7%），41/41 = 100%，safe 13/13 |
| micro_service_seclab | 19 覆盖（95%），19/19 = 100%，safe 4/4 |
| newbee-mall（新） | 切片基线全对齐；authz 11/11 正确；sqli 误报 0 |

冒烟新增 `[45]` 路由前缀与拦截器排除（6 条）、`[46]` 串接方向锁（17 条），
其中 4 条是方向护栏；`[26]` 的"双向各 1 条"改成"只连写→读一条"。

另补一处会骗人的地方：OWASP 切片缓存指纹原来漏了 `framework_wiring.py`
和 `models.py` —— 改了装配解析或 `CodeUnit` 字段，回归照样 3 秒"通过"，
跑的却是旧切片。指纹本身也会漏，这是第二次踩。

---

## 八、下一步（按性价比）

1. **修同名重载丢入口**（会改分母，需同步四个靶场的入口数与真值表）。
2. **`/orders` 这类"主体值写进 Map 键"的判据**：现在 `params.put("userId", ...)`
   读不出来，是 authz 唯一未覆盖的一条。
3. **类级 `@RequestMapping` 的数组形式**（`@RequestMapping({"/a","/b"})`）
   目前只取第一个字面量，多前缀控制器会算错路由。
