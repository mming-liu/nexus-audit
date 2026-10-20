# 阶段报告 2026-10-21（a）：`/logout` 路由口径拆分

起点 `74606d4`。七步长线规划最后一个跨靶场遗留项：`/manage-api/v1/logout`
因路由名含 `logout` 被"认证入口"排除而判 None。

---

## 一、先探针，再动手

七个靶场全部含 `logout` 的入口共 **8 条**（改前基线，`authn命中` = 被旧口径排除）：

| 靶场 | 入口 | 路由 | 旧判定 | 形态 |
|---|---|---|---|---|
| java-sec-code | `Login.logoutPage` | `/logout` | None（**被排除**） | Spring Security `SecurityContextLogoutHandler` |
| Hello-Java-Sec | `Login.logout` | `/user/logout` | None | `session.invalidate()`（路径带前缀，旧口径本就没排除） |
| JavaSecLab | `LoginController.logoutSuccess` | `/logout_success` | None | 静态页（`logout` 后跟 `_`，同样没被排除） |
| newbee-mall | `AdminController.logout` | `/admin/logout` | None（**被排除**） | `request.getSession().removeAttribute(...)` |
| newbee-mall | `PersonalController.logout` | `/logout` | None（**被排除**） | `httpSession.removeAttribute(...)` |
| newbee-mall-api | `NewBeeAdminManageUserAPI.logout` | `/manage-api/v1/logout` | None（**被排除**） | `adminUserService.logout(adminUser.getAdminUserId())` |
| newbee-mall-api | `NewBeeMallPersonalAPI.logout` | `/api/v1/user/logout` | **False** ✔ | 同上（`/user/logout` 带前缀，一直走正常链） |

两个关键事实：

1. **旧口径的排除面比看起来窄**：正则要求字面量路径以 `logout` 结尾
   （`"/logout"` 命中、`"/user/logout"` 不命中），所以 8 条里只有 4 条真被排除；
   mall 用户侧那条早就被 2b 正确判了 False。
2. **真正欠的账只有一条**：`/manage-api/v1/logout`。它的方法体与已被正确
   判 False 的 `/api/v1/user/logout` 完全同构，唯一的区别是路径写法。

## 二、改动：把 logout 从"建立身份"里拆出来

`_AUTHZ_AUTHN_ROUTE_RE` 去掉 `logout`（login/register/signin/signup/captcha 保留）。
**没有新增任何判据** —— logout 走的就是正常 authz 链，三种形态各有归属：

| 形态 | 例子 | 判定 | 走哪条 |
|---|---|---|---|
| 主体自己的 token/session 作资源键 | `logout(adminUser.getAdminUserId())` | **False** | 2b（主体值参与资源选择） |
| 外部可控 userId、无主体 | `logout(String userId)` | **True** | 4)（入参直查资源） |
| 只操作请求自身的 session | `session.invalidate()` / `removeAttribute` | **None** | 证据不足（没有任何"资源"可比对） |

设计要点：logout 是**使用/销毁当前身份**，不是**建立身份**——login 的入参
（口令）当资源键是口径错误，logout 的入参（要注销的会话）恰恰就是要审的
资源键。两者不该共用一个排除名单。

配套改动：

* `benchmark_newbeemallapi.py`：`NewBeeAdminManageUserAPI.logout` 登记进
  `AUTHZ_TRUTH`（False, subject-key）→ 真值 28 → **29**；
* `smoke_test_chains.py` 新增 **[54] 4 条断言**：主体 token 键 → False、
  外部 userId → True、只 invalidate → None、**login 仍被排除**（防放宽护栏）。

## 三、回归（零回归）

| 靶场 | 结果 | 与改前比 |
|---|---|---|
| OWASP 2740 规则层 | **A = 0 / B = 0**，1352 条确定性判定逐类目一致 | 不变 |
| java-sec-code | Score **1.000** | 不变 |
| Hello-Java-Sec | 规则 **59/59**（covered 60） | 不变 |
| JavaSecLab | 覆盖 42、**41/41**（accuracy 1.0） | 不变 |
| micro_service_seclab | **20/20** | 不变 |
| newbee-mall | 73 入口、authz **13/13**、后缀截断 2/2 | 不变 |
| newbee-mall-api | authz 真值 29、判 **24/29**、**24/24 正确**、FPR 0 / FN 0 | decided 23 → **24** |

5 条退回不变（4 公开资源 + `/user/info` 无入参）。jsc / HJS / newbee 的
logout 样本全部维持 None（要么 Spring Security 基建、要么只动自身 session，
无资源归属面可判）——**该退的照退，没有因为"能判了"就硬判**。

冒烟 [54] 4 条 + 原有 24 类全过，`CHAIN SMOKE TEST PASS`。

## 四、方法论沉淀

* **排除名单要按"机制"划，不能按"路由名"划**。login/register 是建立身份，
  logout 是使用身份 —— 一字之差，一个是"资源就是凭据库"（不判），一个是
  "入参就是资源键"（照判）。
* **改全局正则前先量化排除面**。这次先探针发现 8 条里只有 4 条真被排除、
  只有 1 条欠账 —— 改动范围从"波及四个靶场"缩小成"一条真值转正"。
  面积算清楚了，破坏性变更就不破坏了。
