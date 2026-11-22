# STAGE REPORT · v1.5.30（M467–M470：候选仓口径 / 4 条 A 板假阳清零 / YAML 注释与 dev overlay 凭据）

> 日期：2026-11-22 ｜ 基线：v1.5.29（`514294c`，巡猎产物 `8b547ff`）
> 主题：统一「候选仓 / 已处理」的报告与 JSON 口径并显式记账缺 slug 候选；
> 清零 11-22 的 4 条 A 板假阳（dax-pay `redir` ×3 + novanova-studio
> `pathtraver` ×1）；收口 v1.5.29 遗留的 YAML `#` 注释 `hardcoded_secret`
> 误报与本地 dev overlay 凭据降噪；新增门禁 `[353]`。
> 结论：smoke **1,842** 项断言 PASS / triage **16/16** / doctor PASS；
> 4 条 A 板假阳逐条重放全部归零（3 条规则层不再产根因 + 1 条归 B）；
> 两仓离线复扫 **A=0 / B=237**。

## 〇、背景（11-22 09:20 巡猎）

- 候选 **18** / 实扫 6 / 跳过 8 / 失败 0；新增根因 448（A **4** / B 444）；
  证据不足未列 1 条。
- **报告头与 JSON 口径撕裂**：`LIVE_HUNT_REPORT.md` 写「候选仓：14」，
  `daily_hunt.json` 的 `daily.candidates` 写 **18** —— 差额 4 条是缺 slug 的
  候选被 `continue` 静默丢弃（CLI 日志「候选 18 ｜ 实扫 6 ｜ 跳过 8 ｜
  失败 0」三个分项只加得出 14）。这正是 M467 要统一的口径。
- A 板 4 条全部是假阳：

| # | 仓库 | 类目 | 根因 | HEAD |
|---|---|---|---|---|
| 1 | dax-pay | redir | `EasyPayApiV1Controller.submit` | `466517a1b7cb`（2026-11-16） |
| 2 | dax-pay | redir | `EasyPayApiV2Controller.submit` | 同上 |
| 3 | dax-pay | redir | `OpenAuthController.getOpenId` | 同上 |
| 4 | novanova-studio | pathtraver | `StorageBillingController.listFiles` | `eb7c8e92abbe`（2026-11-21） |

## 一、M467：统一「候选仓」报告 / JSON / CLI 口径（`core/context/daily_hunt.py`）

### 1. 缺 slug 的候选不再静默丢弃

```python
slug = str(item.get("slug") or "").strip()
if not slug:
    ledger.append({"slug": "(missing_slug)", "result": "SKIPPED",
                   "reason": "missing_slug"})
    continue
```

旧实现直接 `continue`：侦察返回 18 个候选、账本只有 14 行，报告头写 14、
JSON 写 18。现在缺 slug 也占一行 SKIPPED，`len(items)` 与 `len(ledger)`
的差额只剩「`--limit` 截断后未进入循环的候选」这一种可解释来源。

### 2. `daily_meta` 两个字段分口径

```python
"candidates": len(items),     # 侦察返回候选总数
"processed": len(ledger),     # 真正进入账本（实扫 / 跳过 / 失败）
```

### 3. 报告头：两数相等保持旧写法，不等时同时亮出

```python
if candidates and candidates != len(ledger):
    _cand = f"候选仓：{candidates}（已处理 {len(ledger)}）"
else:
    _cand = f"候选仓：{len(ledger)}"
```

- 相等 → `候选仓：{len(ledger)}`，兼容既有报告断言；
- 不等 → `候选仓：{candidates}（已处理 {len(ledger)}）｜ 实扫：...`。
- CLI 汇总行同步改为 `候选 18（已处理 14）｜ 实扫 6 ｜ 跳过 8 ｜ 失败 0`，
  避免下次再从日志里读出 18 与 14 两个互相矛盾的数字。

## 二、M468：清零 11-22 的 4 条 A 板假阳

### 1. `dax-pay` `EasyPayApiV1/V2Controller.submit`（`redir` ×2）

`core/agents/rule_detectors.py` 新增 `_redir_redirect_targets()` 与
`_redir_config_url_assembled()`，在 `redir_verdict()` 的
`_redir_repo_sourced()` 之后判「跳转目标由服务端配置服务拼装」：

真实切片（`EasyPayPayV1/V2Service.submit` 跨文件证据段）：

```java
String gateway = platformUrlConfigService.getUrlConfig().getPaymentGatewayBaseUrl();
var order = newOrder(..., param.getReturnUrl(), ...);   // returnUrl 只落库
order.setPayUrl(gateway + "/easypay/v1/pay/" + order.getId())
        .setPcCallType(PayBodyTypeEnum.QR_CODE.getCode());
easyPayOrderManager.save(order);
return order.getPayUrl();
```

四条判据同时成立才返 False（缺一即退回原判）：

1. 入口跳转目标是内部服务调用（`easyPayPayV1Service.submit(param)`）或
   配置/URL getter，不是把请求参数直接塞进 RedirectView；
2. 切片证据面存在「配置读取 → URL 变量」赋值（`_CONFIG_GET_RE`
   命中 `*ConfigService*.get*Url*()` 且右式带 url/gateway/base 语义）；
3. 该配置变量参与**拼接**的 URL 属性 setter（`set\w*Url(cfg + ...)`）；
4. 证据里读得回同一属性的 getter（`return order.getPayUrl()`）。

`order.setReturnUrl(param.getReturnUrl())` 这类"只落库"字段不参与本次跳转：
它没有拼接、也不是配置变量派生，因此不会把本判据拐到 True。

### 2. `dax-pay` `OpenAuthController.getOpenId`（`SIGNED_OAUTH_RELAY`）

`core/context/wild_noise.py` 新增 `SIGNED_OAUTH_RELAY`，在 `classify()`
的 `redir` 分支最前面判「签名认证后的 OAuth 中转」：

- 入口门：unit 的类名/方法名命中 `OpenAuth` / `OAuth` / `getOpenId`
  （`_OAUTH_ENTRY_RE`，路径目录名不算）；
- 验签门三选一：
  1. 入口方法体直接有 `verifySign` / `checkSign` / `validateSign` / `SignUtil`
     / `signVerify` 等商户验签调用；
  2. 入口类内（`_class_span()` 覆盖范围）有验签；
  3. 跳转目标调用的 Hop 服务方法里有验签 —— dax-pay 正是这一条：
     `openAuthService.generateOpenAuthRedirect(param)` →
     `OpenAuthService.generateOpenAuthRedirect()` →
     `paymentSignService.signVerify(param)`。

Hop 定位不做全仓无脑扫描：先按「字段声明类型 / 接收者首字母大写」定位
`OpenAuthService.java`（3000+ 个 .java 的仓在 400 文件处截断会正好错过
`daxpay-payment` 模块），找不到才退回 400 文件有界扫描；结果按
`(repo, 接收者:方法)` 记忆化。

→ `classify()` 返回 `SIGNED_OAUTH_RELAY`，记录以 UNKNOWN 压进 B 板。

### 3. `novanova-studio` `StorageBillingController.listFiles`（`pathtraver` ×1）

根因定位：**通用 `listFiles` 命名**。`PATHTRAVER` 的 sink 正则里原来写的是
裸 `\.\s*listFiles\s*\(`（`re.I`），于是纯 DB/R2DBC 分页查询

```java
@GetMapping("/listFiles")
public Mono<ApiResponse<JSONObject>> listFiles(@Valid @ModelAttribute StorageBillingRequest request) {
    return fileService.listFiles(request).map(ApiResponse::ok);
}
```

命中 sink 后，`_FILE_API_NAME_RE` 又被 `StorageFileDtos` / `listFiles` 带偏，
最终判 True。修复：

- 把 `\.\s*listFiles\s*\(` 从 `PATH_SINK_RE` 移除；
- 新增 `_listfiles_sink_hit()`：只认接收者确实是 `java.io.File` 的三种形态 ——
  `new File(...).listFiles()`、本切片里声明为 `File` / `File[]` 的变量、
  名字里带 file 的 getter 调用（`getUploadFile().listFiles()`）；
- 新增 `_path_sink_matches()` / `_path_sink_search()`，替换 `pathtraver_verdict`
  里全部 5 处 `PATH_SINK_RE` 调用点（相关性命中、sink 标识符、sink 集合、
  入口体/证据段两处 search）。

`fileService.listFiles(request)` 现在不是文件 sink → 整份切片无文件 API →
判 False（纯 DB 分页查询返回 None/False 均可，实测 False）。

## 三、M469：收口 v1.5.29 遗留（YAML `#` 注释 / dev overlay 凭据）

### 1. YAML 纯注释行不再当成硬编码凭据

`hardcoded_secret_verdict(source, filename="")`：后缀 `.yml` / `.yaml`
时先跑 `_strip_yaml_comment_lines()`，删掉以 `#` 开头的**纯注释行**再判。
`verdict(category, source, *, filename="")` 新增透传参数，
`cli._scan_secret_files()` 调用时传文件路径。

真实文件验证（akb `docker-compose.keycloak.yaml`，v1.5.29 白盒对象）：

| 输入 | 判定 |
|---|---|
| 原样全文 | `True`（旧行为：注释里的示例键值被当成赋值） |
| 传 filename 后 | `None`（注释剥离，不再产生根因） |

非注释行里的真实密钥仍判 True（`[353]` 防放宽断言）。

### 2. 本地 dev overlay compose 凭据归 `DEV_OVERLAY_SECRET`

`wild_noise.classify()` 顶层新增 `hardcoded_secret` 专属分支：

- 文件名命中 `docker-compose*.yaml` / `compose*.yml`（`_COMPOSE_NAME_RE`）；
- 文件**头部前 40 行**显式标注 `OPTIONAL local ... overlay` /
  `NOT part of the default stack` / `for developing/testing` /
  `local (development) overlay`（`_DEV_OVERLAY_MARKER_RE`）；
- 命中则返回 `{"blocked": True, "code": DEV_OVERLAY_SECRET}` 压 B。

M463 让 `hardcoded_secret` 不再继承 `LOCAL_LOOPBACK_ONLY` 之后，这类文件会
直接进 A 板；它需要的是"这是开发叠加"的专属归因，而不是回环继承。生产
compose（无头部标注）不受影响（`[353]` 防放宽断言）。

## 四、M470：门禁 `[353]` + 离线复扫 + 全套验证

### 1. `benchmarks/smoke_test_chains.py` 新增 `[353]`（17 项，纯离线）

| 断言 | 结果 |
|---|---|
| M467：缺 slug 候选入账为 `(missing_slug) SKIPPED` | ✅ |
| M467：`candidates=3 / processed=2` 分口径 | ✅ |
| M467：报告头 `候选仓：3（已处理 2）` | ✅ |
| M467：JSON 与报告头同源 | ✅ |
| M467：两数相等时保持 `候选仓：1 ｜`（兼容旧断言） | ✅ |
| M467：相等时 `processed == candidates` | ✅ |
| M468：配置服务拼装支付网关 → `redir_verdict` False | ✅ |
| M468：同证据下目标换成请求参数仍 True（防放宽） | ✅ |
| M468：request 参数直通 RedirectView 仍 True（防放宽） | ✅ |
| M468：带商户验签的 OAuth 中转 → `SIGNED_OAUTH_RELAY` | ✅ |
| M468：无验签的 OAuth 跳转不误压（防放宽） | ✅ |
| M468：纯 R2DBC 分页 `listFiles` 不判路径穿越 | ✅ |
| M468：`File.listFiles` 真实遍历仍 True（防放宽） | ✅ |
| M469：YAML 注释行示例凭据不判 `hardcoded_secret` | ✅ |
| M469：YAML 非注释行真实密钥仍 True（防放宽） | ✅ |
| M469：dev overlay compose 归 `DEV_OVERLAY_SECRET` | ✅ |
| M469：生产 compose 不归 `DEV_OVERLAY_SECRET`（防放宽） | ✅ |

### 2. 离线复扫：4 条 A 板假阳逐条重放（真实切片，HEAD 旧规则 vs 当前规则）

用 `git show HEAD:core/agents/rule_detectors.py` 载入旧规则，在同一份
`.cache/upstream/` 真实切片上对比：

| 记录 | 旧 | 新 | 新行为 |
|---|---|---|---|
| dax-pay `EasyPayApiV1Controller.submit` | True | **False** | 根因层不再产出 |
| dax-pay `EasyPayApiV2Controller.submit` | True | **False** | 根因层不再产出 |
| dax-pay `OpenAuthController.getOpenId` | True | True | `classify` → `SIGNED_OAUTH_RELAY` 压 B |
| novanova `StorageBillingController.listFiles` | True | **False** | 根因层不再产出 |

→ **A 板 4 → 0**。

### 3. 两仓离线复扫（`daily_hunt.run(offline=True, dedup_online=False)`，空 state）

```text
summary: {"total": 237, "board_a": 0, "board_b": 237}
daily  : {"candidates": 2, "processed": 2, "scanned": 2, "skipped": 0,
          "failed": 0, "new_roots": 237, "board_a": 0, "blocked": 237}
dax-pay        : 1 根因（OpenAuthController.getOpenId → B）
novanova-studio: 236 根因（全部 authz，本地降噪压 B）
pathtraver 根因 : 0
```

| 目标记录 | 复扫结果 |
|---|---|
| dax-pay `EasyPayApiV1Controller.submit` | **GONE** |
| dax-pay `EasyPayApiV2Controller.submit` | **GONE** |
| dax-pay `OpenAuthController.getOpenId` | 仍在根因集，但被 `SIGNED_OAUTH_RELAY` 压 B（A=0） |
| novanova `StorageBillingController.listFiles` | **GONE** |

> 离线模式 `dedup_online=False` 不可能给出 `ZERO_RECORD_FRESH`（与 v1.5.29
> 同口径），所以 A=0 不能单独证明清零；"4 → 0" 由上面的**逐条规则重放**
> 与根因层消失共同证明。作为最严口径的补充：给所有根因注入 FRESH 查重桩
> 后再跑，A 板只剩 1 条 `OpenAuthController.callback` —— 它不是 11-22 的
> 4 条，而是实跑里查重未给 FRESH（当日 `incomplete_dedup=1`）的存量候选；
> 白盒结论为"会话态 `redirect_url`（`AuthSessionStore` 取出）+ 平台私钥
> 签名参数"，本轮未扩大改动面（见"说明与遗留"）。

### 4. 全部门禁

| 门禁 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,842 项断言**（v1.5.29 为 1,825，+17 即 `[353]`） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 地板全绿** |
| `python cli.py doctor` | **PASS（12 段全绿）** |
| `benchmark_javaseccode.py --offline` | OVERALL 54，规则判定 54，**TPR 1.00 / FPR 0.00**（与改动前逐类目一致） |
| `benchmark_hellojavasec.py --offline` | 66 样本 / 规则直接结论 59（89.4%）/ **正确 58/58 = 100%**，1 条已知争议单列（与改动前一致） |

## 五、说明与遗留

- **`OpenAuthController.callback`（最严口径下的存量候选）**：跳转目标
  `redirectUrl = session.getReturnPath()` 来自服务端 session（`state` 即
  authToken），且回调参数用平台私钥签名；不是开放重定向。11-22 实跑里
  该根因未获 FRESH（当日 `incomplete_dedup=1`），未进 A 板；本轮未新增
  判据覆盖它，留作下一轮 `redir` 降噪的候选对象。
- **`DEV_OVERLAY_SECRET` 只覆盖 compose 文件**：`deploy/keycloak-dev/.../
  exercise.py` 这类 dev 脚本凭据仍走 Python 路径（v1.5.29 白盒结论也是
  测试夹具），没有扩大改动面。
- **`--check-floor` 读历史 `results/*.json`**：本轮未重跑全部靶场；
  "不退化"的额外证据是 javaseccode / Hello-Java-Sec 两个 redir+pathtraver
  密集靶场已重跑且与改动前逐类目一致，以及 `[353]` 里 4 组防放宽对照。
- **`PATHTRAVER` 规则改动面**：只影响 `.listFiles(` 一种 sink 形态，
  `new File(...)` / `Files.*` / `FileUtils.*` 等其余 sink 零改动。

## 六、提交清单

- `core/context/daily_hunt.py` — M467 候选仓 / 已处理口径 + 缺 slug 记账
- `core/agents/rule_detectors.py` — M468 redir 配置服务拼装 + M468 `.listFiles`
  接收者归属 + M469 YAML 注释剥离
- `core/context/wild_noise.py` — M468 `SIGNED_OAUTH_RELAY` + M469
  `DEV_OVERLAY_SECRET`
- `cli.py` — M467 CLI 汇总口径 / M469 文件级密钥扫描传 filename
- `benchmarks/smoke_test_chains.py` — M470 `[353]` 17 项
- `STAGE_REPORT_2026-11-22_v1.5.30.md` — 本报告

> 验证用 `.cache/upstream/` 为巡猎即时缓存（`.gitignore` 已排除），
> 不进入提交。
