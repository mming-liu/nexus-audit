# STAGE REPORT · v1.5.9（M383–M386：redir 降噪 + 四档优先级 + 重扫）

> 日期：2026-11-14 ｜ 基线：v1.5.8（d19977d）
> 结论：paicoding 的 5 条 `redir` 全部不再占 A 板（3 条规则层判 False、
> 2 条降噪进 B）；`root_priority` 四档修复后，重扫捞出被挤掉的
> `xss` 候选 1 条 —— 精核为 **假阳**（text/plain 回显）。

## 一、M383：redir 三类野仓降噪

`wild_noise.classify()` 新增（按 **Java 方法体作用域**解析，避免同文件兄弟方法连坐）：

| 噪声码 | 判据 | paicoding 命中 |
|---|---|---|
| `SERVER_BUILT_REDIRECT` | `sendRedirect(<helper>)`，helper 名匹配 `build*Url / *LoginUrl / *Oauth*Url / *Sso*Url / getRedirectUrl`，且实参非自由文本（无 `getParameter/getHeader/getQueryString`、无 `String` 形参） | `redirectToZsxq` / `transferByZsxq` / `autoBindZsxqUser` |
| `REFERER_OPEN_REDIRECT` | 跳转目标（含变量回溯）取自 `getHeader("Referer")` | `logOut` |
| `SHORTLINK_BY_DESIGN` | 类/方法名含 `ShortLink` / `getOriginalLink` | `getOriginalLink` |

`rule_detectors.redir_verdict()` 增加**形参类型底线**：全部形参都是
Boolean/数值/响应对象、且方法体不读 `request.getParameter/getHeader/getQueryString`
→ `False`（`autoBindZsxqUser(Boolean, HttpServletResponse)` 由此在规则层消失，
不占 B 板）。

实测：5 条 A → **0**（3 条规则层 False、2 条进 B）。

## 二、M384：root_priority 四档修复

旧实现：近期普通类目 `(-1, 0)` 排在"陈旧但高危的 sqli"`(0, rank)` 之前 ——
paicoding 5 条 redir 吃光 `--max-roots 5`，122 条高危根因被挤掉。

新四档（严格序）：

| 档 | 条件 | 返回值 |
|---|---|---|
| 1 | 近 90 天 + 第一梯队高危（含 HIGH authz） | `(-2, 类目序)` |
| 2 | 非近 90 天 + 第一梯队高危 | `(-1, 类目序)` |
| 3 | 近 90 天 + 普通类目 | `(0, 0)` |
| 4 | 非近 90 天 + 普通类目 | `(1, 0)` |

同步更新 `[291]`/`[310]` 里两条旧断言（HIGH authz 非近期 = -1；近期 xss = 0）。

## 三、M385：门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,645 项**（+7：`[332]`） |
| `triage_fallbacks.py --check-floor` | **16/16** |
| `cli.py doctor` | PASS |
| `.githooks/pre-push` | exit 0 |

`[332]`：三类 redir 降噪各 1 项；Boolean-only 形参 `redir_verdict=False`；
`String url` 仍 `True`；老 sqli `(-1)` < 近期 redir `(0)`；近期高危 `-2`。

## 四、M386：重扫 paicoding + continew-admin

命令：`daily-hunt --repos itwanger/paicoding,continew-org/continew-admin --cooldown-days 0 --max-roots 10 --evict-cache`（独立 state，避免 unchanged 跳过）。

| 项 | 值 |
|---|---|
| 实扫 | 2 仓 |
| 根因 | 135（A=1，B=134） |
| B 板构成 | `UNVERIFIED_WILD_AUTHZ` 132 / `REFERER_OPEN_REDIRECT` 1 / `SHORTLINK_BY_DESIGN` 1 |

### 唯一 A 候选：`WxCallbackRestController.check`（xss，`WxCallbackRestController.java:88`）→ **假阳**

```java
@GetMapping(path = "callback")
public String check(HttpServletRequest request) {
    this.wxCallbackSecurityCheck();
    String echoStr = request.getParameter("echostr");
    if (StringUtils.isNoneEmpty(echoStr)) return echoStr;
    return "";
}
```

1. `@RestController` 返回 `String` → Spring `StringHttpMessageConverter` 默认
   `text/plain;charset=ISO-8859-1`，浏览器不按 HTML 渲染 → 无脚本执行；
2. `wxCallbackSecurityCheck()` 在配置了 `securityCheckToken` 时校验微信签名
   （sha1(token,timestamp,nonce)），未配置时直接放行 —— 即使放行，回显仍是 text/plain。

**建议 M387**：Java `xss_verdict` 对 `@RestController` 的 `String` 返回值按
`text/plain` 处理（除非 `produces = "text/html"` 或 `@ResponseBody` + 显式
content-type），避免"回显即 XSS"的误判。

### 上一轮 6 个候选为何被跳过

`M382` 的 8 个候选里 6 个 `SKIPPED`，原因是 **HEAD 与上次扫描相同**
（2026-11-05 扫过，`last_scanned_sha` 一致），走的是 `skipped_unchanged`，
不是 `low_units`/`cooldown`：

| 仓 | HEAD | 上次扫描 |
|---|---|---|
| dromara/RuoYi-Vue-Plus | 835246ebeb7b | 2026-11-05 |
| dromara/RuoYi-Cloud-Plus | 8bb23fa703bf | 2026-11-05 |
| yulichang/mybatis-plus-join | 07a372a9cd73 | 2026-11-05 |
| techa03/goodsKill | 1187aafc34bb | 2026-11-05 |
| yzcheng90/x-springboot | f4acf07c6b13 | 2026-11-05 |
| 201206030/novel-cloud | c602974ab597 | 2026-11-05 |

## 五、提交

- `90e12c5` — v1.5.9 代码（M383–M385）
- 后续 docs 提交 — 本报告 + 重扫报告
