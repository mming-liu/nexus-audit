# STAGE REPORT · v1.5.10（M387–M390：Webhook 回显降噪 + 未变仓死循环修复）

> 日期：2026-11-14 ｜ 基线：v1.5.9（56ea89a）
> 结论：`paicoding` + `continew-admin` 重扫 **A=0**（135 条全部 B）；
> `skipped_unchanged` 死循环修复后，6 个未变老仓重新进入 7 天冷却，
> 侦察阶段实测 `dropped_unchanged=18`（不克隆、不占名额）。

## 一、M387：Webhook 验签回显降噪

`wild_noise` 新增 `WEBHOOK_CHALLENGE_ECHO`：`xss` 类目下，入口方法体命中

- 类/方法/文件含 `WxCallback` / `WechatCallback` / `Webhook`，或
- 方法体含 `echostr` / `hub.challenge` / `zd_echo`，或
- 方法体调用 `wxCallbackSecurityCheck` / `checkSignature` / `verifySignature`

→ 压 B（"第三方 Webhook 验签挑战串原样回显，非浏览器 HTML 页面"）。

**没有**在 `rule_detectors.xss_verdict` 一刀切排除 `@RestController` 返回 `String`
—— 那会打穿 `[6]`/`[10]` 与 16 靶场地板（浏览器导航 `Accept: text/html` 时
Spring 会协商返回 `text/html`）。

验证：`paicoding` + `continew-admin` 重扫 135 条根因 → **A=0 / B=135**。

## 二、M388：未变老仓无限重克隆

| 步 | 修改 | 效果 |
|---|---|---|
| 1 | `process_repo()` 的 `skipped_unchanged` 分支返回 `{**entry, **base, "last_scanned_at": _now()}` | 确认未变的仓重新进入 7 天冷却 |
| 2 | `scout_daily()` 新增 `scanned_at` 参数；`run()` 传入已扫仓时间表；`pushed_at <= last_scanned_at` 的仓在侦察阶段直接排除 | 不克隆、不占候选名额，并触发 M380 补拉 |

时间戳比较做了归一（`2026-11-05T09:03:45Z` → `2026-11-05 09:03:45`）。

实测证据：

- 第 1 轮巡猎 4 个候选（Snowy / Mako-Public / RuoYi-Vue-Plus / RuoYi-Cloud-Plus）
  全部 `skipped_unchanged`，跑完后 state 里 `last_scanned_at` 刷新为
  `2026-11-14 20:28:24` / `20:28:41`（此前停在 2026-11-05）；
- 直接调用 `scout_daily(scanned_at=真实时间表)`：8 个候选、**`dropped_unchanged=18`**。

## 三、M389：门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,652 项**（+7：`[333]`） |
| `triage_fallbacks.py --check-floor` | **16/16** |
| `cli.py doctor` | PASS |
| `.githooks/pre-push` | exit 0 |

`[333]`：echostr 回显 → `WEBHOOK_CHALLENGE_ECHO`；普通反射 XSS 不误拦；
同 HEAD 跳过并刷新 `last_scanned_at`；刷新后 `last_scan_age_days < 7`；
`pushed_at` 早于/晚于扫描时刻的排除与保留。

## 四、M390：满额巡猎（3 轮实盘）

| 轮次 | 候选 | 实扫 | 跳过 | 失败 | A | 说明 |
|---|---|---|---|---|---|---|
| 1（20:26） | 4 | 0 | 4 | 0 | 0 | 4 个全是 unchanged；刷新时间戳后进冷却 |
| 2（20:31） | 0 | 0 | 0 | 0 | 0 | GitHub 搜索限流（无 Token 10 次/分钟），错误未上报 |
| 3（20:38） | 6 | 1 | 2 | **3** | 0 | `django-crm` 扫出 1 条 authz → B；3 个仓 clone 失败（HEAD 为空） |

第 3 轮明细：

| 仓库 | 结果 |
|---|---|
| `DjangoCRM/django-crm` | SCANNED（1 条 `authz contact_form` → `UNVERIFIED_WILD_AUTHZ` 进 B） |
| `KoalixSwitzerland/koalixcrm` | SKIPPED |
| `Impertio-Studio/Frappe_Claude_Skill_Package` | SKIPPED |
| `avansaber/erpclaw` / `SourByte05/Vulnerability-Wiki-PoC` / `yarsa/nepal-compliance` | FAILED（clone 后 HEAD 为空） |

**结论**：6 个未变老仓不再霸占名额（已进冷却）；但 `--min-stars 300 + 21 天`
的 java/python 新仓供给本身很薄，第 2 轮还撞了搜索限流。3 个 clone 失败
需要下一轮排查（`repo_timeout=300` 仍空 HEAD，疑似仓库过大或网络瞬断）。

## 五、提交

- `bc9c4b5` — v1.5.10 代码（M387–M389）
- 后续 docs 提交 — 本报告 + 巡猎报告
