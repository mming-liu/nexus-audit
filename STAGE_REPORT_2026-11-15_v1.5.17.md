# STAGE REPORT · v1.5.17（M415–M418：缓存四源仲裁修复 / 第 6 号交单包 / 缓存一致性复验 / 新一轮巡猎）

> 日期：2026-11-15 ｜ 基线：v1.5.16（`7bf9fd8`）
> 主题：修复 `cve_dedup` 读缓存把 M368 四源仲裁 `FRESH` 误降级为 `UNKNOWN`
> 的自相矛盾 Bug；`AUTHENTICATED_LOCAL_ONLY` 增加鉴权基石类目豁免；归档
> `android-agent` 防御修复交单包；连续两次复扫验证缓存一致性（A=2 稳定）；
> 跑新一轮在线巡猎。
> 结论：门禁全绿（smoke 1,756 / triage 16/16 / doctor PASS）；两次复扫
> 均 **A=2 / B=38**，缓存命中可复现；本轮在线巡猎仅 1 个候选且被
> `ZERO_ENTRY_LIB` 跳过，无新 A 候选。

## 一、M415：缓存读取门禁修复 + 类目豁免

### 1. 自相矛盾 Bug 的根因

M368 允许 NVD 熔断时由 `CIRCL + 仓内/全网 GHSA + 仓内 Issue` 四源仲裁判
`FRESH`，并把 `nvd_fallback="CIRCL+GHSA"`、`evidence_gaps` 写成
`nvd_circuit_open_fallback_circl_ghsa`。但读缓存时旧逻辑只检查
`nvd.ok`，一旦 NVD 失败就无条件把 `FRESH` 降级 `UNKNOWN` —— 刚写下的
仲裁结论下一次读回就自相矛盾地消失。

### 2. 修复（`core/context/cve_dedup.py`）

读缓存命中 `FRESH` 且 `nvd.ok=False` 时：

1. 取 `circl / github_advisories / github_global_advisories / github_issues`；
2. 若 `cached["nvd_fallback"] == "CIRCL+GHSA"` 或
   `_dedup_quorum_ok(...)` 成立：
   - 保留 `STATUS_FRESH`；
   - 写回 `nvd_fallback="CIRCL+GHSA"`、`reason="via CIRCL+GHSA (nvd_circuit_open)"`；
   - 把 `evidence_gaps` 里的 `nvd:*` 规范化为
     `nvd_circuit_open_fallback_circl_ghsa`；
3. **只有四源仲裁也不成立**时才降级 `UNKNOWN`，并写
   `INCOMPLETE_DEDUP_EVIDENCE: {nvd_err}`。

### 3. 类目豁免（`core/context/wild_noise.py`）

`AUTHENTICATED_LOCAL_ONLY` 分支增加：

```python
if _repo_auth_local and str(record.get("category") or "") not in (
        "hardcoded_secret", "jwt_weakness"):
```

硬编码密钥 / JWT 弱校验是鉴权基石类目 —— 攻击者可借它伪造全局凭据，
不能被"认证后本地管理面"降噪压掉。

### 4. 附带修复：切片外全大写配置常量 URL 不再判 SSRF

复扫时发现 `android-agent` 的 `ollama_pull`（`agent_chat.py:348`）被
SSRF 规则误报：`OLLAMA_URL = settings.ollama_base_url` 是模块级常量，
不在入口切片里，旧逻辑找不到赋值就按"未知"放行。修复
`rule_detectors._url_var_is_config()`：全大写常量在切片内无赋值时按配置
常量处理（切片内有赋值则仍走配置校验）。`ollama_pull` 切片实测
`ssrf_verdict → False`，A 板从 3 回到 2。

## 二、M416：`cve_submission_kit/06_android_agent.md`

新建第 6 号候选交单包（**纯防御补丁，0 攻击脚本/0 curl 攻击命令**）：

- 仓库：`ghost-in-the-droid/android-agent`，审计 HEAD
  `8974838fd74c06944583c9dcea66570bc4c5c161`（2026-11-14），422 stars，MIT；
- 披露入口：GitHub Private Security Advisory
  `https://github.com/ghost-in-the-droid/android-agent/security/advisories/new`
  + `security@ghostinthedroid.com`（`SECURITY.md` 要求不开公开 Issue）；
- 同仓基线：Issue #31（closed，同类 `{filename:path}` 路径穿越已修）+
  `/api/skills/install` 的 `Depends(require_admin_token)`；
- 完整 Unified Diff：`explorer.py:217-224`、`skills.py:612-621`，均补
  `dependencies=[Depends(require_admin_token)]` 与
  `base.resolve()` / `target.relative_to(base)` / `target != base`；
- `cve_submission_kit/README.md` 新增条目，状态：
  **待用户通过 GitHub Private Security Advisory 私密提交**。

## 三、M417：门禁 `[340]`（9 项）

| 组 | 覆盖 |
|---|---|
| 缓存往返 | NVD 失败 + 四源 ok/0 命中：第 1 次 `FRESH` + `nvd_fallback` + 无 `from_cache`；第 2 次读缓存仍 `FRESH` + `from_cache=True` + `nvd_fallback` |
| 缺口规范化 | 读回后 `evidence_gaps` 含 `nvd_circuit_open_fallback_circl_ghsa` |
| 旧缓存降级 | `FRESH` + NVD 失败 + CIRCL 失败（四源仲裁不成立）→ 读缓存降级 `UNKNOWN` |
| 类目豁免 | `AUTHENTICATED_LOCAL_ONLY` 服务下 `ssrf` / `arbitrary_file_delete` → blocked；`hardcoded_secret` / `jwt_weakness` → 不 blocked |
| SSRF 常量 | 切片外全大写 `OLLAMA_URL` → 不判 SSRF |

## 四、M418：缓存一致性复验 + 新一轮巡猎

### 1. 两次复扫（不删除 `.cache/cve_dedup`）

```
python cli.py daily-hunt --repos ghost-in-the-droid/android-agent --offline \
  --cooldown-days 0 --max-roots 0 --state .tmp/m418_r1c_state.json \
  --report .tmp/m418_r1c_LIVE_HUNT_REPORT.md --json .tmp/m418_r1c_daily_hunt.json \
  --packs-dir .tmp/m418_r1c_packs --repo-timeout 300
# 第二次同命令，仅把 r1c 换成 r2
```

| 次 | 根因 | 板块 A | 板块 B | 说明 |
|---|---|---|---|---|
| 第 1 次 | 40 | **2** | 38 | `ollama_pull` 误报已随 SSRF 修复消失（41→40） |
| 第 2 次 | 40 | **2** | 38 | 100% 命中缓存，稳定 A=2 |

A 板两条：

```
android-agent  arbitrary_file_delete  api_skill_delete   gitd/routers/skills.py:612
android-agent  arbitrary_file_delete  explorer_delete    gitd/routers/explorer.py:217
```

缓存命中证据（直接调用 `cve_dedup.dedup`）：

```
explorer_delete   from_cache=True  status=ZERO_RECORD_FRESH  nvd_fallback=CIRCL+GHSA
api_skill_delete  from_cache=True  status=ZERO_RECORD_FRESH  nvd_fallback=CIRCL+GHSA
evidence_gaps=['nvd_circuit_open_fallback_circl_ghsa']
```

### 2. 新一轮在线巡猎

```
python cli.py daily-hunt --languages java,python --days 21 --limit 8 \
  --min-stars 300 --max-roots 5 --cooldown-days 7 --repo-timeout 300
```

结果：

- 候选仓 1 ｜ 实扫 0 ｜ 跳过 1 ｜ 失败 0 ｜ 候选来源 `github_search`；
- 候选 `Hainrixz/whatsapp-agentkit`（HEAD `e33eb6a35804`）→
  `SKIPPED (ZERO_ENTRY_LIB)`（仓内 0 个可识别入口，不占实扫名额）；
- 新增根因 0 ｜ 板块 A 0 ｜ 拦截进 B 0；冷却期免克隆 0；
- 报告已更新：`LIVE_HUNT_REPORT.md`（本次 0 行 A/B），
  JSON `benchmarks/results/daily_hunt.json`，账本 262 仓。

**白盒精核**：本轮无新 A 候选，无需逐行核查；`android-agent` 两条既有 A
已在 v1.5.16 报告 §4 完成精核与防御补丁归档。

## 五、门禁结果

| 项 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,756 项断言**（v1.5.16 为 1,747；`[340]` 9 项） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿**（含 SSRF 常量修复后复跑） |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 六、已知边界与建议

1. **巡猎候选池偏薄**：`.cache/scout_search` 仅 12 页缓存、无 GitHub token，
   且账本已有 262 仓、多数在 7 天冷却内；本轮只捞出 1 个候选且是
   `ZERO_ENTRY_LIB`。下一轮建议：配置 `GITHUB_TOKEN` 提高搜索配额，
   或 `--refresh-advisories`/清理旧页后再跑。
2. **NVD 熔断成为常态**：缓存修复后四源仲裁 `FRESH` 可稳定复现，但
   `evidence_gaps` 仍会标注 NVD 缺口；报告侧应继续按"via CIRCL+GHSA"口径
   解读，不要把 `evidence_complete=False` 误读为"没查过"。
3. **类目豁免只覆盖 `AUTHENTICATED_LOCAL_ONLY`**：同仓若先命中文件级
   `LOCAL_LOOPBACK_ONLY`，`hardcoded_secret`/`jwt_weakness` 仍会被后者拦下
   —— 这是既有规则行为，若需一并豁免应单独评估（本轮未改）。
4. **全大写常量 SSRF 启发式**：切片内无赋值即视为配置；若某项目把用户输入
   赋给全大写变量且赋值行不在切片内，理论上会漏报。概率低，已用
   `[340]` 锁定"切片内有赋值仍走配置校验"的边界。

## 七、提交清单

- `core/context/cve_dedup.py` — M415 缓存四源仲裁保留 FRESH + 缺口规范化
- `core/context/wild_noise.py` — M415 `hardcoded_secret`/`jwt_weakness` 豁免
- `core/agents/rule_detectors.py` — 附带修复：切片外全大写配置常量不判 SSRF
- `benchmarks/smoke_test_chains.py` — M417 `[340]` 9 项
- `cve_submission_kit/06_android_agent.md` + `README.md` — M416 第 6 号交单包
- `LIVE_HUNT_REPORT.md` — M418 新一轮巡猎结果（1 候选 / 0 A）
- `STAGE_REPORT_2026-11-15_v1.5.17.md` — 本报告
