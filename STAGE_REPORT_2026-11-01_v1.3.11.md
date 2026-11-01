# STAGE REPORT · v1.3.11（M314 → M316：跨仓查重三防线）

> 日期：2026-11-01 ｜ 基线：v1.3.10（15ad7bc）
> 结论：v1.3.10 的两单"真洞"经全网查重均为**已公开 CVE**，已归档不发；
> 查重器的三个跨仓盲区已补齐。

## 一、撞车事实

| 我方发现 | 已公开记录 |
| --- | --- |
| yshop deleteFlowStep | CVE-2026-92462（2026-09-16） |
| yshop getFlowUserIds | CVE-2026-92461 |
| LZ-litchi getFileContent | CVE-2026-71805 / GHSA-gvv2-7gf7-286x（2026-09-09），且继承自 ruoyi-vue-pro Issue #1146/#1188 |

两单均已写 `REPORT_STATUS.md` 标为 DUPLICATE_CVE 归档，不提交。

## 二、三个盲区与修法

| 盲区 | 旧行为 | 新行为 |
| --- | --- | --- |
| 全局 GHSA | 只查 `/repos/{slug}/security-advisories`（作者手动发布，几乎恒空） | 同时翻 `GET /advisories` 全局库（默认 3 页 × 100），按仓库名 + 方法名收窄 |
| 跨仓 Issue | `q=repo:{slug} {term}` 锁死目标仓 | 新增 `"类名" "方法名"` 全网搜索，返回 `repo#num`，抓改名仓与外部 PoC |
| 二开基座 | 只按二开仓名查 | `detect_upstream_aliases()`：包名 `cn.iocoder.yudao / org.jeecg / com.ruoyi` 或 pom 里 yudao/ruoyi/jeecg 指纹 → 自动挂上游主仓别名 |

`live_hunt.run_one` 现在把 `repo_root` 与 `class_name` 传给 `dedup()`。

## 三、种子库（M315）

`config/known_public_cves.json` 新增 11 条：yshop 的 CVE-2026-92462 / 92461 / 92458 /
92459 / 92463 / 109171 / 111703 / GHSA-h7m8-pw8h-m438，LZ 的 CVE-2026-71805，
以及 ruoyi-vue-pro Issue #1146 / #1188。

## 四、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,805 项**（新增 [299] 6 项、[300] 5 项） |
| cli.py doctor | PASS（12 段全绿） |
| 冒烟里程碑 | [1]–[300] 全绿，累计断言 ≥ 1,800 |

## 五、遗留

- 全局 advisory 翻页上限 3 页（300 条），更早的公告仍靠本地种子兜底；
  种子库应随每次撞车持续补录。
