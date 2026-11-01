# STAGE REPORT · v1.3.13（M318：--refresh-advisories）

> 日期：2026-11-01 ｜ 基线：v1.3.12（78dbb96）
> 结论：给查重缓存加一个人工强制刷新开关，默认行为不变。

## 一、改动

| 项 | 说明 |
| --- | --- |
| `cve_dedup.set_refresh_advisories()` | 清空 `_GLOBAL_ADV_MEMO` 并删除 `.cache/cve_dedup/_global_advisories.json` |
| `cli.py daily-hunt --refresh-advisories` | 启动时调用上述函数；默认关闭，24h 缓存照旧 |
| 冒烟 [302] | 刷新后 memo 清空、缓存文件删除、下一次 `load_global_advisories()` 重新发请求 |

## 二、使用方式

~~~bash
# 日常挂机（默认 24h 缓存）
python cli.py daily-hunt --languages java,python --days 14 --limit 10

# 人工复核 / 怀疑刚发新 CVE
python cli.py daily-hunt --languages java,python --days 14 --limit 10 --refresh-advisories
~~~

## 三、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,816 项**（新增 [302] 4 项） |
| cli.py doctor | PASS（12 段全绿） |
