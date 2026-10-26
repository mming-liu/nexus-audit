# 第四波收官报告 —— M215 → M232（50 仓大满贯 / 67 门禁）

> doctor 十段 PASS、run_all 67 PASS、smoke [1]-[240] 1,274 项、
> clusters 209 根因 → 127 簇（15 个多仓共现，计数守恒）。

## 一、数字（50 仓大满贯）

| 项 | 数值 |
|---|---|
| 真实野仓 | 50（Java 20 + Python 15 + Solidity 15） |
| 入口/合约单元 | 15,617 |
| 路由级 P0 | 4,999 |
| 独立根因 | 209 |
| GHSA 草稿 | 209（50 仓，INDEX 零断链） |
| 跨仓簇 | 127 / 多仓共现 15 |
| 规则 / 补丁器 | 40 / 35 |
| run_all | 67 PASS |
| 冒烟 | [1]-[240] / 1,274 断言 |

## 二、第四波四仓

| 仓 | 基准 | 关键边界 |
|---|---|---|
| halo | 0 注解入口 / RouterFunction 90 文件 / 0 True | Halo 2.x 用 WebFlux RouterFunction，注解式切片器不适用；基准如实登记并保留反向锚点 |
| sanic | 15 入口 / 0 True | 异步路由；排除路由器工具 find_route_by_view_name |
| litestar | 29 入口 / 0 True | guards 文件 19 个；排除 session/CLI 工具函数 |
| starlette | 0 装饰器入口 / Route+requires 就位 / 0 True | 路由是 Route(...) 对象，不适用装饰器切片；核对 routing.py + authentication.py |

## 三、两条新规则

- jndi_injection（CWE-917，补丁 #34）：InitialContext/JndiTemplate.lookup(参数) 判 True；java:comp/env 常量或前缀白名单+throw 判 False；补丁注入前缀限制后重切 False。
- arbitrary_file_delete（CWE-73，补丁 #35）：Files.delete/File.delete/os.remove/shutil.rmtree 外部路径判 True；getCanonicalPath/realPath startsWith、basename 判 False；补丁注入目录基准守卫后重切 False。

## 四、诚实边界

1. halo 与 starlette 的**函数式/对象式路由**没有被注解切片器覆盖，基准是边界登记（0 入口 + 机制证据 + 反向锚点），不是"整仓无漏洞"。
2. sanic/litestar 只覆盖装饰器路由；排除的是路由器工具与 session/CLI 命令，不是生产路由。
3. kkFileView 的 deleteFile 依赖 deleteFileCheck/checkResult 守卫，已补进文件删除判据，避免 1 条假阳。
4. 209 根因包含 ruoyi 46、spring 12 等；逐仓数字以 wild_hunt.json 为准。

## 五、下一步（最后一波）

M233-M250：matrix --check、Top-10 交单包、ci-init、verify_reproducibility、
smoke [241]-[250]（>=1,500 断言）、run_all 68、doctor 12 段、RELEASE_NOTES_v1.0.0、
STAGE_REPORT_v1.0.0 与最终 push。
