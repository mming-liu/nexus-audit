# v1.1 深潜中间报告（M251 → M252 完成，其余未清账）

> 本轮只完成 M251/M252 两条路由切片；M253–M266 未完成。特别是 M258 的
> “209 条逐条源码核验”不能由脚本伪造，必须人工复核，因此本报告不宣称
> “零未复核队列”。

## 一、已完成

| 模块 | 交付 | 实跑 |
|---|---|---|
| M251 | java_servlet 解析 Spring WebFlux RouterFunctions 链式路由 | halo 全仓 scan **173 入口**（原 0）/ benchmark 173 入口 / 0 True |
| M252 | web_treesitter 解析 Starlette Route/Mount 对象式路由 | starlette benchmark **148 Route 入口**（scan 包内 6 入口）/ 0 True |

连带影响：litestar 因 Route 解析从 29 → 33 入口（仍 0 True）；50 仓重算
15,800 入口 / 208 根因 / 126 簇（15 多仓）。

## 二、门禁

    doctor: PASS（12 段）
    smoke: [1]-[250] / 1,503 断言 PASS
    run_all: 68 PASS（m000 基线；路由切片后未重跑全量）
    repro: PASS（sha256 284ec8c3，50 仓守恒）

## 三、未完成（明确）

1. **M253 零空跑门禁**：flask-jwt-extended 仍是 0 路由（库仓，无 Flask 路由），
   直接加“全部 >0”会误伤；需要先把它标成 library 例外或补合成入口。
2. **M254 ruoyi 46 根因**：尚未逐条解剖；基准仍只锁 system+infra。
3. **M255/M256**：apollo/Sentinel/xxl/kk 的全仓扫描与基准口径尚未对齐。
4. **M257 生产/教学分账**：未在 wild_hunt 数据里加 production/educational 字段。
5. **M258 verified_root_causes.json**：未建立；208 根因仍有大量未人工复核，
   不能用“脚本生成一条 status=verified”冒充核验。
6. **M259 纯生产 Top-10**：当前 Top-10 仍含 spring-boot-demo（教学演示）。
7. **M260-M266**：冒烟 [251]-[260]、v1.1.0 重算与封版未做。

## 四、结论

M251/M252 证明“函数式/对象式路由切得动”，但 v1.1 的核心是**人工清淤**
而不是再加切片器。没有逐条源码核验，就不能把 208 条根因标成实锤。
下一步应先做 M257 分账 + M258 台账（人工填），再决定哪些根因可以对外。
