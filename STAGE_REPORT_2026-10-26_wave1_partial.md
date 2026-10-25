# 第一波中间报告 —— M167 → M172（未到 M182 门禁，不作完成声明）

> 这不是第一波的收官报告。M181/M182 要求的 38 仓、55 项 run_all 尚未达到；
> 本文只登记已经实跑、可复现的中间增量，避免把"做了一半"写成"全绿"。

## 一、已完成并纳入门禁

| 模块 | 交付 | 实跑数字 |
|---|---|---|
| M168 | reference_repos/flask-realworld + benchmark_flask_rw.py --strict | 26 入口 / 全类目 0 True / 8 条 authz False / 反向锚点 True→False |
| M169 | reference_repos/v3-periphery + benchmark_v3_periphery.py --strict | 136 生产入口（排除 test/）/ 0 True / multicall delegatecall False |
| M171 | 第 33 类 nosqli（CWE-943）+ 补丁 #28 | Java Document.parse / Python pymongo find 正反例；补丁 True→False |
| M172 | 第 34 类 log_injection（CWE-117）+ 补丁 #29 | Java 拼接 / Python f-string 正反例；参数化日志与 String.format 不计入 |
| M173 | MATRIX_FIX_MAP / DOCTOR_PATCHERS 注册 | 34 类规则 / 29 类补丁器 / 23 个矩阵类目，doctor [10/10] 双向恒等 |
| M174 | 冒烟 [201]–[205] | 正反例、补丁翻转、两新仓基准、注册表对账 |

## 二、门禁（实跑）

    doctor: PASS（34 类 / 29 类补丁器 / 十段）
    run_all: 53 PASS / 0 FAIL / 0 SKIP（新增 flask-realworld、v3-periphery 两项）
    smoke: [1]–[205] / 1,178 项断言 PASS
    advisories: 119 份 / 34 仓（未重跑 wild_hunt，数字未变）

## 三、未完成 / 明确缺口

1. **M167 spring-boot-demo 未接入**。整仓切片 80 入口，当前规则层 102 条 True：
   cors 74（全局配置继承）、authz 15、ssrf 7、unrestricted_upload 2、
   log_injection 2、xss 1、redir 1。需要先做全局 CORS 与 Security 配置识别，
   不能把 74 条配置继承当成 74 个漏洞。
2. **M170 xxl-job 只完成 authz 归零**（22 → 0 True，靠 @XxlSso 角色门、
   validJobGroupPermission、loginCheckWithAttr 三条机制）。xss 4 条
   （IndexController.errorPage 的 int 状态码、LoginController 常量视图、
   JobInfoController 的 JSON 返回）与 deserial 5 条仍未校准，因此没有建
   benchmark_xxl_job.py，也没有把它写进 run_all。
3. **M174–M182 未完成**：冒烟 [206]–[210]、38 仓 wild_hunt、
   cross_repo_clusters 重算、run_all 55 项、阶段性提交都还没做。
4. **第二波至第五波（M183–M250）未开始**。

## 四、本轮由真实代码逼出的修正

- Flask-JWT-Extended：current_user.profile.id 写进 filter_by、current_user.profile
  作为构造实参、article.favourite(profile)/unfavourite(profile) 都要认成主体归属；
  只认 current_user.id 会把 9 条正常路由判成越权。
- xxl-job：@XxlSso(role=...) 是管理员门；@XxlSso(login=false) 是作者显式匿名入口
  （退 None，不判 True）；validJobGroupPermission 是资源组权限校验。
- log_injection 口径收窄：只收字符串拼接 / f-string / % 运算；SLF4J 的
  "{}" 参数化日志、Python 的 "%s" 参数化日志、String.format 常量模板
  不计入，否则 kkFileView 立刻出 4 条假阳。
- v3-periphery：测试合约 contracts/test/TestPositionNFTOwner.sol 必须排除，
  否则 setOwner 的 1 条 True 会污染生产面。

## 五、下一步（按顺序）

1. 做 spring-boot-demo 的全局 CORS/Security 识别，把 74 条 cors 折成配置级根因；
2. 校准 xxl-job 的 xss/deser 5+4 条，建 benchmark_xxl_job.py；
3. 补 [206]–[210]，重跑 38 仓 wild_hunt + clusters + run_all 55；
4. 只有上述四项全绿，才把 M181/M182 标完成，再进第二波。
