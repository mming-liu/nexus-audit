# Module 20 → 27 阶段报告（2026-10-22）

一次性全自动连跑，三个硬性约束执行情况：全程零中断；每个扩展先探针、零收益即记录跳过；
最终回归 **run_all --offline --jobs 4 = 16 PASS / 0 FAIL / 0 SKIP**，OWASP 1352 条
**A=0 / B=0**，冒烟 [1]-[73] 全绿。

## 一、新靶场（11 → 14 个）

| 靶场 | 单元 | 真值 | 判定 | 误报 | 判反 | 门禁 |
|---|---|---|---|---|---|---|
| not-so-smart-contracts (M20) | 208 | 8 | 7 | 0 | 0 | strict |
| RuoYi (M22) | 305 | 164 | 159 | 0 | 0 | strict |
| pygoat (M24) | 119 | 9 | 9 | 0 | 0 | strict |

- **M20 nssc**：README 指名真值按 (相对路径, start_line) 精确标定 8 条（施工单期望 access
  分母 +35 未达，只收指名条目，如实报告）。honeypots 不收：既"有洞"又"对受害者不可利用"，
  收进真值表自相矛盾。
- **M22 RuoYi**：159 条 `@RequiresPermissions` 注解行全部直判 False（方法级权限注解 =
  作者垂直授权声明）；dataScope 5 条——`DataScopeAspect` 先 clear 客户端传入的
  `params.dataScope` 再写服务端 SQL，非客户端可控，sqli=False。跨模块 Hop1 命中 174 单元。
  无注解 20 条不进真值表（未标注 ≠ 声明安全），其中 8 条暴露 2g 判据缺口，修复后单列 16 条。
- **M24 pygoat**：Flask 20 lab；作者指名 9 条全 True（含 spel `ImageMath.eval` 软件完整性、
  yaml upload、pickle 反序列化、xxe）。DISPUTED 单列：xss_lab 视图层 `render_template`
  自动转义、真实 sink 在模板 `|safe`，与类目口径一致判 False，不收真值但在案。

## 二、判据与模型层扩展

- **M21 2300 gas 津贴早退**：单参 `.transfer(x)/.send(x)`（stipend 形态）VM 层重入不可能
  → 规则早退 False；双参 token `transfer(to, amount)` 是 ERC20/777（777 有钩子）照旧进
  CEI 行序。三分类 hard/stipend/token。
- **M21 Solidity 事实诊断头** `build_solidity_diagnostic`：只发射模型看不到的确定性事实
  （0.4.x 构造函数关系、modifier 定义体不在切片内、老语法默认 public），纯 public 返回空串，
  带"不可作为证据引用"声明。冒烟抓出首版发射过宽，已收紧。
- **M23 authz 2g 分支**：主体链取值（`ShiroUtils.getSysUser()` / `getSysUser()`）赋局部
  变量作 Service 实参 → False；裸 `getUserId()` 不算（客户端 DTO 可冒充主体）。
  `_AUTHZ_SUBJECT_RE` 补 Shiro 形态。
- **M25 Python 反序列化判据 + 补丁**：pickle/cpickle/dill loads、yaml.unsafe_load/full_load
  → True；yaml.load 逐调用查 `Loader=SafeLoader`；仅 safe_load → False。`--fix` 第 6 类
  `_fix_python_deserial`：ast 定位 `yaml.load` 改 `.safe_load`，跨行 Loader 不产补丁，
  重切片自检 + 字节级还原。pickle 无等价安全 API，不动手。
- 同批 Python 判据补口（M24 逼出）：xxe（defusedxml 门控含裸 `fromstring(`、
  `feature_external_ges` 三态）、pathtraver（裸 `open(` + os.path.join(常量,输入) 不防遍历）。

## 三、切片器三 bug 修复（pygoat 逼出）

1. **同名符号共存**：SymbolIndexer `symbol_table` 由 name→dict 改 name→list，
   `get_symbol_code(prefer_file)` 同文件优先。修复前 pygoat 整库 50 单元丢一半，
   修复后 119 单元（20 个 lab 都有 index/lab1/health_check 同名）。
2. **Python 赋值链区域语义** `_py_local_region`：只在 sink 所在段追赋值——hop 段同名
   赋值不遮蔽入口、sink 同段赋值可见；关键字实参 `sql_query=sql_query,` 不是赋值
   （括号深度 0 才认）；多行括号右值吃到配平。两次语义修正都被冒烟抓回。
3. **xxe 门控漏裸 `fromstring(`**：正则补 `\bfromstring\s*\(`。

## 四、基建（M26）

- `run_all.py --jobs N`：ProcessPoolExecutor 并发段，冒烟/争议核对保持串行，FAIL 后不再
  启动新作业。--jobs 4 实测：OWASP 360s 占 86% 是并发瓶颈，其余 13 项 ~35s 压进并发窗口。
- `SCOREBOARD.md` 白名单制：只收五标量（units/decided/correct/fp/reverse_fn）齐全的
  真值型靶场（smartbugs/DeFiVulnLabs/nssc/vulpy/RuoYi/pygoat 六行），全绿才刷新；
  模型层数字不进计分板。合计 **误报 0 · 判反 0**。

## 五、声明的跳过项（探针零收益）

- **M20 跨文件继承修饰符切片**：探针 0 命中（nssc 无继承修饰符形态），跳过。
- **M21 覆盖率 101 → 130+/246**：探针证明退回批 145 条对六类确定性事实零命中，
  剩余是单元内缺外转/扣减证据的不可判定面，不凑覆盖率。
- **M24 Django 视图识别**：pygoat 实为 Flask，Django 切片无输入面，跳过。

## 六、口径分歧单列（不收真值、打印在案）

pygoat xss_lab 三条（模板层 |safe）、RuoYi 无注解 True 面 16 条、GenController.create
（管理员专用建表工具）。

## 七、提交清单（本地 7 笔，本报告随 M27 收口笔一并 push）

cfac11e M20 / 81e1219 M21 / f0d491b M22 / c41e55a M23 / d732e86 M24 /
2d22c4b M25 / 4e80799 M26；M27 收口 = 本报告 + push。
缓存指纹已核对：`_slicer_fingerprint` 登记 web_treesitter.py / symbol_indexer.py，
OWASP 缓存自动失效，全量重扫后 A=0/B=0 不受切片器改动影响。
