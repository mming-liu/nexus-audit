# 阶段报告 —— M151 → M166 十六模块连续施工（2026-10-25d）

> 本报告只登记**实跑**数字。唯一事实源：benchmarks/results/wild_hunt.json、
> cross_repo_clusters.json、advisories/INDEX.md、run_all.md。
> 门禁：python cli.py doctor（十段全绿）、
> python benchmarks/run_all.py --offline --jobs 4（51 PASS）、
> python benchmarks/smoke_test_chains.py（[1]–[200]，1,153 项断言）。

## 一、收官数字

| 项 | 数值 |
|---|---|
| 真实野仓 | **34 个**（Java 15 + Python 8 + Solidity 11） |
| 入口/合约单元 | **11,575 个** |
| 路由级 P0 命中 | **1,566 条** |
| 去重后的独立根因 | **119 个** |
| GHSA 披露草稿 | **119 份**（零断链，CVSS 降序） |
| 跨仓簇 | **65 簇 / 12 个多仓共现簇**（计数守恒 119） |
| 规则类目 | **32 类** |
| 确定性补丁器 | **27 类** |
| 离线门禁 | **51 项全 PASS** |
| 冒烟断言 | **[1]–[200] / 1,153 项** |

供应链侧：**5 个仓**命中已知组件 advisory，其中 **4 个仓**同时有代码级 P0
（双重实锤）。jeecg-boot 是首个 Java 侧完整样本：mysql-connector-java
8.0.27 < 8.0.28（CVE-2022-21363）+ 代码级 SQLi 根因。

## 二、十六模块交付

### M151 矩阵 × 补丁注册表双向恒等
- MATRIX_FIX_MAP 补齐 ssti / header_injection / mass_assignment /
  weakrand / _fix_solidity_txorigin；展开集 == DOCTOR_PATCHERS（27 个）。
- doctor 新增 [10/10]：双向差集、函数可调用性、矩阵 key 是否真实类目。

### M152 cli.py watch 白盒增量首杀
- 新增 core/context/watchtower.py：git diff → 变更方法/反向调用方/装配级
  影响面 → 规则层 True → base worktree 基线比对（只报新引入）→ 四件套。
- watch_state.json 状态机：首跑回看 HEAD~1；第二次跑无变更即 0 命中。
- 冒烟 [191] 用真实两提交仓库锁定：1 条 sqli → ADVISORY/fix.patch/checklist/PoC；
  第二跑 0 条。

### M153–M156 第 31–34 号野仓

| 仓 | 入口 | 结果 | 由真实代码逼出的修正 |
|---|---|---|---|
| kkFileView | 15 controller + 解压 helper | zip_slip False（normalize+startsWith），去掉守卫反向锚点 True；0 条其它 True | crypto 裸 encrypt/decrypt 匹配形参名 encryption → 4 条假阳；authz 不认 sendError(SC_UNAUTHORIZED) 与共享密钥实现体 configKey.equals(key) |
| full-stack-fastapi-template | 23 | authz 0 True；superuser/CurrentUser 全 False | 跨行装饰器尾巴污染；Annotated[..., Depends(...)] 别名与 APIRouter(dependencies=...) 未展开；Depends 只扫 body |
| solady | 2,968 | 五类 0 True；Ownable/OwnableRoles/ERC721 全 False | _checkOwner()/_checkRoles() 的 Yul caller()+sload 门未被识别；eq(caller(), from) 变体 |
| apollo | 200 | authz 0 True；59 个 @PreAuthorize 全 False | 自定义 @bean.method() EL；anyRequest().hasAnyRole 只在 profile 生效 → [auth-profile-dependent] 退 None |

### M157–M158 第 31/32 类规则 + 补丁 #26/#27
- unrestricted_upload（CWE-434）：Java MultipartFile.getOriginalFilename()
  与 Python UploadFile.filename 落盘；后缀白名单/固定 UUID 后缀判 False；
  MIME-only 不算防护。补丁 #26 注入白名单并重切片自检 True→False。
- signature_replay（CWE-347）：状态变更路径原生 ecrecover 缺零地址校验
  或 nonce 消费 → True；view/pure 与带 nonce 的 ECDSA.recover → False。
  补丁 #27 注入 require(signer != address(0)) + __usedSig[h] 消费。
- 两类的三语言 PoC 合成全部自检通过。

### M159 Java 供应链
- versions() 先建 dependencyManagement 索引；子模块 dependency 省略
  version 时回退。新增 hutool-all / druid / pagehelper / mybatis /
  mysql-connector-java / postgresql 的保守 advisory（有明确 fixed_in 的才收）。
- 实测：jeecg mysql 8.0.27 命中 CVE-2022-21363；eladmin hutool 5.8.35、
  mall pagehelper 6.1.1、jeecg postgresql 42.2.25 均不低于修复版本。

### M160 Top-3 交单包

benchmarks/results/first_blood_packs/：

1. My-Blog_unrestricted_upload_uploadFileByEditormd（新规则 #31）
2. newbee-mall_weakrand_upload
3. RuoYi_sqli_create

每包 ADVISORY.md / poc_test.* / fix.patch / SUBMISSION_CHECKLIST.md
四件套，ADVISORY 带 [Auto-Fix Verified]，补丁均实测 True→False。

### M161–M163 冒烟 [186]–[200]
- [186] 矩阵恒等 / 32 类空源码 None / 27 补丁器可调用；
- [187] unrestricted_upload 正反例 + #26 翻转 + 文件还原；
- [188] signature_replay 正反例 + #27 翻转 + view 安全；
- [189]–[190] 注册表/矩阵/PoC；
- [191] watch 状态机；
- [192]–[195] 四个新仓机制边界；
- [196] 供应链双重证据 + dependencyManagement 回退；
- [197]–[198] 交单四件套与 PoC；
- [199] 34 仓语言对账；
- [200] 1,150+ 断言里程碑。

### M164–M165 野战重算与白皮书
- wild_hunt.py --advisory-dir benchmarks/results/advisories：34 仓实跑，
  119 根因 / 119 草稿；cross_repo_clusters.py：65 簇 / 12 多仓共现，守恒。
- refresh_wild_report.py 从 JSON 重建白皮书一/二/四节；第七节由 wild_hunt
  直接 splice。README/SCOREBOARD 同步。

## 三、本轮由真实代码逼出的修正（节选）

1. **crypto 证据归属**：裸 encrypt/decrypt 命中形参名 encryption
   → 改为要求调用形态；kkFileView 4 条假阳清零。
2. **共享密钥门**：validateKey 的实现体是 configKey.equals(key)，
   sendError(SC_UNAUTHORIZED) 与 401 同义；按机制认，不按名字。
3. **cmdi 裸 .load(**：把 appService.load(appId) 当 Runtime.load；
   收窄到 Runtime/System/rt/runtime。jeecg 冻结表因此从 24 修为 17。
4. **MyBatis 美元花括号归属**：变量必须能被入口形参触达；Apollo
   importConfigByZip 的无关 Mapper 证据不再判 True。
5. **@RestController 的 return dto**：按返回类型区分 JSON 与 HTML 回显；
   String 返回仍按反射型 XSS 判。
6. **硬编码密钥文件级普查**：移除 .js/.ts/.json —— minified bundle 与
   i18n 文案不是凭证。
7. **沙箱并发回退**：受限 Windows 禁止匿名管道，run_all / OWASP 回归在
   ProcessPool 建池失败时明确告警并顺序执行，不伪装并发。

## 四、诚实边界

- **kkFileView 的 zip_slip 在上游已修复**：本仓判定 False 是"守卫被认出"，
  不是"发现新漏洞"；反向锚点（去掉 startsWith → True）证明判据仍然灵敏。
- **Apollo 仍有 8 条规则层 True**（5 条存储型 XSS、2 条 deserial、1 条 sqli），
  已列在 benchmarks/results/apollo.json 的 residual，属于交人工复核队列：
  XSS 依赖前端渲染方式，deserial 依赖 fastjson 版本证据，sqli 依赖 Mapper
  语句归属。它们计入 119 根因，但不作为"零误报"声明的一部分。
- **119 根因与 98 的差额**来自：新仓（Apollo 8 / 新规则命中的 eladmin、
  My-Blog、newbee 等）与判据修正（jeecg -6、kkFileView 0）。逐仓数字以
  wild_hunt.json 为准。

## 五、门禁输出（实跑）

    doctor: PASS（全部就绪）                 # [1/10]–[10/10]
    run_all: 51 PASS / 0 FAIL / 0 SKIP
    smoke:   CHAIN SMOKE TEST PASS（已执行 1,153 项断言）
    clusters: 119 根因 → 65 簇（守恒）/ 多仓共现 12 ≥ 8
    advisories: 119 份 / 34 仓（INDEX 零断链，CVSS 降序）

## 六、下一步

1. 人工复核 Apollo 8 条 residual，确认 XSS 的前端渲染与 deserial 的实际
   组件版本；确认后二选一：转正式 advisory 或登记为争议。
2. 对 first_blood_packs/ 三份按 SUBMISSION_CHECKLIST.md 走私密披露。
3. 把 watch 挂到目标仓的 post-commit / CI 定时任务，积累首杀时间线。
