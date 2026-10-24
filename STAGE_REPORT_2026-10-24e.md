# 阶段报告 2026-10-24e：M79–M86 状态锁 + FastAPI + JWT/CVSS/基线

**范围**：`Module 79` → `Module 86`
**基线**：`f7495f8`（M78b，冒烟 `[1]`–`[115]`，25/25 PASS）
**状态**：代码与数据已落盘；M86 全量门禁见 §5

---

## 1. 一页摘要

| 项 | 结果 |
|---|---|---|
| 真实仓库 | **11 个**（Java 7 + Python 2 + Solidity 2） |
| 入口 | **1,554 个** |
| 规则判定对 | **22,808 次** |
| P0 路由级命中 | **630 条** |
| 独立根因 P0 | **42 个**（4 份全局 CORS + 38 条端点/文件级） |
| 确认的规则层误报 | **0 条** |
| 二级漏斗派发模型 | **0 条**（17,317 条假候选全过滤，100%） |
| 自动修复自检 | **3 条**（litemall CORS + JWT 密钥；Employee 弱密钥） |
| 新增规则 | 第 23 类 `jwt_weakness` |
| 新增补丁 | 第 17 类 JWT 验签补丁 |
| 新增靶场 | Uniswap V3（第 27）、FastAPI（第 28） |
| 冒烟 | `[1]`–`[122]`，**702 项 PASS** |
| 全量门禁 | `run_all --offline --jobs 4` **27 PASS / 0 FAIL / 0 SKIP** |
| `doctor` | **23 类规则 + 17 类补丁器 + 16 项地板 + 第六段白皮书对账，PASS** |
| 11 个真实仓库 strict | **11/11 exit 0** |

---

## 2. 十一仓数据

数据源：`benchmarks/results/wild_hunt.json`（`benchmarks/wild_hunt.py` 实跑）。

| 项目 | 语言 | 入口 | 判定对 | P0 | 根因 | 过滤 | strict |
|---|---|---:|---:|---:|---:|---:|---|
| newbee-mall | Java | 73 | 1,460 | 6 | 6 | 100% | ✔ |
| newbee-mall-api | Java | 62 | 1,240 | 66 | 5 | 100% | ✔ |
| RuoYi | Java | 305 | 6,100 | 1 | 1 | 100% | ✔ |
| eladmin-mp | Java | 65 | 1,300 | 76 | 12 | 100% | ✔ |
| mall | Java | 246 | 4,920 | 253 | 8 | 100% | ✔ |
| My-Blog | Java | 54 | 1,080 | 3 | 3 | 100% | ✔ |
| litemall | Java | 219 | 4,380 | 223 | 5 | 100% | ✔ |
| Employee-Management-System | Python | 4 | 80 | 2 | 2 | 100% | ✔ |
| Compound | Solidity | 450 | 1,800 | 0 | 0 | 100% | ✔ |
| Uniswap V3 | Solidity | 67 | 268 | 0 | 0 | 100% | ✔ |
| FastAPI | Python | 9 | 180 | 0 | 0 | 100% | ✔ |
| **合计** | — | **1,554** | **22,808** | **630** | **42** | **100%** | **11/11** |

完整证据与逐项目清单见 [`WILD_HUNT_REPORT.md`](WILD_HUNT_REPORT.md)。

---

## 3. 模块落点

### M79 Uniswap V3：自定义状态互斥锁

- `UniswapV3Pool` 使用 `modifier lock() { require(slot0.unlocked);
  slot0.unlocked = false; _; slot0.unlocked = true; }`，不叫 `nonReentrant`；
- `reentrancy_verdict` 新增通用结构识别：`require/if` 前检 + `_;` 前把同一
  状态位置 false/0 + `_;` 后置 true/1；只有赋值没有前检不算锁；
- 生产 `contracts/` 排除 `contracts/test/`（123 个测试入口）后 67 入口 /
  268 判定 / **0 True**；`mint/burn/swap/flash/collect` 全 False；
- `benchmark_uniswapv3.py --strict`；`run_all` 第 26 项；冒烟 `[116]`。

### M80 FastAPI：async + Depends + SQLAlchemy 2.0

- 新增真实模板仓 `fastapi-sql-template`：9 个 `async def` 入口；
- `Depends(require_superuser)` 作为框架级授权声明 → 5 个 users 入口
  `authz=False`；`Depends(get_current_user)` 只作为主体注入，不直接判安全；
- `session.execute(select(...))` 识别为 SQLAlchemy 2.0 绑定参数表达式 →
  `sqli=False`，消除 4 条 ORM 误报；
- `benchmark_fastapi_wild.py --strict`；`run_all` 第 27 项；冒烟 `[117]`。

### M81 第 23 类 `jwt_weakness`

- Python：`verify_signature: False` / `verify=False` /
  `algorithms=["none"]` → True；指定 HS256 且未关验签 → False；
- Java：`.parseClaimsJwt(` / 无 `setSigningKey` 的 `Jwts.parser().parse(` →
  True；`.setSigningKey(...).parseClaimsJws(` → False；
- `CATEGORIES` 单一事实源 23 类，doctor 自动升 23；冒烟 `[118]`。

### M82 第 17 类 JWT 补丁

- Python 把 `verify_signature: False`→True、`verify=False`→True、
  `algorithms=["none"]`→`["HS256"]`；
- Java 把 `parseClaimsJwt(`→`setSigningKey(env).parseClaimsJws(`；
- 重切片验证 `jwt_weakness` 翻 False，finally 字节级还原；
- PoC 合成器新增 `alg=none` 伪造管理员 Token（Python/Java）；冒烟 `[119]`。

### M83 CVSS v3.1

- 新增零依赖 `core/context/cvss.py`：23 类基础向量 + 标准 3.1 公式；
- GHSA 草稿头部写 `CVSS v3.1：6.5 MEDIUM` 与 `CVSS:3.1/...`；
- SARIF `rules[].properties.security-severity` / `cvss` / `severity`，
  GitHub Code Scanning 可直接展示；HTML 卡片加分值徽章；
- 冒烟 `[120]` 验证 9.8/8.1/6.1/6.5 等向量与分值。

### M84 `--baseline` 增量抑制

- 读取基线 SARIF / summary JSON 的 `(ruleId, uri, root_cause)`；
- 命中基线的存量根因进入 `suppressed_by_baseline`，报告/SARIF/HTML/
  退出报告只反映净增；
- 3 条继承 CORS 路由只算 1 个根因；注入 1 个新密钥只报 1 条；
- 冒烟 `[121]`。

### M85 doctor 第六段

- `doctor` 升六段：依赖 / 规则 / 指纹 / 补丁器 / 扩展 / 白皮书对账；
- 第六段核对 `wild_hunt.json` 与 `WILD_HUNT_REPORT.md` 的仓库数、入口总数、
  独立根因数、零误报计数；
- 冒烟 `[122]`。

---

## 4. 关键工程判断

1. **"看实现体不看名字"再次兑现**：Uniswap 的锁叫 `lock()`，结构识别后
   `mint/flash` 从 None 翻 False，不写合约名特判。
2. **ORM 表达式不是 SQL 文本**：`select(...)` 走绑定参数；只对
   `text("..." + x)` 保留拼接判据。
3. **`Depends(get_current_user)` 不等于授权**：只证明知道是谁，归属比对
   可能下沉 Service；`require_superuser` 才是门。
4. **CVSS 不进规则判定**：它只影响披露优先级，不改变 P0 三态；避免
   "评分高就判漏洞"的口径污染。
5. **基线按根因抑制**：按路由抑制会让 219 条 CORS 每次 CI 都刷屏；按根因
   只抑制 1 条。

---

## 5. M86 验收

- [x] 11 仓 `wild_hunt.py` 刷新（Java 7 + Python 2 + Solidity 2）
- [x] `run_all --offline --jobs 4` **27 PASS / 0 FAIL / 0 SKIP**
- [x] 冒烟 `[1]`–`[122]` **702 项 PASS**
- [x] `doctor` exit 0（23 类 + 17 补丁器 + 16 地板 + 第六段）
- [x] 11 仓 `benchmark_* --strict` 全 exit 0
- [x] SCOREBOARD / run_all / triage 同步
- [x] README / WILD_HUNT_REPORT / MEMORY 更新
- [x] pre-push 全绿、远端 `main` 同步

---

## 6. 提交

| 提交 | 内容 |
|---|---|
| `c2ed672` | M71 根因去重折叠 |
| `8f5051e` | M72–M77 Python/Solidity 扩军 + CORS 补丁 + PoC/Advisory |
| `ee77630` | M78 九仓白皮书 |
| `f7495f8` | M78b 数据来源脚注 |
| 本报告 | M79–M86 状态锁 / FastAPI / JWT / CVSS / 基线 |

---

## 7. 边界

- Uniswap 只扫生产 `contracts/`，排除 `contracts/test/`（123 个测试入口）；
- FastAPI 仓库是真实模板，9 个入口；`delete` 是空实现，sqli 合理为 None；
- JWT 类目对"只做 base64 解码"不判 True，避免把非验签入口当漏洞；
- CVSS 是类目级基础向量，不等于具体环境的可利用性评分；
- 披露草稿是人工复核前的 GHSA 模板，提交上游前仍需维护者确认。

---

*生成：2026-10-24｜基线 `f7495f8`｜数据 `benchmarks/results/wild_hunt.json`*
