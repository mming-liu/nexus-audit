# CONTRIBUTING

`nexus-audit` 是一个 Java Web 漏洞静态审计器：切片（slicer）→ 上下文（context）→
智能体（agents）→ 沙箱（sandbox）四层解耦，契约在 `core/models.py`。
规则层的定位是"能确定性判定的不交给 LLM"——本文写的是给这个层贡献代码时
**必须遵守的纪律**，每一条背后都有真实踩过的坑。

## 快速上手

```sh
# 冒烟（判据链路断言，几秒内结束）
python benchmarks/smoke_test_chains.py
python benchmarks/smoke_test_week1.py
python benchmarks/smoke_test_week2.py

# OWASP 规则层全量回归（离线，不调模型；首次会建 42MB 切片缓存）
python benchmarks/regress_owasp_rules.py

# 三靶场规则层回归（--offline 只跑确定性规则）
python benchmarks/benchmark_javaseccode.py --offline
python benchmarks/benchmark_hellojavasec.py --offline
python benchmarks/benchmark_javaseclab.py --offline
```

## 开启 Git 钩子

```sh
git config core.hooksPath .githooks
```

- **commit-msg**：提交信息正文必须含回归段（写明如何验证未打回归）。
- **pre-push**：推送前自动跑 `smoke_test_chains.py` 与
  `export_disputes.py --check`。

## 三条铁律

1. **先核事实，再动判据。** "证据在切片里"要用定义位置验证，不能用
   `in` 判断；任何"我确认过 X 存在"的结论都要说得出它是哪一行。
   判据写错的代价是误报，证据缺一块的代价是**不报错、不掉指标的静默暗坑**。
2. **兜底分支只能 `return None`，不能 `return True`。**
   把"我不确定"伪装成"我有把握"，比漏报更危险。同理：控制流没建模时
   （switch 多分支、非恒定 if 互斥路径）不表态，交模型。
3. **真值争议登记但不剔除。** 靶场标错的样本进 `benchmarks/disputed_truth.py`
   （要求：说得清双方依据 + 带行号的逐字证据 + 归入既有 kind），
   **绝不从分母剔除**——靶场标错也是数据，不是麻烦。

## 规则层改动必跑清单

| 什么改了 | 必须跑 |
|---|---|
| `core/agents/rule_detectors.py` 判据 | 三套冒烟 + `regress_owasp_rules.py` + 三靶场 `--offline` |
| 触碰 `_resolve_rhs_origin` / `_value_origin` 等共享机制 | 同上，且必须对比改动**前后**的 A/B 方向清单（见下） |
| 切片器 `core/slicer/` | 三套冒烟 + `regress_owasp_rules.py --refresh` 重建缓存后全量 |

`regress_owasp_rules.py` 检查两个危险方向：

- **A：vul 被规则判 False**（静默放行真漏洞）——必须为 0 条新增；
- **B：safe 被规则判 True**（规则层误报）——除 `disputed_truth.py`
  登记的已知争议外必须为 0 条新增。

## 提交信息格式

```text
<type>(<scope>): 一句话

- 回归段: 三套冒烟全过；HJS 58/59（+1 争议单列）；
  OWASP 规则层扫描 A/B 方向均无新增
- 其他要点（可选）
```

`type`：`feat` / `fix` / `bench` / `docs` / `refactor`。
没有回归段的提交会被 `commit-msg` 钩子拒收。

## 常用工具

- `benchmarks/diag_owasp_sqli_fp.py` / `diag_owasp_xpathi_fp.py`：
  误报样本逐条归因（打印值来源证据与当前判定）。
- `benchmarks/export_disputes.py --md / --json / --issues DIR`：
  导出争议清单与靶场 Issue 草稿。
- `benchmarks/check_stability.py`：引用单轮分数前先跑稳定性检查。
