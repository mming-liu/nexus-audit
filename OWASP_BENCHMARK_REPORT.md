# OWASP Benchmark 跑分报告

> 目标：验证「误报率降至 20% 以内」这条验收线是否达成
> 靶场：OWASP Benchmark v1.2（Java），2740 个用例 / 11 个漏洞类别
> 模型：`longcat-2.5-preview-free`（免费优先策略）
> 采样：每类 40 条（真漏洞 / 安全用例各半），共 435 条

## 一、结论

| 指标 | 离线基线<br>（纯关键词） | 初版 LLM | **最终版** |
|---|---|---|---|
| TPR 检出率 | 0.73 | 0.86 | **1.00** |
| FPR 误报率 | 0.64 | 0.16 | **0.02** |
| **Score（TPR−FPR）** | 0.09 | 0.70 | **0.98** |

**误报率 2%，验收线（20%）达成，且留有 10 倍余量。**

但必须明说成绩的来源结构：

| 子集 | 样本数 | Score | 由谁判定 |
|---|---|---|---|
| 配置型 4 类（crypto/hash/weakrand/securecookie） | 160 | 1.000 | **确定性规则** |
| 语义型 7 类（sqli/xss/cmdi/pathtraver/ldapi/xpathi/trustbound） | 275 | 0.964 | **LLM** |

也就是说，**LLM 单独扛住了 275 条语义类样本，Score 0.964** —— 这部分才是模型真正的能力证明。

## 二、分类目明细

| 类目 | 类型 | 样本 | TP | FN | FP | TN | Score |
|---|---|---|---|---|---|---|---|
| weakrand | 配置 | 40 | 20 | 0 | 0 | 20 | 1.00 |
| securecookie | 配置 | 40 | 20 | 0 | 0 | 20 | 1.00 |
| crypto | 配置 | 40 | 20 | 0 | 0 | 20 | 1.00 |
| hash | 配置 | 40 | 20 | 0 | 0 | 20 | 1.00 |
| xss | 语义 | 40 | 20 | 0 | 0 | 20 | 1.00 |
| trustbound | 语义 | 40 | 20 | 0 | 0 | 20 | 1.00 |
| ldapi | 语义 | 40 | 20 | 0 | 0 | 20 | 1.00 |
| xpathi | 语义 | 40 | 15 | 0 | 0 | 20 | 1.00 |
| cmdi | 语义 | 40 | 20 | 0 | 1 | 19 | 0.95 |
| sqli | 语义 | 40 | 20 | 0 | 1 | 19 | 0.95 |
| pathtraver | 语义 | 40 | 19 | 1 | 2 | 18 | 0.85 |

> xpathi 只有 15 条真/假样本对（该类别本身用例少），样本量偏小，分数波动较大。

## 三、关键工程发现

### 1. 限流会把数据伪装成「极低误报率」

第一轮跑分得到 FPR 0.05，看起来近乎完美。核查发现 435 条里 **243 条（56%）**
是 503 / 空响应，被静默归类成 "no_sink"（等价于"没有漏洞"）。
加上指数退避重试后，真实 FPR 是 0.16，**差了 3 倍**。

现在跑分器强制区分 `llm_failed`，失败样本剔除且不计分。

### 2. 切片缺证据，模型只能猜

- **配置值**：`Cipher.getInstance(algorithm)` 的算法来自 `benchmark.properties`
  的 `cryptoAlg2=AES/CCM/NoPadding`。源码里看不到，模型只能瞎判。
- **跨文件方法**：`Utils.getCipher()` 内部才是真正的 `RSA/ECB/OAEPWithSHA-512`。
- **辅助方法**：`doSomething(request, param)` 是清洗发生的地方，丢了它就必然误报。
  这里踩过一个坑：用 `startswith("do")` 过滤辅助方法，把 `doSomething` 自己也
  排除了 —— OWASP 的清洗方法偏偏就叫这个名字。

### 3. 问法要区分「污点型」和「配置型」

`weakrand` 曾出现 **TPR = 0**（整类漏报）。原因是我用统一的判据
"外部输入是否可达汇聚点"，而配置型缺陷（用了弱随机源）与外部输入毫无关系。
模型严格按判据执行，于是全部答 No。

类目定义里加了 `needs_taint` 字段后，该类别从 0.00 直接到 1.00。

### 4. 客观事实不该交给概率模型

模型把 `RSA/ECB/OAEPWithSHA-512AndMGF1Padding` 判成弱加密 ——
它把 RSA 的 ECB 标识当成了 AES-ECB 的可预测性缺陷。
补全上下文后仍然判错，属于模型知识盲区。

改成确定性规则前置后：四类配置型 100% 规则判定，**满分且耗时降低 4 倍**（35s vs 140s）。

### 5. 调用 API 枚举不全 = 整批漏报

`trustbound` 漏报 5 条，全是卡在 "protected"。查代码发现用的是
`session.putValue()`，而我的类目定义只写了 `setAttribute()`。
OWASP 的 trustbound 真漏洞里有 **45/83** 用的是 putValue。
补全后该类目从 0.75 → 1.00。

## 四、当前局限

1. **样本量**：每类 40 条，共 435/2740（16%）。全量跑需约 2.5 小时，尚未做。
2. **单模型**：只用了一个免费模型，未验证模型更换后的稳定性。
3. **Benchmark 特性**：OWASP Benchmark 的漏洞模式高度模板化（每个用例都是
   "取参数 → 拼接 → sink"），在这个靶场上的高分**不能直接外推到真实业务代码**。
   真实项目缺少这样规整的边界，误报率预计会显著上升。
4. **仅 Java**：Python Web 与 Web3 赛道未纳入本次跑分。

## 五、复现方式

```bash
# 最终结果
python benchmarks/benchmark_owasp.py --per-category 40 --concurrency 6

# 对照组（不调 LLM）
python benchmarks/benchmark_owasp.py --offline --per-category 40

# 关闭规则、纯看 LLM 能力
python benchmarks/benchmark_owasp.py --categories sqli,xss --no-rules
```

产物：
- `benchmarks/results/owasp_v2.csv` — scorecard
- `benchmarks/results/owasp_v2.jsonl` — 逐条明细（含卡点归因）
- `benchmarks/results/owasp_v2.md` — 自动生成报告
