"""OWASP 规则层全类目回归（只跑规则层，不调模型）。

用途：任何触碰 `_resolve_rhs_origin` / `_value_origin` / 各 verdict 的改动，
都要过这个扫描。管线语义：规则 True → 直接 flag；False → 直接不 flag；
None → 交给 sink 检查与模型。所以两个危险方向是：
  A) vul 样本规则判 False —— 静默放行真漏洞（比误报危险）
  B) safe 样本规则判 True —— 规则层误报
两个数字都必须与上一轮的基线一致：

  A) **0 条** —— 真漏洞被规则判 safe 是静默放行，任何一条都必须逐条解释。
  B) **0 条** —— 规则层误报。

2026-10-20 基线（全量 2740 样本，修正前 → 修正后）：

    A) 15 条（全 xss）→ 0    B) 41 条（sqli 19 / pathtraver 11 / xpathi 11）→ 0

修正前的 30 条/类抽样池把这些全盖住了 —— "规则层仅 1 条错判"只对抽样池
成立。**引用任何 OWASP 分数都要说清分母是抽样池还是全量。**

用法：
    python benchmarks/regress_owasp_rules.py
"""
from __future__ import annotations

import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from benchmarks.diag_owasp_sqli_fp import load_units, pick_unit   # noqa: E402
from core.agents import rule_detectors as R            # noqa: E402

REPO = os.path.join(ROOT, "reference_repos", "BenchmarkJava-master")

# 真值存疑、登记在 disputed_truth.py 的样本：safe 被判 True 允许
KNOWN_DISPUTED_SAFE_TRUE = {"BenchmarkTest01807"}


def load_truth() -> dict[str, tuple[str, bool]]:
    truth = {}
    path = os.path.join(REPO, "expectedresults-1.2.csv")
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.reader(line for line in f if not line.startswith("#")):
            if len(row) >= 3:
                truth[row[0].strip()] = (row[1].strip(), row[2].strip() == "true")
    return truth


def main() -> None:
    units = load_units(False)
    truth = load_truth()

    fn_rule: list[tuple[str, str]] = []     # A) vul → False
    fp_rule: list[tuple[str, str]] = []     # B) safe → True
    per_cat: dict[str, list[int]] = {}
    resolved = 0

    for name, (cat, is_vul) in sorted(truth.items()):
        hit = [k for k in units if name in k]
        if not hit:
            continue
        # 同一个用例类里有 doGet + doPost 两个入口，必须**锁定 doPost**：
        # 真值标注的就是 doPost 那条链路（doGet 通常只是转发/页面壳）。
        #
        # 这里原来写 `units[hit[0]]`，靠 dict 的插入顺序偶然拿到 doPost
        # （旧切片器按方法体长度倒序收集，doPost 更长所以排前面）。切片器
        # 改成按源码顺序输出后 doGet 排到了前面，A 方向凭空冒出 264 条
        # "静默放行" —— 全是量错对象造成的**假回归**。
        # 结论：凡"用 `in` 找入口"的地方都要写清命中的是哪一条（本文件
        # 第 34 条经验的又一次现形）。
        src = units[pick_unit(units, name)]
        verdict = R.verdict(cat, src)
        c = per_cat.setdefault(cat, [0, 0, 0, 0])   # [vul_t, vul_none, safe_f, safe_true]
        if is_vul:
            if verdict is False:
                fn_rule.append((name, cat))
            elif verdict is True:
                c[0] += 1
                resolved += 1
            else:
                c[1] += 1
        else:
            if verdict is True:
                fp_rule.append((name, cat))
            elif verdict is False:
                c[2] += 1
                resolved += 1
            else:
                pass

    print("=== 危险方向 A：vul 被规则判 False（静默放行） ===")
    for name, cat in fn_rule:
        print(f"  {name}  {cat}")
    print(f"  共 {len(fn_rule)} 条\n")

    print("=== 危险方向 B：safe 被规则判 True（规则层误报） ===")
    for name, cat in fp_rule:
        note = "  [已知争议，disputed_truth.py]" if name in KNOWN_DISPUTED_SAFE_TRUE else "  <<<< 新增"
        print(f"  {name}  {cat}{note}")
    n_new = sum(1 for n, _ in fp_rule if n not in KNOWN_DISPUTED_SAFE_TRUE)
    print(f"  共 {len(fp_rule)} 条，其中新增 {n_new} 条\n")

    print("=== 规则层确定性判定数（True/False，None 交给模型） ===")
    for cat in sorted(per_cat):
        v_t, v_n, s_f, _ = per_cat[cat]
        print(f"  {cat:14} vul→True {v_t:3}   vul→None {v_n:3}   safe→False {s_f:3}")
    print(f"  规则层合计判定 {resolved} 条")


if __name__ == "__main__":
    main()
