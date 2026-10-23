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


# ---- Module 32：分片并行（ProcessPoolExecutor） ----
# 每个 chunk 自带（name, cat, is_vul, 源码），worker 无共享状态（Windows
# spawn 语义干净，也不必把整份 units dict pickle 给每个 initializer）。
# 汇总永远在主进程按 sorted(truth) 原序做 —— 输出与串行版**逐位一致**
# （A/B 名单顺序、逐类目计数、合计数都是纯聚合，与分片大小无关）。


def _eval_chunk(chunk: list[tuple[str, str, bool, str]]) -> list[tuple[str, str, bool, int]]:
    from core.agents import rule_detectors as R
    out = []
    for name, cat, is_vul, src in chunk:
        out.append((name, cat, is_vul, R.verdict(cat, src)))
    return out


def main() -> None:
    import argparse
    from concurrent.futures import ProcessPoolExecutor
    import time

    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 4,
                    help="并行 worker 数（默认 CPU 核数；1 = 串行）")
    args = ap.parse_args()

    t0 = time.monotonic()
    units = load_units(False, workers=args.workers)
    t_slice = time.monotonic() - t0
    truth = load_truth()

    # 原序任务表（与旧版逐条循环同一顺序）
    tasks: list[tuple[str, str, bool, str]] = []
    for name, (cat, is_vul) in sorted(truth.items()):
        hit = [k for k in units if name in k]
        if not hit:
            continue
        tasks.append((name, cat, is_vul, units[pick_unit(units, name)]))

    if args.workers > 1:
        batch = max(1, len(tasks) // (args.workers * 4) or 1)
        chunks = [tasks[i:i + batch] for i in range(0, len(tasks), batch)]
        with ProcessPoolExecutor(max_workers=args.workers) as ex:
            results = [row for ch in ex.map(_eval_chunk, chunks) for row in ch]
    else:
        results = _eval_chunk(tasks)

    fn_rule: list[tuple[str, str]] = []     # A) vul → False
    fp_rule: list[tuple[str, str]] = []     # B) safe → True
    per_cat: dict[str, list[int]] = {}
    resolved = 0

    for name, cat, is_vul, verdict in results:
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

    print(f"（--workers {args.workers}，切片+verdict 共 "
          f"{time.monotonic() - t0:.1f}s，其中切片 {t_slice:.1f}s）")
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
