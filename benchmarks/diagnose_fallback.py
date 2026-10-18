"""退回样本诊断：规则为什么把这一条交给了模型？

## 为什么需要这个脚本

"退回率 50%" 是个没信息量的数字。同样是 None，可能来自完全不同的原因：

  a. 类目判据写窄了（如 spel 只认受限 Context，不认输入白名单）→ 该修规则
  b. sink 枚举漏了一个 API（如 ObjectInputStream.readUnshared）→ 该修规则
  c. 证据在切片外（跨文件实现、框架装配）→ 该修切片
  d. 靶场真值与安全事实不符 → 不该改引擎，该改真值

把 a/b/c/d 混在一起报"模型侧 FPR 57%"，等于让模型背规则的锅。
本脚本对每条退回样本打印入口签名、入口体里出现的 sink 候选、以及
`has_external_input()` 的判定，供人工归因。

用法：
    python benchmarks/diagnose_fallback.py              # 全部退回样本
    python benchmarks/diagnose_fallback.py --cat spel   # 只看某类
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as RD                       # noqa: E402
from core.agents.rule_detectors import verdict as rule_verdict     # noqa: E402
from core.slicer.java_servlet import JavaSlicer                     # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "Hello-Java-Sec-master"

sys.path.insert(0, str(ROOT / "benchmarks"))
from benchmark_hellojavasec import classify, route_of              # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--cat", default="", help="只诊断某个类目")
    ap.add_argument("--full", action="store_true", help="打印完整入口体")
    args = ap.parse_args()

    units = JavaSlicer(Path(args.target)).extract_entry_units()
    rows = []
    for u in units:
        cat, truth, src = classify(u)
        if not cat or truth is None:
            continue
        if rule_verdict(cat, u.source_code) is not None:
            continue
        if args.cat and cat != args.cat:
            continue
        rows.append((u, cat, truth, src))

    print(f"退回样本 {len(rows)} 条\n" + "=" * 78)
    for u, cat, truth, src in rows:
        body = RD.entry_body(u.source_code)
        sig = RD._entry_signature(body) if body else ""
        ext = RD.has_external_input(u.source_code) if hasattr(RD, "has_external_input") else None
        print(f"\n[{cat}] {u.unit_name}  真值={truth}  来源={src}  route={route_of(u)}")
        print(f"  签名({sig.strip()[:70]})")
        print(f"  has_external_input={ext}")
        print(f"  切片 {len(u.source_code.splitlines())} 行 / 入口体 {len(body.splitlines())} 行")
        if args.full:
            print("  ---- 入口体 ----")
            for ln in body.splitlines():
                print("   " + ln.rstrip())
        else:
            for ln in body.splitlines():
                s = ln.strip()
                if not s:
                    continue
                line = "   " + s[:110]
                print(line)
        # 证据段概览：漏了哪一段，模型就只能猜
        secs = [ln.strip() for ln in u.source_code.splitlines()
                if ln.strip().startswith("// ----")]
        if secs:
            print("  证据段：" + " | ".join(s.strip("- /") for s in secs))


if __name__ == "__main__":
    main()
