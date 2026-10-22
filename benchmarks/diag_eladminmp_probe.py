# -*- coding: utf-8 -*-
"""M29 探针：eladmin-mp 零改动切片 + 规则判定分布"""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import verdict as rule_verdict
from core.slicer.java_servlet import JavaSlicer

repo = ROOT / "reference_repos" / "eladmin-mp-master"
units = JavaSlicer(repo).extract_entry_units()
print(f"切出入口 {len(units)} 个")
cats = ("sqli", "authz", "pathtraver", "xss", "cmdi", "deserial", "ssrf", "xxe")
dist = {c: {"T": 0, "F": 0, "N": 0} for c in cats}
hop_cross = 0
for u in units:
    src = u.source_code or ""
    i = src.find("[Hop 1]")
    if i >= 0 and "eladmin-mp-master" in src[i:i+220] and "me.zhengjie" in src[i:i+300]:
        pass
    for c in cats:
        rv = rule_verdict(c, src)
        dist[c][{True: "T", False: "F", None: "N"}[rv]] += 1
print(f"{'cat':12} True False None")
for c, d in dist.items():
    print(f"{c:12} {d['T']:4} {d['F']:5} {d['N']:4}")
# 看看入口样例
for u in units[:6]:
    print(" -", Path(u.file_path).name, u.unit_name)
# 关键形态统计
all_src = "\n".join(u.source_code or "" for u in units)
print("含 .apply( 拼接的单元:",
      sum(1 for u in units if ".apply(" in (u.source_code or "")))
print("含 .last( 的单元:",
      sum(1 for u in units if re.search(r"\.last\s*\(", u.source_code or "")))
print("含 @PreAuthorize @el.check 的单元:",
      sum(1 for u in units if "@el.check" in (u.source_code or "")))
print("含 @AnonymousAccess 的单元:",
      sum(1 for u in units if "@AnonymousAccess" in (u.source_code or "")))
