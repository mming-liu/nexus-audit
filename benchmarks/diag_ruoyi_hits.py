# -*- coding: utf-8 -*-
"""M28 探针：逐条打印 RuoYi 无注解 authz=True / sqli=True / pathtraver=True 命中切片"""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import verdict as rule_verdict
from core.slicer.java_servlet import JavaSlicer

repo = ROOT / "reference_repos" / "RuoYi-master"
units = JavaSlicer(repo).extract_entry_units()
hits = []
for u in units:
    src = u.source_code or ""
    ann = "@RequiresPermissions" in src
    for cat in ("authz", "sqli", "pathtraver"):
        rv = rule_verdict(cat, src)
        if rv is True and not (cat == "authz" and ann):
            hits.append((cat, u))
print(f"探针命中 {len(hits)} 条")
for i, (cat, u) in enumerate(hits, 1):
    src = u.source_code or ""
    head = [l for l in src.splitlines() if l.strip()][:14]
    print(f"\n===== [{i}] {cat} {Path(u.file_path).name}:{u.unit_name} =====")
    print("\n".join(head))
