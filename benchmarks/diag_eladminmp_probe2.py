# -*- coding: utf-8 -*-
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import verdict as rule_verdict
from core.slicer.java_servlet import JavaSlicer
repo = ROOT / "reference_repos" / "eladmin-mp-master"
units = JavaSlicer(repo).extract_entry_units()
wrapper_re = re.compile(r"\.(?:eq|ne|like|in|between|gt|ge|lt|le|orderBy\w*)\s*\(")
for u in units:
    src = u.source_code or ""
    for cat in ("authz", "pathtraver"):
        if rule_verdict(cat, src) is True:
            print(f"[{cat} TRUE] {Path(u.file_path).name}:{u.unit_name}"
                  f"  el.check={'@el.check' in src} anon={'@AnonymousAccess' in src}")
            print("   " + " | ".join(l.strip() for l in src.splitlines() if l.strip())[:220])
# sqli None 且含 Wrapper 调用的单元数
wn = sum(1 for u in units if rule_verdict("sqli", u.source_code or "") is None
         and wrapper_re.search(u.source_code or ""))
print("sqli=None 且含 Wrapper 条件构造器调用的单元:", wn)
