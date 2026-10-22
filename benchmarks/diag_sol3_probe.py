# -*- coding: utf-8 -*-
"""M30 探针：tx.origin / unchecked low-level call / arbitrary transferFrom 样本分布"""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
repos = ["smartbugs-curated-main", "DeFiVulnLabs-main", "not-so-smart-contracts-master"]
for r in repos:
    base = ROOT / "reference_repos" / r
    print(f"\n########## {r}")
    if not base.exists():
        print("  不存在"); continue
    for cat, pat in [
        ("txorigin", re.compile(r"tx\.origin")),
        ("unchecked", re.compile(r"\.\s*call\s*\{|\.call\s*\.\s*value\s*\(|\.send\s*\(")),
        ("transferFrom", re.compile(r"transferFrom\s*\(")),
    ]:
        files = sorted(base.rglob("*.sol"))
        hits = []
        for f in files:
            try:
                t = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if pat.search(t):
                hits.append(f.relative_to(base))
        print(f"[{cat}] {len(hits)} 文件")
        for h in hits[:14]:
            print("   ", h)
