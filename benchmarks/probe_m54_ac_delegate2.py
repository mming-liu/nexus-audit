"""M54：access_control "委托形态"早退的**判反风险锚点**。

拟新增早退（规则层）：
  `from` 的实际转出被**委托**给本切片**看不见**的实现时
  —— ① `super.transferFrom(...)`（父合约委托，且切片没拿到父实现体）；
  —— ② `X.transferFrom(...)`（外部合约/接口转发）；
  按"缺证退 None"铁律，**不判 True**（退 None 交模型）。

**关键区分**：本地辅助函数形态 `_transfer(from, ...)` **不是**委托 ——
它是真阳形态（DeFiVulnLabs NFT-transfer.sol 的 VulnerableERC721），
绝不能退。

本锚点要回答：
  A. smartbugs access_control 真阳里有没有 ①/② 形态？（有 ⇒ 判反）
  B. DeFiVulnLabs NFT-transfer.sol 的两条真值现在判什么？
     （74 行须 True、92 行须 False）
  C. Top200 的 4 条误报是否都落在 ①/② 形态？
"""
from __future__ import annotations
import json, re, sys
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.slicer.web3_slither import SoliditySlicer
from core.agents.rule_detectors import _split_sol_sections, verdict as rule_verdict

SB = ROOT / "reference_repos" / "smartbugs-curated-main"
meta = {Path(x["path"]).name: x
        for x in json.loads((SB / "vulnerabilities.json").read_text(encoding="utf-8"))}
slicer = SoliditySlicer(SB)
units = slicer.extract_entry_units(SB / "dataset" / "access_control")

SUPER_FROM = re.compile(r"\bsuper\s*\.\s*(?:transferFrom|_transfer|_safeTransfer)"
                         r"\s*\(\s*_?from\b")
EXT_FROM = re.compile(r"\b[A-Za-z_]\w*\s*\.\s*(?:transferFrom|_transfer|_safeTransfer)"
                       r"\s*\(\s*_?from\b")
LOCAL_FROM = re.compile(r"(?<![.\w])(?:_?transferFrom|_transfer|_safeTransfer)"
                         r"\s*\(\s*_?from\b")


def classify(func_src: str, evid: str) -> str:
    """返回委托形态分类。"""
    if SUPER_FROM.search(func_src):
        # super 委托：若证据段里**没有**父实现体 ⇒ 缺证
        has_impl = bool(re.search(r"function\s+(?:transferFrom|_transfer)\s*\(",
                                   evid))
        return "super_missing_impl" if not has_impl else "super_with_impl"
    if EXT_FROM.search(func_src):
        return "external"
    if LOCAL_FROM.search(func_src):
        return "local"
    return "none"


print("=== A. smartbugs access_control 真阳的 from 形态 ===")
cnt = Counter()
for u in units:
    entry = meta.get(Path(u.file_path).name)
    if not entry:
        continue
    vul = {l for v in entry["vulnerabilities"]
           if v["category"] == "access_control" for l in v["lines"]}
    if not vul or not any(u.start_line <= l <= u.end_line for l in vul):
        continue
    f, m, fe = _split_sol_sections(u.source_code)
    if not re.search(r"address\s+(?:payable\s+)?_?from\b", f):
        continue
    cnt[classify(f, f + "\n" + m + "\n" + fe)] += 1
    print("   %-40s %s" % (Path(u.file_path).name, classify(f, f + "\n" + m + "\n" + fe)))
print("   汇总:", dict(cnt))
print()

print("=== B. DeFiVulnLabs NFT-transfer.sol 两条真值 ===")
DV = ROOT / "reference_repos" / "DeFiVulnLabs-main"
dv_slicer = SoliditySlicer(DV)
for u in dv_slicer.extract_entry_units(DV):
    if u.unit_name != "transferFrom":
        continue
    if "NFT-transfer" not in str(u.file_path):
        continue
    f, m, fe = _split_sol_sections(u.source_code)
    rv = rule_verdict("access_control", u.source_code)
    kind = classify(f, f + "\n" + m + "\n" + fe)
    print("   行 %-4d %-22s 判定=%-5s 形态=%s"
          % (u.start_line, u.unit_name, str(rv), kind))
print()

print("=== C. Top200 剩余 4 条的形态 ===")
from benchmarks.slice_cache import cached_units
GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
gp = cached_units(GP, "gptscan-top200", lambda: SoliditySlicer(GP).extract_entry_units(GP))
for u in gp:
    if rule_verdict("access_control", u.source_code) is not True:
        continue
    f, m, fe = _split_sol_sections(u.source_code)
    if not re.search(r"address\s+(?:payable\s+)?_?from\b", f):
        print("   %-30s %-24s 形态=%s (非 from 形参)"
              % (Path(u.file_path).name, u.unit_name,
                 classify(f, f + "\n" + m + "\n" + fe)))
        continue
    print("   %-30s %-24s 形态=%s"
          % (Path(u.file_path).name, u.unit_name,
             classify(f, f + "\n" + m + "\n" + fe)))
