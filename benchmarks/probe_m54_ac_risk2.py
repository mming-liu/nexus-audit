"""M54：access_control 七类新机制的**判反风险锚点**。

**方法论**：任何早退/放宽判据之前，先在 smartbugs **真阳单元**上跑一遍
该机制的命中数 —— 命中 0 条 ⇒ 加上去不会造成判反（真阳仍判 True）；
命中 >0 ⇒ 该机制与真阳冲突，必须换口径。

七类机制（M54 access_control 剩余 43 条误报的根因）：
  M1 super.X 委托      —— 父合约同名函数的实现体（allowance 扣减）
  M2 父合约 modifier    —— onlyOwner/onlyRole 的实现体在父合约
  M3 间接身份检查      —— require(比较一侧是"返回 msg.sender 的函数")
  M4 tx.origin 二分    —— 比较另一侧是不是 msg.sender
  M5 owner 局部变量    —— 局部声明 vs 状态写
  M6 allowance 拼写    —— allowance vs allowed
  M7 外部库调用        —— ContractOwnershipStorage.layout().xxx()
"""
from __future__ import annotations
import json, re, sys
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.slicer.web3_slither import SoliditySlicer
from core.agents.rule_detectors import _split_sol_sections

SB = ROOT / "reference_repos" / "smartbugs-curated-main"
meta = {Path(x["path"]).name: x
        for x in json.loads((SB / "vulnerabilities.json").read_text(encoding="utf-8"))}
slicer = SoliditySlicer(SB)
units = slicer.extract_entry_units(SB / "dataset" / "access_control")

truth_units = []
for u in units:
    entry = meta.get(Path(u.file_path).name)
    if not entry:
        continue
    vul = {l for v in entry["vulnerabilities"]
           if v["category"] == "access_control" for l in v["lines"]}
    if vul and any(u.start_line <= l <= u.end_line for l in vul):
        truth_units.append(u)

print("smartbugs access_control 真阳单元：%d 个\n" % len(truth_units))

# ---- M1：super.X 委托 ----
hit = Counter()
for u in truth_units:
    func_src, _m, _f = _split_sol_sections(u.source_code)
    for mm in re.finditer(r"\bsuper\s*\.\s*([A-Za-z_]\w*)\s*\(", func_src):
        hit[mm.group(1)] += 1
print("M1 super.X 委托          真阳命中 %d 条  %s"
      % (sum(hit.values()), dict(hit)))

# ---- M2：父合约 modifier（签名带 modifier 名但本合约无定义体）----
_MODKEY = {"external", "public", "internal", "private", "view", "pure",
           "payable", "constant", "returns", "virtual", "override", "function",
           "address", "uint", "uint256", "bool", "bytes", "bytes32", "bytes4",
           "bytes8", "bytes16", "bytes1", "bytes2", "bytes3", "bytes4",
           "string", "int", "int256", "mapping", "memory", "storage",
           "calldata", "event", "emit", "require", "revert"}
hit = Counter()
for u in truth_units:
    func_src, mod_ev, _f = _split_sol_sections(u.source_code)
    sig = func_src.split("{")[0]
    # 只取参数表 `)` **之后**的尾巴 = modifier / returns 部分
    tail = sig[sig.rfind(")") + 1:] if ")" in sig else ""
    named = {n for n in re.findall(r"\b([A-Za-z_]\w*)\b", tail)
             if n not in _MODKEY}
    local_mods = set(re.findall(r"\bmodifier\s+([A-Za-z_]\w*)", mod_ev))
    miss = named - local_mods
    if miss:
        hit[tuple(sorted(miss))] += 1
        print("   M2 命中[%s] 缺定义体的 modifier: %s" % (u.unit_name, sorted(miss)))
print("M2 父合约 modifier        真阳命中 %d 条  %s"
      % (sum(hit.values()), dict(hit)))

# ---- M3：间接身份检查（比较一侧是"返回 msg.sender 的函数"）----
_IDFN = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{[^}]*?"
                   r"\breturn\s+\(?\s*msg\s*\.\s*sender\s*\)?\s*;", re.S)
hit = 0
for u in truth_units:
    func_src, mod_ev, func_ev = _split_sol_sections(u.source_code)
    evid = func_src + "\n" + mod_ev + "\n" + func_ev
    idfns = {m.group(1) for m in _IDFN.finditer(evid)}
    if not idfns:
        continue
    own = func_src + "\n" + mod_ev
    for mm in re.finditer(r"(?:require|assert|if)\s*\([^;]{0,160}?\b"
                          r"([A-Za-z_]\w*)\s*\(\s*\)\s*(?:==|!=)", own):
        if mm.group(1) in idfns:
            hit += 1
            print("   M3 命中[%s]: %s" % (u.unit_name, mm.group(0)[:70]))
            break
print("M3 间接身份检查          真阳命中 %d 条" % hit)

# ---- M4：tx.origin 比较的另一侧 ----
hit = Counter()
for u in truth_units:
    func_src, _m, _f = _split_sol_sections(u.source_code)
    for mm in re.finditer(r"(?:require|if)\s*\([^;]{0,120}?\btx\s*\.\s*origin\s*=="
                          r"\s*([A-Za-z_][\w.]*)", func_src):
        hit[mm.group(1)] += 1
print("M4 tx.origin 另一侧       真阳命中 %d 条  %s"
      % (sum(hit.values()), dict(hit)))

# ---- M5：owner 局部变量声明形态 ----
_OWN = re.compile(r"\b(?:owner|creator|owner_|contract_owner|admin)\b"
                  r"(?:\s*\.\s*balance)?\s*(?<!=[=!<>])=(?!=)", re.I)
hit = Counter()
for u in truth_units:
    func_src, _m, _f = _split_sol_sections(u.source_code)
    for mm in _OWN.finditer(func_src):
        toks = re.findall(r"[A-Za-z_]\w*", func_src[:mm.start()])
        typ = toks[-1] if toks else ""
        hit[typ] += 1
print("M5 owner 写左侧 token     真阳命中 %d 条  %s"
      % (sum(hit.values()), dict(hit)))

# ---- M6：allowance 形态 ----
hit = Counter()
for u in truth_units:
    func_src, mod_ev, _f = _split_sol_sections(u.source_code)
    for mm in re.finditer(r"_?allow\w*\s*\[[^\]]*\]\s*\[[^\]]*\]\s*(?:-=|=)",
                          func_src + "\n" + mod_ev, re.I):
        hit[mm.group(0)] += 1
print("M6 allowance 槽位写       真阳命中 %d 条  %s"
      % (sum(hit.values()), dict(hit)))

# ---- M7：外部库/合约的限定调用（X.y() 形态的 owner 写）----
hit = 0
for u in truth_units:
    func_src, _m, _f = _split_sol_sections(u.source_code)
    if re.search(r"\b[A-Za-z_]\w*\s*\.\s*transferOwnership\s*\(", func_src):
        hit += 1
        print("   M7 命中[%s]" % u.unit_name)
print("M7 限定调用 transferOwnership 真阳命中 %d 条" % hit)

print("\n锚点结论：命中数必须全为 0（除 M4/M5/M6 这三条是『排除型』判据，"
      "它们的真阳形态已记录，用于确认排除逻辑不会误伤）。")
