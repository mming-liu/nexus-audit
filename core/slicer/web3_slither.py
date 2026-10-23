"""GPTScan 式 Web3 静态候选过滤器（第2周后半，零依赖正则实现）。

当前实现能力（对标 Damn Vulnerable DeFi 已知真实缺陷回归）：
  1. Solidity 函数切片：提取带 external/public 的状态修改函数为 CodeUnit
  2. 精度/优先级缺陷启发式（scenario=precision_loss）：
     `a - b * C` 未加括号的减乘混排，且参与除法运算——
     对应真实案例：puppet-v2/UniswapV2Library.sol:78
     `reserveOut - amountOut * 997`（应为 (reserveOut - amountOut) * 997），
     该缺陷由 issue #114 与 #105 两度报告仍未修复。

Slither 集成保留为升级点（slither 可用时用其调用图替换正则切片）。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from core.models import CodeUnit, Language, VulnHypothesis

FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)[^{;]*?(?:external|public|internal|private)?[^{;]*?(\{)", re.S)

# 减乘混排未加括号：a - b * C （且 b*C 紧邻 - 之后）， fee 常数特征 997/9970/970/3
#
# 结尾**不能**要求分号：真实写法里这个表达式通常是除法分母的一部分，
# 形如 `amountIn - amountIn * 997 / 1000 / 9970`，`997` 后面跟的是 `/` 或换行，
# 永远等不到 `;`。早期版本写了 `\s*;`，导致整个正则恒不匹配，
# `prop_ok` 恒为 None、置信度恒为 0.6，三个真漏洞被渲染成"未复现"。
# 现在的收尾是"后面不是数字或标识符"——足以界定常数边界，又不限制后续运算。
PRECEDENCE_RE = re.compile(
    r"(\w+)\s*-\s*(\w+)\s*\*\s*(\d+)(?![\w.])")

FEE_CONSTANTS = {"997", "9970", "970", "1000", "10000", "3"}


class SoliditySlicer:
    language = "solidity_web3"

    def __init__(self, repo_path: str | Path | None = None):
        self.repo_path = repo_path
    def extract_entry_units(self, repo_path: str | Path) -> List[CodeUnit]:
        repo = Path(repo_path)
        units: List[CodeUnit] = []
        # Module 39：仓库级合约索引（两阶段切片的前提）。跨文件父合约的
        # modifier 实现体只有先扫全库才知道在哪 —— `contract X is Ownable`
        # 的 Ownable 可能在同文件，也可能在 import 的另一个 .sol 里。
        parent_index = self._build_parent_index(repo)
        for sol in repo.rglob("*.sol"):
            if any(p in self.IGNORE for p in sol.parts):
                continue
            try:
                text = sol.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            # 合约边界：`contract X ... {` 到配平 `}`。函数归属哪个合约、
            # "函数名 != 合约名"（错名构造函数）的判定都需要它。
            contract_spans: list[tuple[int, int, str]] = []
            for cm in re.finditer(r"\bcontract\s+([A-Za-z_]\w*)[^{]*\{", text):
                depth = 0
                start = cm.end() - 1
                for idx in range(start, len(text)):
                    if text[idx] == "{":
                        depth += 1
                    elif text[idx] == "}":
                        depth -= 1
                        if depth == 0:
                            contract_spans.append(
                                (cm.start(), idx, cm.group(1)))
                            break
            # 修饰符定义体：`modifier xxx(...) { ... _; ... }`。
            # 权限判定铁律是"看实现体不看名字"—— onlyowner 名字防不了
            # 空实现，必须把 body 拼进切片让规则核验 msg.sender 检查。
            mod_spans: list[tuple[int, int, str, str]] = []
            # modifier 可以无参（rubixi 的 `modifier onlyowner {`）——
            # 括号组必须可选，否则整类权限修饰符静默进不了切片。
            for mm in re.finditer(r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*[^{;]*\{", text):
                depth = 0
                for idx in range(mm.end() - 1, len(text)):
                    if text[idx] == "{":
                        depth += 1
                    elif text[idx] == "}":
                        depth -= 1
                        if depth == 0:
                            mod_spans.append((mm.start(), idx, mm.group(1),
                                              mm.group(0) + text[mm.end():idx]))
                            break
            for m in FUNC_RE.finditer(text):
                name = m.group(1)
                start_line = text[:m.start()].count("\n") + 1
                # 花括号配平找函数结束行（group(2) 是开头大括号）
                depth = 0
                end_line = start_line
                for idx in range(m.start(2), len(text)):
                    if text[idx] == "{":
                        depth += 1
                    elif text[idx] == "}":
                        depth -= 1
                        if depth == 0:
                            end_line = text[:idx].count("\n") + 1
                            break
                src = "\n".join(lines[start_line - 1: end_line])
                vis = m.group(0)
                visibility = next((v for v in ("external", "public", "internal", "private")
                                   if re.search(rf"\b{v}\b", vis)), "default")
                mods = [f"modifier:{n}" for n in
                        re.findall(r"\b([A-Za-z_]\w*)\s*(?:\([^()]*\))?(?=[^()]*\{)",
                                   vis[vis.find(")") + 1:] if ")" in vis else "")
                        if n not in {"public", "external", "internal", "private",
                                     "view", "pure", "payable", "constant", "returns"}
                        and re.search(rf"\b{n}\b", vis)]
                # 所属合约：函数起点落在哪个合约 span 里
                contract = next((c for s, e, c in contract_spans
                                 if s <= m.start() <= e), "")
                mods.append(f"contract:{contract}" if contract else "contract:?")

                # 本函数签名用到的修饰符定义体拼进切片（可被规则核验）
                used = set(re.findall(r"\b([A-Za-z_]\w*)\b", vis))
                extra = [seg for _ms, _me, mname, seg in mod_spans
                         if mname in used]
                # Module 39：签名用了 modifier 但**本合约没有定义** ——
                # 只能来自父合约（`contract X is Ownable` 的 onlyOwner）。
                # 沿继承链到父合约文件里抓实现体贴进证据段，铁律 17
                # "看实现体不看名字"才能跨文件成立；抓不到就保持缺证，
                # 判定层按缺证退 None（不许只凭名字判安全）。
                local_mods = {mname for _s, _e, mname, _g in mod_spans}
                missing = [n for n in used if n not in local_mods]
                if missing and contract:
                    inherited = self._inherited_mods(contract, missing,
                                                     parent_index)
                    if inherited:
                        extra.append(
                            "// ---- 父合约继承证据 ["
                            + ", ".join(f"{c}.{n}" for c, n, _s in inherited)
                            + "] ----\n"
                            + "\n".join(seg for _c, _n, seg in inherited))
                # 合约名写进切片首行注释：函数级切片没有文件头，
                # "函数名 == 合约名 → 构造函数"的判定只能靠它。
                src = f"// contract: {contract or '?'}\n" + src
                if extra:
                    # 只有「本合约」modifier 段才用本合约段头；继承证据
                    # 段自带 `// ---- 父合约继承证据 [...] ----` 段头，
                    # 空的本合约头会误导核验（Module 39 实测空段头）。
                    local = [s for s in extra if not s.startswith("// ---- 父合约")]
                    inh = [s for s in extra if s.startswith("// ---- 父合约")]
                    parts = []
                    if local:
                        parts.append("// ---- 修饰符定义（本合约，供核验）----\n"
                                     + "\n".join(local))
                    parts.extend(inh)
                    src = src + "\n" + "\n".join(parts)
                units.append(CodeUnit(
                    file_path=str(sol), language=Language.SOLIDITY_WEB3,
                    unit_name=name, start_line=start_line, end_line=end_line,
                    decorators_or_modifiers=[visibility, *mods],
                    called_symbols=self._calls(src), source_code=src))
        return units

    IGNORE = {"node_modules", "lib", "test/helpers"}

    # ---- Module 39：跨文件父合约继承索引 ----

    def _build_parent_index(self, repo: Path) -> dict:
        """扫全库 .sol：合约名 → (is 继承列表, {modifier名: 实现体})。

        只做正则级事实提取（合约头 is 子句 + modifier 括号配平体），
        与 extract_entry_units 的本文件解析同正则口径，两遍结果一致。
        索引失败静默降级为空 —— 继承证据是增强项，不能拖垮切片。
        """
        idx: dict[str, tuple[list[str], dict[str, str]]] = {}
        try:
            for sol in repo.rglob("*.sol"):
                if any(p in self.IGNORE for p in sol.parts):
                    continue
                try:
                    text = sol.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                mods: dict[str, str] = {}
                for mm in re.finditer(
                        r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*[^{;]*\{",
                        text):
                    depth = 0
                    for i2 in range(mm.end() - 1, len(text)):
                        if text[i2] == "{":
                            depth += 1
                        elif text[i2] == "}":
                            depth -= 1
                            if depth == 0:
                                mods[mm.group(1)] = mm.group(0) + text[mm.end():i2]
                                break
                for cm in re.finditer(
                        r"\bcontract\s+([A-Za-z_]\w*)\s*(?:is\s+([\w\s,.\-]+))?\s*\{",
                        text):
                    bases = [b.strip() for b in (cm.group(2) or "").split(",")
                             if b.strip()]
                    idx[cm.group(1)] = (bases, mods)
        except Exception:
            return {}
        return idx

    def _inherited_mods(self, contract: str, missing: list[str],
                        idx: dict, _seen: set | None = None
                        ) -> list[tuple[str, str, str]]:
        """沿 is 继承链（BFS，防环）抓父合约里缺失 modifier 的实现体。
        返回 [(父合约名, modifier名, 实现体)]。"""
        if _seen is None:
            _seen = set()
        if contract in _seen or contract not in idx:
            return []
        _seen.add(contract)
        bases, mods = idx[contract]
        out: list[tuple[str, str, str]] = []
        want = set(missing)
        for n in want:
            if n in mods:
                out.append((contract, n, mods[n]))
        rest = want - {n for _, n, _ in out}
        if rest:
            for b in bases:
                out.extend(self._inherited_mods(b, sorted(rest), idx, _seen))
        return out

    @staticmethod
    def _calls(src: str) -> list[str]:
        return sorted({m.group(1) for m in re.finditer(r"(\w+)\s*\(", src)
                       if m.group(1) not in {"if", "for", "while", "require", "return"}})


def detect_reentrancy_surface(units: List[CodeUnit]) -> List[VulnHypothesis]:
    """场景：闪电贷函数向 msg.sender 发起带 ETH 的外部调用，仅靠余额差值校验还款。
    对标：side-entrance/SideEntranceLenderPool.flashLoan（可重入存入记账）。"""
    hyps = []
    for u in units:
        if "flashLoan" not in u.unit_name and "flashloan" not in u.unit_name.lower():
            continue
        src = u.source_code
        if re.search(r"\.\w+\{value:", src) or "call{value:" in src:
            has_state_guard = re.search(r"nonReentrant|locked|entered", src)
            hyps.append(VulnHypothesis(
                unit=u, vuln_type="reentrancy_surface", scenario_hit=True,
                property_missing="外部调用目标为 msg.sender 且无重入锁；"
                                 "回调期间可通过 deposit 记账绕过余额差校验",
                reasoning_summary="flashLoan 内 msg.sender 外部调用 @ 函数级检测",
                confidence=0.7 if not has_state_guard else 0.4))
    return hyps


def detect_arbitrary_call(units: List[CodeUnit]) -> List[VulnHypothesis]:
    """场景：放贷/提款函数以调用方提供的 target+calldata 执行任意外部调用。
    对标：truster/TrusterLenderPool.flashLoan（target.functionCall(data) 可批准劫持）。"""
    hyps = []
    for u in units:
        src = u.source_code
        for m in re.finditer(r"(\w+)\.functionCall\((\w+)\)", src):
            target, data = m.group(1), m.group(2)
            params_in_sig = target in u.source_code.split("{")[0] and data in u.source_code.split("{")[0]
            if params_in_sig:
                hyps.append(VulnHypothesis(
                    unit=u, vuln_type="arbitrary_external_call", scenario_hit=True,
                    property_missing=f"外部调用目标 ({target}) 与 calldata ({data}) 均为调用方参数，"
                                     "且还款仅靠余额差校验——可借 approve 劫持代币",
                    reasoning_summary=f"target.functionCall(data) gadget @ {u.unit_name}",
                    confidence=0.8))
                break
    return hyps


def detect_missing_receive(units: List[CodeUnit], repo_path: str | Path) -> List[VulnHypothesis]:
    """场景：合约处理 ETH 存取/闪电贷，但整个合约无 receive()/payable fallback。
    对标：issue #104 —— SideEntranceLenderPool 无法通过普通转账接收 ETH。"""
    hyps = []
    by_file: dict[str, list[CodeUnit]] = {}
    for u in units:
        by_file.setdefault(u.file_path, []).append(u)
    for file, us in by_file.items():
        try:
            text = Path(file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(r"receive\s*\(\s*\)|fallback\s*\(", text):
            continue
        # 收窄（对齐 issue #104 本质）：非 payable 函数中读取 address(this).balance，
        # 说明合约依赖"直接转 ETH 进来"但根本没有 receive() 通道
        hits = [u for u in us
                if "address(this).balance" in u.source_code
                and not re.search(r"\bpayable\b", u.source_code)]
        if hits:
            main = hits[0]
            hyps.append(VulnHypothesis(
                unit=main, vuln_type="missing_payable_receiver", scenario_hit=True,
                property_missing="非 payable 函数中读取 address(this).balance，但合约未定义 "
                                 "receive()/fallback——外部无法直接向合约注资，"
                                 "只能靠 payable 入口内转（可能正是重入面）",
                reasoning_summary=f"issue #104 同型缺陷 @ {Path(file).name}",
                confidence=0.75))
    return hyps


def detect_precision_loss(units: List[CodeUnit]) -> List[VulnHypothesis]:
    """GPTScan 两步法（Web3 场景，离线启发式版）：

    Step 1 Scenario: 函数是否计算代币兑换/输入金额（出现 fee 常数或 reserve 变量）？
    Step 2 Property: 金额公式中 `减法-乘法` 混排是否有括号保证优先级？
    """
    hyps: List[VulnHypothesis] = []
    for u in units:
        src = u.source_code
        scenario_hit = ("997" in src or "reserve" in src.lower()
                        or "amountIn" in src or "amountOut" in src)
        if not scenario_hit:
            continue
        for m in PRECEDENCE_RE.finditer(src):
            lhs, sub, const = m.group(1), m.group(2), m.group(3)
            if const not in FEE_CONSTANTS:
                continue
            line = src[:m.start()].count("\n") + 1
            # 属性核对：该表达式是否作为除法（或除法链）的被除数，决定误差是否被放大。
            # 直接看匹配结束位置之后的字符，不再用 rstrip(";") 拼正则 —— 那个写法
            # 依赖原表达式带分号，正是早期恒不命中 prop_ok 的根因。
            tail = src[m.end(): m.end() + 20]
            prop_ok = bool(re.match(r"\s*/\s*[\w(]", tail))
            line_abs = u.start_line + src[:m.start()].count("\n")  # 换算为文件绝对行号
            hyps.append(VulnHypothesis(
                unit=u, vuln_type="precision_loss", scenario_hit=True,
                property_missing=(f"`{lhs} - {sub} * {const}` 未加括号，实际求值为 "
                                  f"`{lhs} - ({sub} * {const})`；"
                                  + ("该表达式参与除法，误差被放大" if prop_ok else "需人工确认用途")),
                reasoning_summary=f"UniswapV2Library 风格减乘混排 @ 文件第 {line_abs} 行",
                confidence=0.85 if prop_ok else 0.6))
            break
    return hyps
