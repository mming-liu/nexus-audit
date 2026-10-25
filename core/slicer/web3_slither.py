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

# Solidity 内建/语言关键字/常见 ERC20 接口名 —— 这些不是"本合约定义的
# 函数"，不该去父合约里找实现体（M54 拼父合约函数证据时排除）。
_SOLIDITY_BUILTINS = frozenset({
    "if", "for", "while", "require", "assert", "revert", "throw", "return",
    "returns", "emit", "new", "delete", "function", "modifier", "constructor",
    "abi", "address", "bool", "string", "bytes", "byte", "uint", "uint256",
    "int", "int256", "var", "mapping", "payable", "memory", "storage",
    "calldata", "public", "private", "internal", "external", "view", "pure",
    "constant", "keccak256", "sha256", "sha3", "now", "block", "msg", "tx",
    "this", "super", "true", "false", "assembly", "unchecked",
    "transfer", "send", "call", "balance", "transferOwnership", "selfdestruct",
    "suicide", "delegatecall", "ecrecover", "gasleft", "blockhash",
    "type", "using", "library", "interface", "contract", "struct", "enum",
    "event", "fallback", "receive", "try", "catch", "let", "constant",
})

FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)[^{;]*?(?:external|public|internal|private)?[^{;]*?(\{)", re.S)

# 注释剥离（行注释 + 块注释），用于**等长空白**替换 —— 保偏移量，
# 行号行数都不变（切片的 start_line/end_line 依赖它）。
_SOL_STRIP_COMMENTS_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def _sol_blank_keep_lines(m: re.Match) -> str:
    """把一段注释替换成**等长且保行**的空白。

    换行符原样保留（行号不变），其余字符替成空格（字符偏移量不变）。
    """
    return "".join("\n" if ch == "\n" else " " for ch in m.group(0))


def _sol_project_key(sol: Path, repo: Path) -> str:
    """文件的"项目标识" —— 用于同名合约的分桶（M54）。

    口径：相对 repo 的路径里，**第一层目录名**就是项目名（Top200 的
    `0x<addr>_<chain>/`；普通单项目仓则是文件名本身）。
    同一项目里的 vendored 依赖（openzeppelin/...）与主合约共享标识 ——
    它们本就是同一份依赖树。
    """
    try:
        rel = sol.relative_to(repo)
    except ValueError:
        return sol.stem
    parts = rel.parts
    if len(parts) >= 2:
        return parts[0]
    return rel.stem

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
            if sol.name.endswith(self.TEST_SUFFIXES):
                continue
            try:
                text = sol.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # 本文件所属项目（M54：同名合约分桶时用来挑同项目实现）
            proj = _sol_project_key(sol, repo)
            lines = text.splitlines()
            # **先剥注释再切合约**（M54 实测教训）：Solidity 源里满是
            # `// contract Context` / `* contract Ownable is ...` 这类注释，
            # 不剥就会把注释里的名字当成合约声明 —— 合约 span 配平错位，
            # 合约名认成注释词，父合约继承链整条断掉。
            #
            # 替换必须是**保行**的：块注释常跨多行，若整段压成一行，
            # 后面所有代码的行号都会前移 —— 切片的 start_line/end_line
            # 随之偏移，真值按行号映射就全错（实测 7 条判反 +
            # 9 条"真值与源码不同步"）。所以换行符原样保留，
            # 其余字符替成空格（保字符偏移量）。
            text = _SOL_STRIP_COMMENTS_RE.sub(_sol_blank_keep_lines, text)
            # 合约边界：`contract X ... {` 到配平 `}`。函数归属哪个合约、
            # "函数名 != 合约名"（错名构造函数）的判定都需要它。
            #
            # **M54：`library` / `interface` 也要纳入边界**（实测教训）：
            # OpenZeppelin 的 `library Address` 里就装着 `functionCallWithValue`
            # —— 它把底层调用的返回值交给 `verifyCallResultFromTarget`
            # 消费（成功才继续）。`library` 不进边界 ⇒ 这个函数**不属于
            # 任何合约** ⇒ 同文件辅助函数证据机制找不到它的实现体 ⇒
            # 规则层看不见"返回值被消费" ⇒ 判成未检查（Top200 实测 62 条
            # 误报，全落在这个形态上）。
            # `interface` 同理（ERC20 接口声明）。
            contract_spans: list[tuple[int, int, str]] = []
            for cm in re.finditer(
                    r"\b(?:contract|library|interface)\s+([A-Za-z_]\w*)[^{]*\{",
                    text):
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
            for mm in re.finditer(r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*[^{]*\{", text):
                depth = 0
                for idx in range(mm.end() - 1, len(text)):
                    if text[idx] == "{":
                        depth += 1
                    elif text[idx] == "}":
                        depth -= 1
                        if depth == 0:
                            # **右端含 idx**（`text[mm.end():idx+1]`）——
                            # 少一个字符就会丢掉闭合大括号，规则层
                            # 配平不出 modifier 体 ⇒ 认不出
                            # "modifier 调用链上的身份检查"。
                            mod_spans.append((mm.start(), idx, mm.group(1),
                                              mm.group(0) + text[mm.end():idx + 1]))
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
                                                     parent_index, proj=proj)
                    if inherited:
                        extra.append(
                            "// ---- 父合约继承证据 ["
                            + ", ".join(f"{c}.{n}" for c, n, _s in inherited)
                            + "] ----\n"
                            + "\n".join(seg for _c, _n, seg in inherited))
                # M54：核验**间接身份检查** —— 函数体里调用的、定义在
                # 父合约里的普通函数（如 OpenZeppelin Context 的
                # `_msgSender()`，实现体是 `return msg.sender;`）。
                # 只在"本合约没有同名定义"时才去父合约找；找到了就把
                # 实现体拼进证据段，规则层据此认出身份检查（而不是
                # 按名字认 `_msgSender` —— 挂名字 = 挂类目，铁律禁止）。
                #
                # "本合约"的函数名要按**合约 span** 取，不能按整个文件：
                # 同文件里往往有多个合约（CakeToken.sol 里同时定义了
                # Ownable），用整文件口径会把父合约的函数误当本地定义，
                # 于是永远查不到真正的实现体。
                local_funcs: set[str] = set()
                if contract:
                    for cs, ce, cname in contract_spans:
                        if cname != contract:
                            continue
                        local_funcs |= set(re.findall(
                            r"\bfunction\s+([A-Za-z_]\w*)\s*\(",
                            text[cs:ce + 1]))
                # `called` 要把**修饰符定义体**里的调用也算进来 ——
                # `require(_owner == _msgSender())` 写在 modifier 里，
                # 不在函数体 src 里；只看 src 永远查不到 Context 的实现体。
                called = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", src))
                for _seg in extra:
                    called |= set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", _seg))
                # `super.transferFrom(...)`（委托父合约）也要算调用 ——
                # 父合约的同名函数才是真身，实现体在父合约那边。
                #
                # M54：`super.X` 的语义是**明确指向父合约的 X**，
                # 不能被 `local_funcs` 排除掉 —— 本合约往往有同名函数
                # （`PausableToken.transferFrom` 委托 `StandardToken
                # .transferFrom`），`called - local_funcs` 会把
                # `transferFrom` 删掉，于是父合约那份实现体永远拿不到，
                # 规则层看不见 allowance 扣减 ⇒ 23 条 transferFrom 误报。
                # 所以 super 调用**单独成一路**（super_funcs），走
                # "本合约没有同名定义"的查找路径。
                super_called = set(re.findall(
                    r"\bsuper\s*\.\s*([A-Za-z_]\w*)\s*\(", src))
                called |= super_called
                want_funcs = sorted(called - local_funcs - _SOLIDITY_BUILTINS)
                # super 委托：**即使本合约有同名定义也要查父合约那份**
                # （Solidity 的 super.X 走的是继承链上的实现，不是本合约的）。
                want_super = sorted(super_called - _SOLIDITY_BUILTINS)
                # 父合约查找的名字表 —— 同文件辅助函数段会往里补
                # （辅助函数调的父合约函数，如 Context._msgSender）。
                parent_want: set[str] = set(want_funcs)

                # ---- M54：同文件辅助函数证据 ----
                # 入口函数（或它的 modifier）调用了**本合约里**定义的其它函数
                # （如 `require(isOwner())` 里的 isOwner，实现体是
                # `return msg.sender == _owner;`）—— 这类"间接身份检查"
                # 既不在入口函数体里，也不在父合约里，但它是**真实的保护**。
                # 不拼进来就会把 `transferOwnership` 全判成越权
                # （Top200 64 条误报）。
                #
                # 范围：**本合约**里定义的（其它合约的同名函数不算 ——
                # 那不是本合约能调的），且排除入口函数自己。
                # 注意：这些函数名**在 local_funcs 里**（它们是本合约的
                # 本地定义），所以查的是 `called ∩ 本合约函数`，
                # 不是 `called - local_funcs`（那是找父合约用的）。
                if called and contract:
                    cs = ce = 0
                    for cs2, ce2, cname2 in contract_spans:
                        if cname2 == contract:
                            cs, ce = cs2, ce2
                            break
                    # 同文件辅助函数证据 = **一跳**（入口直接调的）
                    # + **二跳**（一跳辅助函数再调的）。
                    #
                    # 二跳是必需的（M54 实测）：OpenZeppelin 的
                    # `verifyCallResultFromTarget` 在失败分支里调
                    # `_revert(returndata, errorMessage)` —— 真正的
                    # "失败即中止"语义在**二跳**的实现体里。只有一跳
                    # 证据时，规则层看不到中止 ⇒ 把 62 条 `Address`
                    # 库的函数全判成"返回值未检查"。
                    #
                    # `_visited` 防环 + 段预算：辅助函数互相调用时
                    # 不能无限展开（铁律：多跳要防环）。
                    visited: set[str] = {name}
                    hop1 = [n for n in sorted(called - _SOLIDITY_BUILTINS)
                            if n != name
                            and n in local_funcs
                            and re.search(rf"\bfunction\s+{re.escape(n)}\s*\(",
                                          text[cs:ce + 1])]
                    hop2: list[str] = []
                    hop1_bodies: list[str] = []
                    for n in hop1:
                        if n in visited:
                            continue
                        visited.add(n)
                        fm2 = re.search(
                            rf"\bfunction\s+{re.escape(n)}\s*\([^)]*\)"
                            rf"[^{{;]*\{{", text[cs:ce + 1])
                        if not fm2:
                            continue
                        st = cs + fm2.start()
                        depth = 0
                        for j in range(cs + fm2.end() - 1, ce + 1):
                            if text[j] == "{":
                                depth += 1
                            elif text[j] == "}":
                                depth -= 1
                                if depth == 0:
                                    hop1_bodies.append(text[st:j + 1])
                                    break
                    if hop1_bodies:
                        for seg in hop1_bodies:
                            for c2 in re.findall(r"\b([A-Za-z_]\w*)\s*\(", seg):
                                if (c2 in visited or c2 not in local_funcs
                                        or c2 in _SOLIDITY_BUILTINS):
                                    continue
                                if not re.search(
                                        rf"\bfunction\s+{re.escape(c2)}\s*\(",
                                        text[cs:ce + 1]):
                                    continue
                                visited.add(c2)
                                hop2.append(c2)
                    segs: list[str] = list(hop1_bodies)
                    for n in hop2:
                        fm2 = re.search(
                            rf"\bfunction\s+{re.escape(n)}\s*\([^)]*\)"
                            rf"[^{{;]*\{{", text[cs:ce + 1])
                        if not fm2:
                            continue
                        st = cs + fm2.start()
                        depth = 0
                        for j in range(cs + fm2.end() - 1, ce + 1):
                            if text[j] == "{":
                                depth += 1
                            elif text[j] == "}":
                                depth -= 1
                                if depth == 0:
                                    segs.append(text[st:j + 1])
                                    break
                    if segs:
                        extra.append(
                            "// ---- 同文件辅助函数证据 ["
                            + ", ".join(hop1 + hop2)
                            + "] ----\n" + "\n".join(segs))
                        # M54：同文件辅助函数调的**非本地**函数要去父合约找。
                        # 身份检查链常是三层：
                        #   modifier onlyOwner → _checkOwner()（同文件辅助）
                        #   → _msgSender()（**父合约** Context 里）
                        #   → return msg.sender;
                        # 父合约查找用的名字表原先只算到"入口直接调的"，
                        # 漏掉"辅助函数再调的"⇒ Context._msgSender 进不了
                        # 证据段 ⇒ 规则层认不出间接身份检查 ⇒
                        # 把有 onlyOwner 保护的 transferOwnership 判成越权。
                        for seg in hop1_bodies:
                            for c3 in re.findall(r"\b([A-Za-z_]\w*)\s*\(", seg):
                                if (c3 in local_funcs
                                        or c3 in _SOLIDITY_BUILTINS
                                        or c3 in visited):
                                    continue
                                parent_want.add(c3)
                # ---- M54：super 委托的**同文件同名实现**候选 ----
                #
                # Solidity 的 `super.X` 在**多继承**体系里解析到的是
                # "最终合约线性化中最靠后的那份实现" —— 那份实现**未必**
                # 在当前合约的 is 继承链上。
                #
                # 例（Top200 CrowdsaleToken.sol）：
                #   contract ReleasableToken is ERC20, Ownable {
                #     function transferFrom(...) { return super.transferFrom(...); }
                #   }
                #   contract CrowdsaleToken is ReleasableToken, MintableToken,
                #                                UpgradeableToken { }   // ← 最终合约
                #   contract MintableToken is StandardToken { }   // ← 真正实现
                # `super.transferFrom` 落到 StandardToken（allowance 扣减
                # 在那里），但 StandardToken **不是** ReleasableToken 的
                # base ⇒ 沿继承链查不到 ⇒ 误报。
                #
                # 口径：`super.X` 的实现可能在**同文件的任何合约**里 ——
                # 同文件多继承是 Solidity 的常见写法。把同文件里所有
                # 同名实现都作为候选证据拼进去（规则层按机制核验，
                # 不靠名字）。
                if want_super and contract:
                    file_impls: list[tuple[str, str]] = []
                    for fm2 in FUNC_RE.finditer(text):
                        fn = fm2.group(1)
                        if fn not in want_super:
                            continue
                        owner2 = next((c for s, e, c in contract_spans
                                       if s <= fm2.start() <= e), "")
                        # 只排除**本合约**自己的那份（super 走的是别的
                        # 合约的实现）；同名但不同合约的必须收 ——
                        # 入口函数本身就叫 transferFrom，候选也叫
                        # transferFrom，按函数名排除会把真候选砍掉。
                        if not owner2 or owner2 == contract:
                            continue
                        depth = 0
                        for j in range(fm2.end() - 1, len(text)):
                            if text[j] == "{":
                                depth += 1
                            elif text[j] == "}":
                                depth -= 1
                                if depth == 0:
                                    file_impls.append(
                                        (owner2, text[fm2.start():j + 1]))
                                    break
                    if file_impls:
                        extra.append(
                            "// ---- 父合约函数证据 [super 同文件候选] ["
                            + ", ".join(f"{c}.{fn}" for c, fn in file_impls)
                            + "] ----\n"
                            + "\n".join(seg for _c, seg in file_impls))
                if (want_funcs or want_super or parent_want) and contract:
                    inh_funcs = self._inherited_funcs(
                        contract, sorted(parent_want), parent_index, proj=proj)
                    # M54：`super.X` 委托走**另一路** —— 跳过本合约自身，
                    # 沿 bases 链找继承链上的那份实现（Solidity 语义：
                    # super.X 调的是父合约的实现，不是本合约的同名定义）。
                    if want_super:
                        inh_funcs += self._inherited_funcs(
                            contract, want_super, parent_index, proj=proj,
                            skip_self=True)
                    # M54：父合约函数证据**二跳** —— 一跳拿到的实现体
                    # （如 Ownable 的 `_checkOwner`）里调的函数
                    # （`_msgSender`）可能定义在**祖父**合约（Context）里。
                    # 身份检查链是三层：
                    #   modifier onlyOwner → _checkOwner() →
                    #   require(owner() == _msgSender()) → return msg.sender;
                    # 少一跳，规则层就认不出"间接身份检查" ⇒
                    # 把有 onlyOwner 保护的 transferOwnership 判成越权
                    # （Top200 实测 8 条）。
                    if inh_funcs:
                        hop2_names: set[str] = set()
                        for _c, _n, seg in inh_funcs:
                            hop2_names |= set(re.findall(
                                r"\b([A-Za-z_]\w*)\s*\(", seg))
                        hop2_names -= _SOLIDITY_BUILTINS
                        hop2_names -= {n for _c, n, _s in inh_funcs}
                        if hop2_names:
                            inh_funcs += self._inherited_funcs(
                                contract, sorted(hop2_names), parent_index,
                                proj=proj)
                    if inh_funcs:
                        extra.append(
                            "// ---- 父合约函数证据 ["
                            + ", ".join(f"{c}.{n}" for c, n, _s in inh_funcs)
                            + "] ----\n"
                            + "\n".join(seg for _c, _n, seg in inh_funcs))
                # 合约名写进切片首行注释：函数级切片没有文件头，
                # "函数名 == 合约名 → 构造函数"的判定只能靠它。
                #
                # M53：pragma 版本同理 —— "0.8+ 内置溢出回滚 / 0.4.x 不检查"
                # 是**编译器事实**，必须让规则层看得到。切片头部写
                # `// pragma: solidity ^0.4.19;`（注释形态，不干扰既有
                # 正则：规则读源码须剥注释，我们自己显式读这一行）。
                src = f"// contract: {contract or '?'}\n" + src
                _pm = re.search(r"^\s*pragma\s+solidity\s+([^;]+);",
                                text, re.M)
                if _pm:
                    src = f"// pragma: solidity {_pm.group(1).strip()};\n" + src
                if extra:
                    # 只有「本合约」modifier 段才用本合约段头；继承证据
                    # 段自带 `// ---- 父合约继承证据 [...] ----` 段头，
                    # 空的本合约头会误导核验（Module 39 实测空段头）。
                    #
                    # M54：**三段必须各自独立**。原先把"同文件辅助函数
                    # 证据"和"修饰符定义"合成同一段（都进 local 列表），
                    # 于是同文件辅助段插在 modifier 段**中间** ——
                    # 规则层按段头切分时，modifier 段被**截断**
                    # （`modifier onlyOwner() { _checkOwner(); _;` 少了
                    # 闭合大括号）⇒ 规则层配平不出 modifier 体 ⇒
                    # 认不出"modifier 调用链上的身份检查" ⇒
                    # 把有 onlyOwner 保护的 transferOwnership 判成越权
                    # （Top200 实测 8 条）。
                    mod_segs = [s for s in extra
                                if not s.startswith("// ---- 父合约")
                                and not s.startswith("// ---- 同文件")]
                    same_segs = [s for s in extra
                                 if s.startswith("// ---- 同文件")]
                    inh = [s for s in extra if s.startswith("// ---- 父合约")]
                    parts = []
                    if mod_segs:
                        parts.append("// ---- 修饰符定义（本合约，供核验）----\n"
                                     + "\n".join(mod_segs))
                    parts.extend(inh)
                    parts.extend(same_segs)
                    src = src + "\n" + "\n".join(parts)
                units.append(CodeUnit(
                    file_path=str(sol), language=Language.SOLIDITY_WEB3,
                    unit_name=name, start_line=start_line, end_line=end_line,
                    decorators_or_modifiers=[visibility, *mods],
                    called_symbols=self._calls(src), source_code=src))
        return units

    IGNORE = {"node_modules", "lib", "test/helpers"}
    # Foundry 约定：`*.t.sol` 是测试合约、`*.s.sol` 是部署脚本 —— 两者都
    # **不上链**，不是生产入口。M136 实测：dss 的 `flip.t.sol` / `vat.t.sol`
    # 里有一批故意写坏的算术表达式（测试要覆盖溢出分支），把它们当生产
    # 入口会让"生产协议零误报"这条门禁失去意义（误报全来自测试夹具）。
    # 只按**文件名后缀**排除，不按目录名排除 —— 有的项目把测试放在 src/ 里
    # （dss 就是），按目录排会漏。
    TEST_SUFFIXES = (".t.sol", ".s.sol")

    # ---- Module 39：跨文件父合约继承索引 ----

    def _build_parent_index(self, repo: Path) -> dict:
        """扫全库 .sol：合约名 → (is 继承列表, {modifier名: 实现体},
        {函数名: 实现体})。

        只做正则级事实提取（合约头 is 子句 + modifier 括号配平体 +
        函数括号配平体），与 extract_entry_units 的本文件解析同正则口径，
        两遍结果一致。
        索引失败静默降级为空 —— 继承证据是增强项，不能拖垮切片。

        M54：函数体索引是为了核验**间接身份检查** —— OpenZeppelin 的
        `require(_owner == _msgSender())` 里没有 msg.sender 字面，但
        Context 基类的 `_msgSender()` 实现体就是 `return msg.sender;`。
        "看实现体不看名字"铁律要求把父合约的实现体拼进切片，
        否则只能按名字认（挂名字 = 挂类目，铁律禁止）。

        **函数索引必须按合约归属建，不能按整文件建**（M54 实测教训）：
          ① 抽象声明（`function balanceOf(...) returns (uint);`）**没有
             函数体** —— 用 `text.find("{")` 找下一个大括号会跨到**别的
             合约**，把整段无关代码当成"实现体"；
          ② 同文件的兄弟合约（如 interface Token）里的函数会被当成本
             合约的父合约证据。
        修法：先切出合约 span，再把**有函数体的**函数归到所属合约
        （口径与 extract_entry_units 的 FUNC_RE 一致）。

        **同名合约必须按项目分桶**（M54 实测教训）：Top200 靶场有 303 个
        独立项目，OpenZeppelin 的 `Context` 在其中 114 个项目里各有一份
        实现 —— 用 `idx[name] = ...` 覆盖式写入会让**最后扫到的那个项目**
        的实现覆盖掉其它 113 个，于是 `require(_owner == _msgSender())`
        永远查不到 `return msg.sender;`，误报 68 条。
        修法：同名合约存**候选列表**（含各自的项目标识），查找时
        **优先同项目**的候选（同一份 vendored 依赖），再退回全局候选。
        """
        idx: dict = {}
        try:
            for sol in repo.rglob("*.sol"):
                if any(p in self.IGNORE for p in sol.parts):
                    continue
                try:
                    text = sol.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                # 同样先剥注释（保行）：注释里的 `contract Context` 会被当成
                # 合约声明 → 合约 span 配平错位 → 该合约的函数全归错人
                # （实测 114 个 Context 里 111 个 funcs 为空）。
                text = _SOL_STRIP_COMMENTS_RE.sub(_sol_blank_keep_lines, text)
                mods: dict[str, str] = {}
                for mm in re.finditer(
                        r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*[^{]*\{",
                        text):
                    depth = 0
                    for i2 in range(mm.end() - 1, len(text)):
                        if text[i2] == "{":
                            depth += 1
                        elif text[i2] == "}":
                            depth -= 1
                            if depth == 0:
                                # 右端含 i2（闭合大括号不能丢）
                                mods[mm.group(1)] = (mm.group(0)
                                                     + text[mm.end():i2 + 1])
                                break
                # ---- 合约 span（函数归属哪个合约） ----
                spans: list[tuple[int, int, str]] = []
                for cm in re.finditer(r"\bcontract\s+([A-Za-z_]\w*)[^{]*\{",
                                      text):
                    depth = 0
                    for j in range(cm.end() - 1, len(text)):
                        if text[j] == "{":
                            depth += 1
                        elif text[j] == "}":
                            depth -= 1
                            if depth == 0:
                                spans.append((cm.start(), j, cm.group(1)))
                                break
                # ---- 每个合约各自的函数实现体（**只收有体的**） ----
                # M54：**同名重载要全部保留**（值是列表）。
                # 原来 `cfuncs[owner][name] = seg` 是覆盖式 —— 重载函数
                # （`_checkRole(role)` 与 `_checkRole(role, account)`）
                # 只留最后一个，于是角色检查链断了一环：
                #   modifier onlyRole → _checkRole(role)
                #   → _checkRole(role, _msgSender())   ← 这一层丢了
                #   → if (!hasRole(role, account)) revert
                # 身份传递的证据不全 ⇒ 判不出"有保护"。
                cfuncs: dict[str, dict[str, list[str]]] = {}
                file_funcs: dict[str, list[str]] = {}
                for fm in FUNC_RE.finditer(text):
                    owner = next((c for s, e, c in spans
                                  if s <= fm.start() <= e), "")
                    if not owner:
                        continue
                    depth = 0
                    for j in range(fm.end() - 1, len(text)):
                        if text[j] == "{":
                            depth += 1
                        elif text[j] == "}":
                            depth -= 1
                            if depth == 0:
                                seg = text[fm.start():j + 1]
                                cfuncs.setdefault(owner, {}).setdefault(
                                    fm.group(1), []).append(seg)
                                file_funcs.setdefault(fm.group(1), []).append(seg)
                                break
                # 项目标识：Top200 每个项目是独立顶层目录，仓名路径里的
                # 目录名相同即同一项目（vendored 依赖也在项目内）。
                proj = _sol_project_key(sol, repo)
                for cm in re.finditer(
                        r"\bcontract\s+([A-Za-z_]\w*)\s*(?:is\s+([\w\s,.\-]+))?\s*\{",
                        text):
                    bases = [b.strip() for b in (cm.group(2) or "").split(",")
                             if b.strip()]
                    # 同名合约**追加**候选，不覆盖（跨项目同名 = 各自实现）
                    idx.setdefault(cm.group(1), []).append(
                        (bases, mods, cfuncs.get(cm.group(1), {}), proj,
                         file_funcs))
        except Exception:
            return {}
        return idx

    @staticmethod
    def _pick_candidate(idx: dict, contract: str, proj: str | None):
        """从同名合约的候选列表里挑一个：**同项目优先**，否则取第一个。

        idx[name] = [(bases, mods, funcs, proj), ...]
        同名合约在多项目里各有各的实现（Top200 的 114 份 Context）——
        必须挑**同一个项目**的那份，否则继承链会串到别的项目的实现上。
        """
        cands = idx.get(contract)
        if not cands:
            return None
        if proj:
            for c in cands:
                if c[3] == proj:
                    return c
        return cands[0]

    def _inherited_mods(self, contract: str, missing: list[str],
                        idx: dict, _seen: set | None = None,
                        proj: str | None = None
                        ) -> list[tuple[str, str, str]]:
        """沿 is 继承链（BFS，防环）抓父合约里缺失 modifier 的实现体。
        返回 [(父合约名, modifier名, 实现体)]。"""
        if _seen is None:
            _seen = set()
        if contract in _seen or contract not in idx:
            return []
        _seen.add(contract)
        c = self._pick_candidate(idx, contract, proj)
        if c is None:
            return []
        bases, mods = c[0], c[1]
        out: list[tuple[str, str, str]] = []
        want = set(missing)
        for n in want:
            if n in mods:
                out.append((contract, n, mods[n]))
        rest = want - {n for _, n, _ in out}
        if rest:
            for b in bases:
                out.extend(self._inherited_mods(b, sorted(rest), idx, _seen,
                                                proj))
        return out

    def _inherited_funcs(self, contract: str, names: list[str],
                         idx: dict, _seen: set | None = None,
                         proj: str | None = None,
                         skip_self: bool = False
                         ) -> list[tuple[str, str, str]]:
        """沿 is 继承链（BFS，防环）抓父合约里指定**普通函数**的实现体。

        M54：核验"间接身份检查"用。OpenZeppelin 的
        `require(_owner == _msgSender())` 里没有 msg.sender 字面，
        但 Context 基类的 `_msgSender()` 实现体就是 `return msg.sender;`
        —— "看实现体不看名字"要求把父合约实现体贴进切片，
        否则只能按名字认（挂名字 = 挂类目，铁律禁止）。

        **skip_self**（M54）：`super.X` 委托查的是**继承链上的实现**，
        不是本合约那份同名定义 —— 所以要跳过 contract 自身、从它的
        bases 开始找。本合约有同名定义时普通路径会被自己的那份挡住
        （Top200 的 `PausableToken.transferFrom` 委托
        `StandardToken.transferFrom`，allowance 扣减在后者里）。

        返回 [(父合约名, 函数名, 实现体)]。
        """
        if _seen is None:
            _seen = set()
        if contract in _seen or contract not in idx:
            return []
        _seen.add(contract)
        c = self._pick_candidate(idx, contract, proj)
        if c is None:
            return []
        bases, _mods, funcs = c[0], c[1], c[2]
        out: list[tuple[str, str, str]] = []
        want = set(names)
        if not skip_self:
            for n in want:
                # M54：同名**重载**的实现体全部带上（值是列表）。
                for seg in funcs.get(n, []):
                    out.append((contract, n, seg))
        rest = want - {n for _, n, _ in out}
        if rest:
            for b in bases:
                out.extend(self._inherited_funcs(b, sorted(rest), idx, _seen,
                                                 proj))
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
