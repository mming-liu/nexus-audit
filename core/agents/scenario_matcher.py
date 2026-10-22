"""GPTScan 式两步法推理（第2周实现，第5周扩展为多语言 / 多类目）。

复刻 GPTScan 的 query_template 设计（prompt_multiple_choice_scenarios /
prompt_single_yes_no_question），把"找漏洞"拆成客观判断题：

  Step 1 — Scenario（Yes/No）: 代码中是否存在该类漏洞对应的危险汇聚点，且入参可达？
  Step 2 — Property（Yes/No）: 汇聚点之前是否已经做了对应防护？

输出 VulnHypothesis 列表（仅保留 property 缺失的）。
合规：全部使用防御合规视角措辞。LLM 可注入（LLMClient 协议），支持 mock 测试。

第5周变更：
  - 由固定 3 个 Web 场景改为按 `core.agents.vuln_categories` 注册表驱动，
    支持 OWASP Benchmark 的 11 个真实类别（sqli/cmdi/xss/...）
  - 新增 code_language 参数，Java 切片渲染为 java 代码块
  - audit_many() 并发初筛（受 max_concurrency 约束），支撑 2700+ 用例跑分
"""
from __future__ import annotations

import asyncio
import inspect
import re
from typing import Callable, Sequence

from core.agents import vuln_categories as VC
from core.agents.router import TwoTierRouter, extract_json
# 只借一个事实判定函数（入口有没有外部输入），无反向依赖
from core.agents.rule_detectors import has_external_input, build_rule_diagnostic
from core.models import CodeUnit, VulnHypothesis

SYSTEM_MESSAGE = (
    "You are a defensive code auditor performing static data-flow reachability "
    "analysis. Answer strictly in the output format requested; no explanations "
    "beyond the format."
)

# 兼容旧接口：默认 Web 赛道场景（IDOR / 越权 / RCE）
WEB_SCENARIOS = [
    {
        "id": "idor",
        "question": ("该函数是否接收客户端可控的资源主键（如 order_id、account_id、user_id），"
                     "并执行数据库读取、修改或删除操作？"),
        "property": ("在执行数据库查询条件或前置校验中，是否显式比对了该资源的归属人字段"
                     "（如 user_id、owner_id）与当前登录会话身份（如 current_user.id）？"),
    },
    {
        "id": "authz_bypass",
        "question": ("该函数是否执行敏感管理操作（如修改角色、删除用户、导出数据），"
                     "但其路由未声明权限装饰器？"),
        "property": ("该函数是否被全局鉴权中间件或权限装饰器（如 @login_required、"
                     "@admin_required、Depends(get_admin)）保护？"),
    },
    {
        "id": "rce",
        "question": ("该函数是否将客户端可控输入传入执行类函数"
                     "（如 eval、exec、system、subprocess、pickle.loads）？"),
        "property": ("传入执行类函数的输入在到达前，是否经过白名单校验或参数化处理？"),
    },
]

SCENARIO_PROMPT_TMPL = """You are performing static data-flow analysis on {lang} code.
Decide whether the described insecure condition holds.

Question:
{question}

This is a TAINT check. It holds only if BOTH are true:
  (1) the dangerous operation exists in the executable statements, AND
  (2) a value that originates OUTSIDE this function flows into it.
If the operation only receives constant, literal, class-field or hard-coded
values, answer "No" — even when the API itself is a dangerous one.
{source_hint}
Output JSON only.
If the answer is "Yes", you MUST quote TWO DIFFERENT lines:
{{"hit": "Yes",
  "source_line": "<verbatim: the line where external input enters this function>",
  "sink_line": "<verbatim: the line that performs the dangerous operation>"}}
If the answer is "No", quote the one line that made you conclude so:
{{"hit": "No", "evidence_line": "<verbatim copy of ONE executable line>"}}

Rules for source_line: it must show input actually being received — a parameter
bound by an annotation, a read from the request object, or a cross-route read.
It must NOT be the sink line itself, must NOT be a routing annotation line
(@GetMapping / @RequestMapping ...), and must NOT merely declare a constant.

All quoted lines must be copied character-for-character from the Code block below.
Do not paraphrase, do not shorten with "...", do not quote a comment line.
An answer whose quoted lines are not literally present in the code is discarded.

Code:
```{lang}
{code}
```"""

# 无外部输入时给模型的一句事实提示。
# 注意这里只**告知事实**，不替它下结论 —— 直接判 False 会漏报：
# Hello-Java-Sec 的 XMLDecoderVul.vul 与 .safe 都不接收输入、读同一个常量
# 文件，真值却一个 True 一个 False，硬短路会把那条真漏洞一起判掉。
_NO_SOURCE_HINT = """
NOTE: the entry method below takes no external parameter and reads nothing from
the request object. Condition (2) can therefore hold only if you can point to a
concrete source_line inside the executable statements. If you cannot, answer "No".
"""
_HAS_SOURCE_HINT = ""

# 配置型缺陷（weakrand / hash / crypto / securecookie）：
# 缺陷在 API/算法选择本身，与外部输入是否可达无关，不能套用污点可达的判据。
CONFIG_SCENARIO_PROMPT_TMPL = """You are performing static code analysis on {lang} code.
Decide whether the code below exhibits the described insecure condition.

Question:
{question}

Answer with JSON only, and you MUST cite the line you judged from:
{{"hit": "Yes", "evidence_line": "<verbatim copy of ONE executable line>"}}
or {{"hit": "No", "evidence_line": "<verbatim copy of ONE executable line>"}}.

"evidence_line" must be copied character-for-character from the Code block below.
Do not paraphrase, do not shorten with "...", do not quote a comment line.
An answer whose evidence_line is not literally present in the code is discarded.

This is a configuration-strength check: it does NOT require external input to reach the
call. Answer "Yes" if the insecure API or weak algorithm/configuration described above
is actually used in the executable statements. Commented-out code and doc comments
do not count.

Code:
```{lang}
{code}
```"""

PROPERTY_PROMPT_TMPL = """You are auditing whether one specific protective property is PRESENT in the code below.

Property:
{property}

Answer with JSON only, and you MUST cite the line you judged from:
{{"protected": "Yes", "evidence_line": "<verbatim copy of ONE executable line>"}}
or {{"protected": "No", "evidence_line": "<verbatim copy of ONE executable line>"}}.

"evidence_line" must be copied character-for-character from the Code block below.
Do not paraphrase, do not shorten with "...", do not quote a comment line.
An answer whose evidence_line is not literally present in the code is discarded.

Judge ONLY on executable statements that actually run on the audited path.
Comments, string literals, log/error messages, and example URLs in comments are NOT
evidence — they frequently describe the unsafe alternative that this code avoided.
If the protective measure is not present in the executed statements, answer "No".

Code:
```{lang}
{code}
```"""

# 旧版模板（保留给 Python Web 赛道与既有测试）
SCENARIO_PROMPT_TMPL_V1 = """Given the following code, answer the questions below and organize the result in a JSON format like {{"idor": "Yes" or "No", "authz_bypass": "Yes" or "No", "rce": "Yes" or "No"}}.

{questions}

Code:
```python
{code}
```"""

PROPERTY_PROMPT_TMPL_V1 = """Does the following code satisfy this property (answer the property being PRESENT)?
"{property}"
Answer ONLY "Yes" or "No".

Code:
```python
{code}
```"""

LANG_TAG = {"python_web": "python", "java_web": "java", "solidity_web3": "solidity"}


def _is_yes(text: str, field: str) -> bool:
    """从模型输出里判定 Yes/No，兼容 JSON 与裸文本。"""
    try:
        data = extract_json(text)
        if isinstance(data, dict) and field in data:
            return str(data[field]).strip().lower().startswith("y")
    except Exception:
        pass
    low = text.lower()
    if "no" in low and "yes" not in low:
        return False
    return "yes" in low


# ---- Cite-Before-Verdict -------------------------------------------------
# 只问 "Yes/No" 时，模型可以凭印象作答，理由和证据脱钩：它能编出一行不存在的
# 代码来解释结论，而这段编造恰好"听起来很合理"。要求它先逐字符引用它据以
# 判断的那一行，然后在本地做子串核验 —— 引用的行必须**真的在切片里**，
# 且不能是注释行。核验不过的采样直接作废，不参与多数票。
#
# 这一步几乎零成本（纯本地字符串操作），但能把"幻觉型误报"整类掐掉。

# 判断一行是否是注释：Java/Python/Solidity 的 // # /* * 开头，以及 XML/HTML 的 <!--
_COMMENT_LINE_RE = re.compile(r"^\s*(?://|#|/\*|\*|<!--|-->)")
# 引用时模型容易带上的行号前缀（切片里是 `123: code` 形式），核验前要剥掉
_LINENO_PREFIX_RE = re.compile(r"^\s*\d+\s*[:|]\s?")

# 切片里的证据块（框架装配 / 跨路由串接）会把**代码**逐行加上 `//   ` 前缀渲染，
# 以免它们被规则当成入口方法体的可执行语句。但这对核验器是个陷阱：
# 那些行确实以 `//` 开头，而注释行一律不许当证据 —— 于是"最有价值的证据"
# （CorsProcessor 的白名单判断、Filter 的装配参数）恰好无法被引用，模型只能
# 退回入口方法体那一行来交差。这正是 mybatisVuln02 引用入口 `return` 行的机制性
# 成因：不是它偷懒，是核验器只给它留了那一条路。
# 判据：只有**这两类段**里的 `//   ` 是代码引用；其它段里的 `//` 仍是真注释。
_QUOTED_EVIDENCE_HEADERS = ("框架装配证据", "跨路由串接证据")
# 前缀是 `//` + 至少三个空格，然后是原行的内容（串接段贴方法体时保留了原缩进，
# 所以填充空格可能远多于三个，必须用 {3,} 而不是固定三格）
_QUOTED_LINE_RE = re.compile(r"^//(\s{3,})(.*\S)\s*$")


def _dequote_evidence_line(s: str) -> str | None:
    """把 `//   <code>` 还原成 `<code>`；不是这种形态就返回 None。

    只认 `//` + 三个以上空格 —— 真实注释通常是 `// 说明` 或 `//说明`，
    不能顺手去前缀，否则"注释里写着原本的漏洞写法"会被当成执行证据。
    """
    m = _QUOTED_LINE_RE.match(s.strip())
    return m.group(2).strip() if m else None
_SECTION_HEADER_RE = re.compile(r"^\s*//\s*----\s*(.*?)\s*-*\s*$")


def _quotable_lines(code: str) -> list[tuple[str, bool]]:
    """返回 [(归一化后的可引用文本, 是否来自证据块)]。

    证据块里的 `//   if (x) {` 会被还原成 `if (x) {`：模型引用带不带前缀都认，
    因为它在切片里看到的两种形态都存在（前缀是渲染加的，代码本身没有）。
    `//   - 说明文字` 这类条目是在描述而不是代码，不参与引用。
    """
    out: list[tuple[str, bool]] = []
    quoted_section = False
    for ln in (code or "").splitlines():
        stripped = ln.strip()
        m = _SECTION_HEADER_RE.match(stripped)
        if m:
            head = m.group(1)
            quoted_section = any(h in head for h in _QUOTED_EVIDENCE_HEADERS)
            continue
        if quoted_section:
            inner = _dequote_evidence_line(stripped)
            if inner is not None:
                if not inner.startswith("-"):
                    out.append((_normalize_line(inner), True))
                continue
            if stripped.startswith("//"):
                continue  # 证据块内的说明行（段落标题、截断提示）
        if _COMMENT_LINE_RE.match(ln):
            continue
        if stripped:
            out.append((_normalize_line(ln), False))
    return out


def _normalize_line(s: str) -> str:
    return " ".join(_LINENO_PREFIX_RE.sub("", s).split())


def verify_evidence(code: str, evidence: str) -> tuple[bool, str]:
    """核验模型引用的代码行是否真实存在于切片中且不是注释行。

    返回 (是否通过, 原因)。原因仅用于日志/审计，不影响判定。
    """
    ev = (evidence or "").strip()
    if not ev:
        return False, "evidence_line 为空"
    if ev in ("...", "…") or "..." in ev:
        # 省略号说明它在概述而不是引用。允许模型概述等于放弃核验。
        return False, "evidence_line 含省略号，非逐字符引用"

    raw_lines = (code or "").splitlines()
    # 模型可能把切片里看到的 `//   <code>` 原样拷过来，也可能只拷 code 部分。
    # 两种都算同一行 —— 前缀是渲染加的，不是代码的一部分。
    cands = [_normalize_line(ev)]
    _dq = _dequote_evidence_line(ev)
    if _dq:
        cands.append(_normalize_line(_dq))
    cands = [c for c in cands if c]

    quotable = _quotable_lines(code)
    hit: tuple[str, bool] | None = None
    for ev_norm in cands:
        for text, is_ev in quotable:
            if ev_norm in text:
                hit = (text, is_ev)
                break
        if hit:
            break
    if hit is None:
        # 整行没匹配上时退一步：允许引用被切片折行后的前半段，
        # 但要求长度足够（太短的片段容易在别处偶然命中，起不到核验作用）。
        if any(len(c) >= 12 for c in cands):
            joined = "\n".join(t for t, _ in quotable)
            if any(c in joined for c in cands if len(c) >= 12):
                hit = ("", False)
        if hit is None:
            # 区分两种失败：引用的是注释行，还是根本不存在。
            # 前者是最危险的假证据（靶场里常写"原本的漏洞写法，已删"），
            # 后者是编造 —— 两者都不作数，但日志里要能分开。
            for ln in raw_lines:
                ln_norm = _normalize_line(ln)
                if _COMMENT_LINE_RE.match(ln) and any(c in ln_norm for c in cands):
                    return False, "evidence_line 命中注释行，不能作为执行证据"
            return False, "evidence_line 不在切片中（疑似编造）"

    if hit[1]:
        return True, "引用自证据块（框架装配/跨路由串接），按代码计入"
    return True, ""

class ScenarioMatcher:
    """两步法初筛器（运行在 Tier-1 模型上）。

    `scenario_votes` / `property_votes` 控制每个问题问几次取多数（默认 1）。

    关于票数，这里踩过两个坑，都记录一下：

    1. 3 票**无效**。每种策略各跑 2 轮完整 66 样本评测，两轮之间的翻转数：
         votes=1：9/66（13.6%）
         votes=3：9/66（13.6%）  ← 一条都没降，成本 ×3
       原因：3 票几乎必然是 2:1，而 2:1 只是把「一次抽样」换成「另一次抽样」。

    2. 但"投票没用"这个结论是错的。把 5 轮完整评测当独立观测事后合并取多数，
       Score 从单轮的 0.639–0.724 抬到 0.793（TPR 0.935 / FPR 0.143）。
       所以正确说法是**票数不够**，不是方法不对。

    默认仍取 1：多数票的收益要用 5 倍调用换，且修不了「5 轮全错」的确定性错误，
    不该让常规跑分默认背这个成本。需要提召回时显式传 5。

    `VulnHypothesis.votes` 记录每一轮原始票型，供事后审计模型有多犹豫：
    1:2 分歧会把 confidence 从 0.7 降到 0.45，下游可优先送人工复核。
    """

    def __init__(self, router: TwoTierRouter | None = None,
                 llm: Callable[[list[dict]], str] | None = None,
                 code_language: str = "java_web",
                 max_concurrency: int = 6,
                 scenario_votes: int = 1, property_votes: int = 1):
        self.router = router
        self._llm = llm
        self.code_language = code_language
        self.max_concurrency = max_concurrency
        self.scenario_votes = max(1, scenario_votes)
        self.property_votes = max(1, property_votes)

    async def _ask(self, prompt: str) -> str:
        messages = [{"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": prompt}]
        if self._llm is not None:
            # llm 既可能是同步函数（mock / 本地模型），也可能是 async（网关客户端）
            r = self._llm(messages)
            return await r if inspect.isawaitable(r) else r
        if self.router is None:
            raise RuntimeError("需要注入 router 或 llm")
        return await self.router.screen(messages)

    async def _vote(self, prompt: str, field: str, n: int,
                    code: str = "", taint: bool = False) -> tuple[bool, tuple[bool, ...]]:
        """问 n 次，多数票为结论。

        并发发出而不是串行：n=3 时串行等于把延迟乘 3，并发只多占一点配额。
        奇数票才不会平局；偶数票平局时按「不判定通过」处理（保守，避免误报）。

        `code` 非空时启用 Cite-Before-Verdict：每轮采样必须先给出引用行，
        且该行必须真实存在于 `code` 中、不是注释行。

        `taint=True` 时对 **Yes** 的票额外要求 `source_line` + `sink_line` 两行。
        只引一行是这套机制最早的一个洞：模型看到 sink 就把它填进 evidence_line，
        核验当然通过（那行真实存在、非注释），但"外部输入是否流入"这个条件
        从没被检查过。`XMLDecoderVul.safe` 上两个模型一致误报就是这么来的 ——
        它引用 `new XMLDecoder(...)` 完全合规，而方法根本没有入参。
        强制它分别贴出两行，找不到 source_line 时它只能答 No。

        核验不过的那一票**直接作废**（不进票箱），而不是记成 No ——
        "证据编造"和"判定为安全"是两件完全不同的事，混在一起会让
        置信度被虚假拉高。全部作废时抛异常，由调用方记为判定失败。
        """
        if n <= 1:
            raw = await self._ask(prompt)
            ok, why = self._check_evidence(raw, code, taint)
            if not ok:
                raise RuntimeError(f"证据核验失败：{why}")
            return _is_yes(raw, field), ()
        results = await asyncio.gather(
            *(self._ask(prompt) for _ in range(n)), return_exceptions=True)
        votes: list[bool] = []
        discarded = 0
        for r in results:
            if isinstance(r, Exception):
                continue
            ok, _why = self._check_evidence(r, code, taint)
            if not ok:
                discarded += 1
                continue
            votes.append(_is_yes(r, field))
        if not votes:
            raise RuntimeError(
                f"多次采样全部失败（其中 {discarded} 票因证据核验不过被作废）")
        yes = sum(votes)
        return yes * 2 > len(votes), tuple(votes)

    @staticmethod
    def _check_evidence(raw: str, code: str, taint: bool = False) -> tuple[bool, str]:
        """提取引用行并核验。`code` 为空时不做核验（兼容旧调用）。"""
        if not code:
            return True, ""
        try:
            data = extract_json(raw)
        except Exception:
            return False, "输出不是合法 JSON，无法提取引用行"
        if not isinstance(data, dict):
            return False, "输出不是 JSON 对象"

        is_yes = str(data.get("hit", "")).strip().lower().startswith("y")
        if taint and is_yes:
            src = str(data.get("source_line", ""))
            snk = str(data.get("sink_line", ""))
            for name, ev in (("source_line", src), ("sink_line", snk)):
                ok, why = verify_evidence(code, ev)
                if not ok:
                    return False, f"{name}: {why}"
            if _normalize_line(src) == _normalize_line(snk):
                # 两行相同等于只引了一行，条件 (2) 仍然没被证明
                return False, "source_line 与 sink_line 相同，未证明输入流入"
            if re.match(r"^\s*@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b", src.strip()):
                # 路由注解只说明"这个 URL 映射到本方法"，不说明"哪里接收输入"
                return False, "source_line 引用的是路由注解行，不是输入接收行"
            return True, ""
        return verify_evidence(code, str(data.get("evidence_line", "")))

    # ---------- 新接口：按类目做两步法 ----------

    async def audit_unit_for(self, unit: CodeUnit, category_keys: Sequence[str],
                             language: str | None = None) -> list[VulnHypothesis]:
        """对单个 unit 按给定类目列表逐一执行 Scenario + Property。"""
        lang = LANG_TAG.get(language or self.code_language, "java")
        out: list[VulnHypothesis] = []
        for key in category_keys:
            cat = VC.get(key)
            if cat is None:
                continue
            # RuleDiagnostic（Module 9 接线）：规则层对该类目退回 None 时，
            # 把"静态前筛已核实事实"（候选输入行 / sink 行）作为注释头拼进
            # 送审代码顶部。与 cli.py cmd_scan_java 同一套机制，但这里**不
            # 变异** unit.source_code（按类目建局部 code），且已有头的切片
            # 不重复注入。注释行不是可引用证据，Cite-Before-Verdict 会拒绝。
            code = unit.source_code
            if "静态前筛已核实事实" not in code:
                hdr = build_rule_diagnostic(key, code, line_offset=1)
                if hdr:
                    code = hdr + "\n" + code
            # Step 1: Scenario（配置型缺陷走不要求污点可达的模板）
            tmpl = SCENARIO_PROMPT_TMPL if cat.needs_taint else CONFIG_SCENARIO_PROMPT_TMPL
            if cat.needs_taint:
                # 把"入口有没有外部输入"这个事实告诉模型，但不替它下结论。
                # 直接短路判 False 会漏报（见 _NO_SOURCE_HINT 的注释）。
                hint = _HAS_SOURCE_HINT if has_external_input(unit.source_code) \
                    else _NO_SOURCE_HINT
                try:
                    hit, s_votes = await self._vote(
                        tmpl.format(lang=lang, question=cat.sink_question,
                                    code=code, source_hint=hint),
                        "hit", self.scenario_votes, code=code, taint=True)
                except Exception as e:
                    out.append(VulnHypothesis(unit=unit, vuln_type=key, scenario_hit=False,
                                              property_missing="",
                                              reasoning_summary=f"LLM 调用失败：{type(e).__name__}: {e}"))
                    continue
            else:
                try:
                    hit, s_votes = await self._vote(
                        tmpl.format(lang=lang, question=cat.sink_question,
                                    code=code),
                        "hit", self.scenario_votes, code=code)
                except Exception as e:
                    out.append(VulnHypothesis(unit=unit, vuln_type=key, scenario_hit=False,
                                              property_missing="",
                                              reasoning_summary=f"LLM 调用失败：{type(e).__name__}: {e}"))
                    continue
            if not hit:
                continue
            # Step 2: Property
            try:
                protected, p_votes = await self._vote(
                    PROPERTY_PROMPT_TMPL.format(
                        property=cat.property, lang=lang, code=code),
                    "protected", self.property_votes, code=code)
            except Exception as e:
                out.append(VulnHypothesis(unit=unit, vuln_type=key, scenario_hit=True,
                                          property_missing="",
                                          reasoning_summary=f"LLM 调用失败：{type(e).__name__}: {e}"))
                continue
            all_votes = s_votes + p_votes
            # 单票模式（默认 votes=1，也是 smartbugs / OWASP 的默认口径）下
            # 票箱本来就是空的 —— 空票箱不可能是"不一致"。原先写成
            # `bool(all_votes) and len(set(...))==1`，单票时恒 False，
            # 于是每条判定都带上"（采样不一致）"，读日志的人会以为模型
            # 自我矛盾，其实是这个标签在说谎（Module 17 模型层实跑抓出：
            # 197 条里 192 条理由全是"采样不一致"）。只有真投了 ≥2 票
            # 且票面不同，才配叫不一致。
            multi_vote = len(all_votes) > 1
            unanimous = multi_vote and len(set(all_votes)) == 1
            inconsistent = multi_vote and not unanimous
            # 有一轮说"不安全"才判漏洞，但票数越悬殊置信度越低：
            # 3:0 给 0.7，2:1 给 0.45 —— 后者应当优先送人工复核而不是直接采信。
            if protected:
                conf = 0.3 if unanimous else 0.2
            else:
                miss = sum(1 for v in p_votes if not v)
                conf = 0.7 if miss == len(p_votes) else 0.45
            out.append(VulnHypothesis(
                unit=unit, vuln_type=key, scenario_hit=True,
                property_missing="" if protected else cat.property,
                reasoning_summary=(f"Scenario={key}=HIT, PropertyCheck="
                                   f"{'PRESENT' if protected else 'MISSING'}"
                                   f"{'（采样不一致）' if inconsistent else ''}"),
                confidence=conf,
                votes=all_votes,
            ))
        return out

    async def audit_many(self, jobs: Sequence[tuple[CodeUnit, Sequence[str]]],
                         language: str | None = None) -> list[list[VulnHypothesis]]:
        """并发初筛：jobs 为 (unit, category_keys) 列表，返回与 jobs 对齐的结果。"""
        sem = asyncio.Semaphore(max(1, self.max_concurrency))

        async def _one(unit, keys):
            async with sem:
                return await self.audit_unit_for(unit, keys, language)

        return list(await asyncio.gather(*(_one(u, k) for u, k in jobs)))

    # ---------- 旧接口（Python Web 赛道，保持向后兼容） ----------

    async def audit_unit(self, unit: CodeUnit) -> list[VulnHypothesis]:
        """对单个 CodeUnit 执行旧版场景两步法。"""
        questions = "\n".join(f'"{s["id"]}": Does the code hit this scenario? "{s["question"]}"'
                              for s in WEB_SCENARIOS)
        s1 = await self._ask(SCENARIO_PROMPT_TMPL_V1.format(questions=questions,
                                                            code=unit.source_code))
        verdicts = extract_json(s1)

        hypotheses: list[VulnHypothesis] = []
        for scenario in WEB_SCENARIOS:
            if str(verdicts.get(scenario["id"], "No")).lower() != "yes":
                continue
            p = await self._ask(PROPERTY_PROMPT_TMPL_V1.format(property=scenario["property"],
                                                               code=unit.source_code))
            missing = "no" in p.lower()
            hypotheses.append(VulnHypothesis(
                unit=unit, vuln_type=scenario["id"], scenario_hit=True,
                property_missing=(scenario["property"] if missing else ""),
                reasoning_summary=f"Scenario={scenario['id']}, PropertyCheck={'MISSING' if missing else 'present'}",
                confidence=0.6 if missing else 0.1,
            ))
        return hypotheses

    async def audit_repo(self, units: list[CodeUnit]) -> list[VulnHypothesis]:
        """旧漏斗：全部 unit 走 Tier-1，仅 property_missing 的进入 Tier-2 队列。"""
        all_h: list[VulnHypothesis] = []
        for unit in units:
            all_h.extend(await self.audit_unit(unit))
        return [h for h in all_h if h.property_missing]
