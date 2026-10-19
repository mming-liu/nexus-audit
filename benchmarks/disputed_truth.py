"""真值争议登记簿：把"靶场标错"从注释里的字符串升级成可导出的结构化数据。

为什么需要这个模块
------------------

跑异源靶场时总会撞到一类样本：**语义上明显是漏洞，靶场却标 safe**（或反过来）。
本项目已经按铁律处理过三次，处置方式一致 —— 单列、不进分母、不改判据：

    ReflectController.safe2   打 CSP header 后裸回显 `return payload`
    XMLDecoderVul.safe        同一 API（readUnshared）在另一处标 vul
    Traversal.safe2           只有 normalize()，无基目录包含校验

但在此之前，这些判断只是三个脚本里各自的 `DISPUTED_TRUTH = {...}` 字典，
一条一句中文说明。这带来三个问题：

  1. **不能横向比对**：想知道"哪些是同一类口径分歧"只能靠读中文。
  2. **证据缺失**：只写了结论，没写"靶场原文怎么标的""我们判什么""源码在哪一行"。
     别人复核时必须重新去翻源码 —— 而复核者往往就是靶场维护者本人。
  3. **无法导出**：想给靶场提 issue，得手工拼。

所以这里做两件事：

  * `Dispute` —— 结构化一条争议：靶场、样本、类目、标注值、我们的判定、
    证据行（文件名 + 行号 + 原文）、口径分歧的类型、以及给外部看的说明。
  * `REGISTRY` —— 全项目唯一的争议清单。各 benchmark 脚本从这里取，
    不再各写一份。

导出
----

`render_markdown()` 产出一份可直接贴进 GitHub issue 的报告：每条含
"靶场标注 vs 本项目判定 + 源码证据 + 分歧类型"，并按分歧类型归类 ——
同类分歧合并呈现，便于维护者一次看清"这不是三条孤立的错，是同一种口径问题"。

**分歧类型不是随便打的标签**，它决定了建议的处置：

    defense_in_depth   把纵深防御当修复（CSP / WAF / 连接池过滤）
    not_the_property   拦的不是本类目关心的那个性质（normalize 之于路径遍历）
    self_contradiction 同一靶场内两个样本的标注互相矛盾
    demo_convention    作者按"演示意图"标，与本项目"是否存在可达注入面"口径不同

判定层不读这个模块（`rule_detectors` 完全不 import 它）——
争议是**评测口径**的事，不能回流到检测逻辑里，否则就是"为迁就靶场改判据"。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal

DisputeKind = Literal[
    "defense_in_depth",
    "not_the_property",
    "self_contradiction",
    "demo_convention",
]

KIND_LABEL: dict[str, str] = {
    "defense_in_depth": "把纵深防御当修复",
    "not_the_property": "拦的不是本类目关心的性质",
    "self_contradiction": "同一靶场内标注自相矛盾",
    "demo_convention": "作者演示口径与本项目口径不同",
}


@dataclass
class Evidence:
    """一条可逐行核对的源码证据。

    刻意要求 file + line + text 三件套：只有文字说明的"证据"复核者无法验证，
    而本项目对模型引证的要求（cite-before-verdict：必须真实存在、不是注释行、
    无省略号）对规则自己也一样适用。
    """
    file: str                       # 仓库内相对路径
    line: int                       # 行号（1 起）
    text: str                       # 该行原文（strip 后）


@dataclass
class Dispute:
    target: str                     # 靶场标识，与 benchmark 的 TARGET 名一致
    unit: str                       # 样本名，形如 'ReflectController.safe2'
    category: str
    labeled: bool                   # 靶场标的值（True=vul, False=safe）
    our_verdict: bool | None        # 本项目判定（None = 我们认为不可判）
    kind: DisputeKind
    summary: str                    # 一句话结论（进标题行）
    detail: str                     # 完整理由（进正文）
    evidence: list[Evidence] = field(default_factory=list)
    # 我们的判定来自哪一层：rule=确定性规则 / model=模型投票 / none=不可判
    decided_by: str = "rule"

    def one_line(self) -> str:
        return (f"[{self.category}] {self.unit}  "
                f"靶场={self.labeled!s:5} 本项目={self.our_verdict!s:5}  "
                f"{KIND_LABEL[self.kind]}")


# ---------------- 全项目争议清单 ----------------
#
# 新增一条时的要求（缺一条就不要登记）：
#   1. 说得清"靶场凭什么标 safe/vul"与"我们凭什么判相反"；
#   2. 至少一条带行号的源码证据；
#   3. 归到一个已有的 kind 里，或先扩 DisputeKind 并写明该 kind 的处置建议。

REGISTRY: list[Dispute] = [
    Dispute(
        target="JavaSecLab",
        unit="ReflectController.safe2",
        category="xss",
        labeled=False,
        our_verdict=True,
        kind="defense_in_depth",
        decided_by="rule",
        summary="打 CSP header 后仍裸回显，CSP 不是输出编码",
        detail=(
            "方法设置了 Content-Security-Policy 响应头，但随后 `return payload;` "
            "把请求参数原样交回响应体，没有任何输出编码。"
            "CSP 是浏览器侧的纵深防御，可降低脚本执行概率，但它不改变"
            "「用户输入原样进入 HTML」这一事实；一旦策略被放宽、被 "
            "script-src 'unsafe-inline' 覆盖，或数据被前端 innerHTML 二次渲染，"
            "注入即成立。"
            "值得注意的是作者自己在 @ApiOperation 的 notes 里写了"
            "「不能替代输出编码与安全模板/DOM用法」—— 标注与注释互相矛盾。"
            "本项目 xss 类目的口径是「输入是否原样进入响应体」，故判 True。"
        ),
        evidence=[
            Evidence(
                file="src/main/java/top/whgojp/modules/xss/controller/ReflectController.java",
                line=124,
                text='response.setHeader("Content-Security-Policy", "default-src \'self\'; '
                     'script-src \'self\'");',
            ),
            Evidence(
                file="src/main/java/top/whgojp/modules/xss/controller/ReflectController.java",
                line=127,
                text="return payload;",
            ),
        ],
    ),
    Dispute(
        target="Hello-Java-Sec",
        unit="XMLDecoderVul.safe",
        category="deserial",
        labeled=False,
        our_verdict=True,
        kind="self_contradiction",
        decided_by="rule",
        summary="同一 API（readUnshared）在同靶场另一处标 vul",
        detail=(
            "`XMLDecoderVul.safe` 用 `new ObjectInputStream(bis).readUnshared()`；"
            "同靶场的 `Deserialization.readUnshared` 用同一个 API，却被标为 vul。"
            "readUnshared 只影响对象引用共享（读到重复引用抛异常），"
            "**不做任何类型过滤**，安全性质与 readObject 完全相同，CWE-502 同样适用。"
            "两处标注不可能同时成立，至少有一处错。"
            "本项目与「标 vul 的那一处」一致，故判 True。"
        ),
        evidence=[
            Evidence(
                file="src/main/java/com/best/hello/controller/Deserialization/XMLDecoderVul.java",
                line=52,
                text="* 替换XMLDecoder类，使用更安全的ObjectInputStream.readUnshared",
            ),
            Evidence(
                file="src/main/java/com/best/hello/controller/Deserialization/XMLDecoderVul.java",
                line=66,
                text="Object obj = ois.readUnshared();",
            ),
            Evidence(
                file="src/main/java/com/best/hello/controller/Deserialization/Deserialization.java",
                line=96,
                text="in.readUnshared();",
            ),
        ],
    ),
    Dispute(
        target="Hello-Java-Sec",
        unit="Traversal.safe2",
        category="pathtraver",
        labeled=False,
        our_verdict=True,
        kind="not_the_property",
        decided_by="rule",
        summary="只有 normalize()，没有基目录包含校验",
        detail=(
            "唯一防护是 `Paths.get(filePath).normalize().toString()`。"
            "normalize 只做**词法**规范化（消解 `.` 与 `..` 段），"
            "不判断结果是否仍在基目录内：`logs/../../etc/passwd` 规范化后是"
            "`../etc/passwd`，照样逃出 `logs/`。"
            "真正构成防护的是「规范化**之后**再校验包含关系」"
            "（`getCanonicalPath().startsWith(baseDir)` 或 `toRealPath()` 对照），"
            "本样本没有这一步。"
            "它拦的不是路径遍历关心的那个性质（是否限制在基目录内），"
            "与本类目口径不一致。"
        ),
        evidence=[
            Evidence(file="src/main/java/com/best/hello/controller/Traversal.java",
                     line=84,
                     text='String filePathSafe = Paths.get(filePath).normalize().toString();'),
        ],
    ),
    Dispute(
        target="OWASP",
        unit="BenchmarkTest01807",
        category="sqli",
        labeled=False,
        our_verdict=True,
        kind="self_contradiction",
        decided_by="rule",
        summary="charAt(2) 恒为 'C'，case 'C' 落进 bar = param，却标 safe",
        detail=(
            "`guess` 是字面量 \"ABC\"，`charAt(2)` 在编译期就是 `'C'`；"
            "switch 的 `case 'C': case 'D':` 直接落进 `bar = param;`，"
            "随后 `bar` 被拼进 "
            "\"SELECT * from USERS where USERNAME='foo' and PASSWORD='\" + bar + \"'\"，"
            "注入面成立。"
            "同模板的 BenchmarkTest01806 用 `charAt(1)`（'B' → `bar = \"bob\"`）标 safe，"
            "并在注释里写明「condition 'B', which is safe」—— 说明作者清楚这条判据"
            "取决于选中哪个 case；01807 换到 'C' 却没有同步改标注。"
            "**本条不参与跑分剔除**：OWASP 的 FPR 仍按 5/15 计，登记它是为了让复核者"
            "看到「这 1 条误报不是检测器的错」。"
        ),
        evidence=[
            Evidence(
                file="src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01807.java",
                line=75,
                text="char switchTarget = guess.charAt(2);",
            ),
            Evidence(
                file="src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01807.java",
                line=85,
                text="case 'C':",
            ),
            Evidence(
                file="src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01807.java",
                line=87,
                text="bar = param;",
            ),
            Evidence(
                file="src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01806.java",
                line=75,
                text="char switchTarget = guess.charAt(1); // condition 'B', which is safe",
            ),
        ],
    ),
]

_BY_TARGET: dict[str, dict[str, Dispute]] = {}
for _d in REGISTRY:
    _BY_TARGET.setdefault(_d.target, {})[_d.unit] = _d


def for_target(target: str) -> dict[str, str]:
    """返回 {unit: 理由}，供各 benchmark 脚本直接当 DISPUTED_TRUTH 用。

    兼容旧签名：脚本里原本是 `dict[str, str]`，判定处只用到 `in` 与取值
    打印，所以这里返回精简单句即可，不破坏调用方。
    """
    return {u: d.detail for u, d in _BY_TARGET.get(target, {}).items()}


def disputes_of(target: str) -> list[Dispute]:
    """返回该靶场的完整争议对象（导出报告时用）。"""
    return [d for d in REGISTRY if d.target == target]


def all_disputes() -> list[Dispute]:
    return list(REGISTRY)


# ---------------- 证据自校验 ----------------
#
# 本项目对模型的引证要求是「必须真实存在、不是注释行、无省略号」
# （cite-before-verdict）。规则自己写下的证据凭什么免检？
# 这里用同一把尺子量：登记的证据必须能在靶场源码里**逐字**找到。
#
# 为什么值得做：证据行号写错的报告比没有报告更糟 —— 维护者按行号跳过去，
# 看到的是无关代码，会直接怀疑整份报告的可信度。而这类错最容易在
# "先写结论再补证据"时发生（本轮就差点把行号全填 0）。

_TARGET_ROOTS = {
    "Hello-Java-Sec": "Hello-Java-Sec-master",
    "JavaSecLab": "JavaSecLab-main",
    "java-sec-code": "java-sec-code",
    "OWASP": "BenchmarkJava-master",
}
# 允许证据落在注释行：这里的用途是"指出标注与注释自相矛盾"，
# 那一行本身就是注释。与 cite-before-verdict 不同 —— 那条是防止模型
# 拿注释当代码证据；这里是要**引用**注释。
_COMMENT_EVIDENCE_OK = True


def verify_evidence(repo_root: str | Path) -> list[str]:
    """核对所有证据行；返回问题列表（空 = 全部通过）。"""
    root = Path(repo_root) / "reference_repos"
    problems: list[str] = []
    for d in REGISTRY:
        sub = _TARGET_ROOTS.get(d.target)
        if not sub:
            problems.append(f"{d.unit}: 未知靶场 {d.target}")
            continue
        for e in d.evidence:
            p = root / sub / e.file
            if not p.is_file():
                problems.append(f"{d.unit}: 文件不存在 {e.file}")
                continue
            if e.line <= 0:
                problems.append(f"{d.unit}: 未填行号 {e.file}")
                continue
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            if e.line > len(lines):
                problems.append(f"{d.unit}: 行号越界 {e.file}:{e.line}")
                continue
            actual = lines[e.line - 1].strip()
            if e.text.strip() not in actual:
                problems.append(
                    f"{d.unit}: 证据不符 {e.file}:{e.line}\n"
                    f"    登记: {e.text.strip()}\n"
                    f"    实际: {actual}")
    return problems


# ---------------- 导出 ----------------

def render_markdown(targets: list[str] | None = None) -> str:
    """渲染成可直接贴进 issue 的报告。

    按 kind 分组而不是按靶场分组 —— 同一个 kind 下的样本是**同一种口径问题**，
    这才是给维护者看的重点：不是"你错了三次"，而是"这三处是同一类分歧，
    如果你同意这个口径，三处都要改"。
    """
    items = REGISTRY if targets is None else [d for d in REGISTRY if d.target in targets]
    if not items:
        return "# 真值争议清单\n\n（无）\n"

    lines: list[str] = [
        "# 靶场真值争议清单",
        "",
        f"共 **{len(items)}** 条。每条都给出：靶场标注、本项目判定、源码证据、"
        "以及**分歧属于哪一类**。",
        "",
        "> 说明：本清单**不修改**任何靶场的评测口径，也不参与本项目检测规则。"
        "它记录的是「同一份代码，两种口径下结论相反」的事实，供维护者复核。",
        "",
        "| 靶场 | 样本 | 类目 | 靶场标注 | 本项目判定 | 分歧类型 |",
        "|---|---|---|---|---|---|",
    ]
    for d in items:
        lines.append(
            f"| {d.target} | `{d.unit}` | {d.category} | "
            f"{'vul（有漏洞）' if d.labeled else 'safe（安全）'} | "
            f"{'vul' if d.our_verdict else ('safe' if d.our_verdict is False else '不可判')} | "
            f"{KIND_LABEL[d.kind]} |")

    order: list[str] = []
    for d in items:
        if d.kind not in order:
            order.append(d.kind)

    for kind in order:
        group = [d for d in items if d.kind == kind]
        lines += ["", f"## {KIND_LABEL[kind]}", ""]
        lines.append(_KIND_ADVICE.get(kind, ""))
        lines.append("")
        for d in group:
            lines += [
                f"### `{d.unit}`（{d.target} / {d.category}）",
                "",
                f"**结论**：{d.summary}",
                "",
                f"**靶场标注**：{'vul' if d.labeled else 'safe'}　"
                f"**本项目判定**："
                f"{'vul' if d.our_verdict else ('safe' if d.our_verdict is False else '不可判')}"
                f"（{'确定性规则' if d.decided_by == 'rule' else '模型投票'}）",
                "",
                d.detail.strip(),
                "",
            ]
            if d.evidence:
                lines.append("**源码证据**：")
                lines.append("")
                for e in d.evidence:
                    loc = f"{e.file}:{e.line}" if e.line else e.file
                    lines.append(f"- `{loc}`　`{e.text}`")
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


_KIND_ADVICE = {
    "defense_in_depth":
        "这类分歧的共同点：样本确实加了某种**缓解措施**（CSP、WAF、连接池过滤），"
        "缓解能降低利用成功率，但不改变「存在注入面」这一事实。"
        "如果把这些样本标为 safe，评测会奖励「加了缓解但没修根因」的写法 —— "
        "而这正是真实项目里最难被发现的坏习惯。建议：要么改为 vul，"
        "要么在类目定义里显式声明「本类目只判代码层修复」。",
    "not_the_property":
        "这类分歧的共同点：防护函数**存在**且**确实做了点什么**，"
        "但拦的不是本类目关心的那个性质。"
        "判定一个防护是否成立，要先写清「本类目要的是哪个性质」，"
        "再看这段代码是否提供了它 —— 而不是看「有没有调用名叫 normalize/check 的函数」。",
    "self_contradiction":
        "这类分歧不需要讨论口径：同一个靶场内部，同一 API / 同一写法被标成了相反的结论。"
        "无论采信哪种口径，至少有一处需要修正。",
    "demo_convention":
        "这类分歧源于作者按「演示意图」标注（这个样本要演示什么），"
        "而本项目按「代码事实」判定（有没有可达注入面）。两者都有道理，"
        "但用于评测时需要统一。",
}


# ---------------- 单个靶场的 issue 草稿 ----------------
#
# 一份 issue 只讲**一个仓库**：维护者打开自己的 issue 列表时才不会看到
# 别人的问题混在里面。仓库内仍按 kind 分组 —— 同一种口径问题的三条样本
# 摆在一次讨论里，比拆成三个 issue 更容易一次谈定。

_TARGET_REPO = {
    "Hello-Java-Sec": "j3ers3/Hello-Java-Sec",
    "JavaSecLab": "whgojp/JavaSecLab",
    "OWASP": "OWASP-Benchmark/BenchmarkJava",
    "java-sec-code": "JoyChou93/java-sec-code",
}


def render_issue(target: str) -> str:
    """渲染某个靶场的 issue 草稿（标题 + 正文，直接可贴）。"""
    items = [d for d in REGISTRY if d.target == target]
    if not items:
        return ""
    repo = _TARGET_REPO.get(target, target)
    kinds: list[str] = []
    for d in items:
        if d.kind not in kinds:
            kinds.append(d.kind)

    lines = [
        f"# {len(items)} 个样本的真值（expected results）与本机静态分析结论不一致",
        "",
        f"仓库：`{repo}`　靶场：`{target}`",
        "",
        "在复现 [nexus-audit](https://github.com/mming-liu/nexus-audit) 的"
        "规则层评测时，以下样本的标注与代码事实不一致。每条都附了**行号级证据**，"
        "可以直接点进去核对；证据由脚本逐字比对过源码（行号写错会当场报错），"
        "不是凭印象写的。",
        "",
        "| 样本 | 类目 | 靶场标注 | 本项目判定 | 分歧类型 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for d in items:
        lines.append(
            f"| `{d.unit}` | {d.category} | "
            f"{'vul' if d.labeled else 'safe'} | "
            f"{'vul' if d.our_verdict else ('safe' if d.our_verdict is False else '不可判')} | "
            f"{KIND_LABEL[d.kind]} |")
    lines.append("")

    for kind in kinds:
        group = [d for d in items if d.kind == kind]
        lines += [f"## {KIND_LABEL[kind]}", "", _KIND_ADVICE.get(kind, ""), ""]
        for d in group:
            lines += [
                f"### `{d.unit}`",
                "",
                f"**结论**：{d.summary}",
                "",
                d.detail.strip(),
                "",
            ]
            if d.evidence:
                lines.append("**源码证据**：")
                lines.append("")
                for e in d.evidence:
                    loc = f"{e.file}:{e.line}" if e.line else e.file
                    lines.append(f"- `{loc}`　`{e.text}`")
                lines.append("")

    lines += [
        "## 我们的口径（供讨论）",
        "",
        "判定一律基于**可逐行核对的事实**：某个防护函数到底拦的是什么、"
        "某个变量最后一次赋值来自常量还是请求参数、某条分支是否恒真。"
        "凡是没有事实支点的，我们退回「不可判」而不给结论 —— "
        "所以这里列出的不是「我们猜你错了」，而是「这几行代码与标注对不上」。",
        "",
        "如果认为其中某条的标注是对的（例如本类目的口径本就包含缓解措施），"
        "欢迎指出 —— 我们更愿意改自己的口径说明，而不是改判据去迁就分数。",
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"


def dump_issues(out_dir: str | Path) -> list[Path]:
    """每个靶场一份 issue 草稿，返回写出的文件列表。"""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for target in dict.fromkeys(x.target for x in REGISTRY):
        text = render_issue(target)
        if not text:
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")
        p = d / f"issue-{slug}.md"
        p.write_text(text, encoding="utf-8")
        written.append(p)
    return written


def dump_json(path: str | Path, targets: list[str] | None = None) -> Path:
    items = REGISTRY if targets is None else [d for d in REGISTRY if d.target in targets]
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps([asdict(d) for d in items], ensure_ascii=False, indent=2),
        encoding="utf-8")
    return p
