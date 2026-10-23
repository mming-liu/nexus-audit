"""跨语言污点证据链可视化（M49）：把切片渲染成 Mermaid 污点传播路径图。

## 为什么需要这一层

判定结果是"是/否"，但**为什么是**要人顺着切片自己数跳：入口在哪、
中间跨了几个文件、最终汇点在第几行。审阅者每看一条结论就要重走一遍
这条链 —— 而这条链恰好是结论唯一的说服力来源。

本模块把切片里的既有标记（Full-Route / [Hop N] / 跨文件证据段 / Sink 行）
直接渲染成一张图：

    Controller.getUser  →  ServiceImpl.query  →  Mapper.xml:42

## 口径

  · 节点只画**切片里真实存在的段** —— 不推断、不补全；
  · Sink 行号用"来源文件 + 基准行 + 段内偏移"推算，基准来自切片自己的
    标记（入口段的 start_line、`// 来自 X.java:35 [Hop 1]` 的 35）；
  · 找不到 Sink 就不画 Sink 节点（只画传播链）—— 宁可少画，不画假的；
  · Mermaid 标签里的引号/方括号/大括号必须转义，否则整张图渲染失败。
"""
from __future__ import annotations

import re

from core.models import CodeUnit

# ---------------- 类目 → 汇点形态（与 triage_fallbacks 同源的最小集）------

SINK_RES: dict[str, re.Pattern[str]] = {
    "sqli": re.compile(r"execute(?:Query|Update)|prepareStatement|createStatement"
                       r"|JdbcTemplate|\$\{|\.apply\s*\(|\.last\s*\(", re.I),
    "authz": re.compile(r"(?:Service|Mapper|Dao|DAO)\s*\.\s*\w+\s*\("),
    "pathtraver": re.compile(r"new\s+File\s*\(|Paths\s*\.|FileInputStream|"
                             r"Files\s*\.\w+\s*\(|open\s*\(", re.I),
    "xss": re.compile(r"out\s*\.\s*print|println|write\s*\(|render_template", re.I),
    "cmdi": re.compile(r"Runtime\s*\.\s*getRuntime|exec\s*\(|subprocess|os\.system", re.I),
    "deserial": re.compile(r"readObject\s*\(|ObjectInputStream|loads\s*\(|"
                           r"load\s*\(|yaml\s*\.\s*(?:unsafe_)?load", re.I),
    "ssrf": re.compile(r"openConnection|URLConnection|requests\.|urlopen|HttpClient", re.I),
    "xxe": re.compile(r"DocumentBuilder|parse\s*\(|fromstring|XMLReader|SAX", re.I),
    "reentrancy": re.compile(r"\.\s*call\s*(?:\{|\.|\()|\.\s*(?:send|transfer)\s*\("),
    "access_control": re.compile(r"selfdestruct|suicide|owner\s*=|msg\s*\.\s*sender"
                                 r"|transferOwnership", re.I),
}

# 切片里的段标记
_FULL_ROUTE_RE = re.compile(r"^//\s*Full-Route:\s*(\S+)", re.M)
_HOP_RE = re.compile(r"^//\s*来自\s+(.+?)\s+\[Hop\s+(\d+)\]", re.M)
_IMPL_RE = re.compile(r"^//\s*----\s*跨文件证据：(.+?)\s*@\s*(.+?)\s*----", re.M)


def _esc(text: str) -> str:
    """Mermaid 标签转义：引号/方括号/大括号/换行都会破坏渲染。"""
    text = (text or "").replace("\\", "/")
    text = text.replace('"', "'").replace("[", "(").replace("]", ")")
    # 花括号用 HTML 实体：路由里的 {id} 是有效信息，不能像方括号那样丢掉
    text = text.replace("{", "&lbrace;").replace("}", "&rbrace;")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:120]


def _node_id(prefix: str, idx: int) -> str:
    return f"{prefix}{idx}"


def _lookup_line(file_path: str, code_text: str) -> int | None:
    """在源文件里回查某行代码的真实行号。

    为什么不用切片偏移推算：切片的段基准只有入口段可靠（start_line），
    同文件辅助方法段的起始行**未知**（切片不告诉你它来自第几行）。
    与其猜，不如回源文件查 —— 切片里的每一行本来就来自源文件。
    规范化（去全部空白）后比对，避免缩进差异导致匹配不上。
    """
    if not file_path:
        return None
    try:
        from pathlib import Path
        text = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    needle = re.sub(r"\s+", "", code_text)
    if not needle:
        return None
    for i, ln in enumerate(text.splitlines(), 1):
        if re.sub(r"\s+", "", ln) == needle:
            return i
    return None


def _segments(source: str, start_line: int = 1, file_path: str = "") -> list[dict]:
    """把切片切成段：{kind, title, file, base_line, text, offset}。

    kind: entry（入口体）/ hop（跨文件辅助方法）/ impl（接口实现类方法体）
    base_line: 该段首行对应的源文件行号（None = 不可知）

    entry 段的基准 = unit.start_line：切片头部的 Full-Route 等标记是
    **注释**，不是源文件行，所以基准要按"入口段第一个代码行"倒推。
    """
    lines = source.splitlines()
    segs: list[dict] = []
    cur = {"kind": "entry", "title": "", "file": file_path,
           "base_line": None, "lines": [], "offset": 0}
    for i, ln in enumerate(lines):
        mh = _HOP_RE.match(ln)
        mi = _IMPL_RE.match(ln)
        # 同文件辅助方法段：分隔注释形态有多种，用"----"包起来的段头认
        if (mh is None and mi is None
                and re.match(r"^//\s*----\s*.*(辅助方法|同文件|证据)", ln)):
            if cur["lines"]:
                segs.append(cur)
            title = re.sub(r"^//\s*----\s*", "", ln).rstrip(" -").strip()
            # 框架装配证据 / 配置取值 / 视图模板：判定依据，不是数据流的一跳
            kind = ("context"
                    if re.search(r"框架装配|配置|视图|模板", title) else "helper")
            cur = {"kind": kind, "title": title, "file": file_path,
                   "base_line": None, "lines": [], "offset": i + 1}
            continue
        if mh:
            if cur["lines"]:
                segs.append(cur)
            fname = mh.group(1)
            base = None
            mb = re.search(r":(\d+)", fname)
            if mb:
                base = int(mb.group(1))
            cur = {"kind": "hop", "title": fname,
                   "file": fname.split(":")[0] if ":" in fname else fname,
                   "base_line": base, "lines": [], "offset": i + 1}
            continue
        if mi:
            if cur["lines"]:
                segs.append(cur)
            cur = {"kind": "impl", "title": mi.group(1), "file": mi.group(2),
                   "base_line": None, "lines": [], "offset": i + 1}
            continue
        cur["lines"].append(ln)
    if cur["lines"]:
        segs.append(cur)
    # entry 段基准行倒推：以**方法声明行**为基准（切片器的 start_line
    # 指的就是方法声明行，注解行在它上面）
    if segs and segs[0]["kind"] == "entry":
        for k, ln in enumerate(segs[0]["lines"]):
            code = ln.split("//")[0]
            if re.search(r"(?:public|protected|private)\s+[\w<>\[\],\.]+\s+\w+\s*\(",
                         code):
                segs[0]["base_line"] = start_line - k
                break
    return segs


def _find_sink(segments: list[dict], category: str,
                file_path: str = "") -> dict | None:
    """在段里找汇点行，返回 {file, line, text, seg_index}。

    行号优先**回源文件查**（准确）；查不到才退回段基准 + 偏移（近似）。
    """
    rx = SINK_RES.get(category)
    if rx is None:
        return None
    for si, seg in enumerate(segments):
        for off, ln in enumerate(seg["lines"]):
            code = ln.split("//")[0]
            if not code.strip():
                continue
            if rx.search(code):
                line_no = _lookup_line(file_path or seg["file"], code)
                if line_no is None and seg["base_line"] is not None:
                    line_no = seg["base_line"] + off
                return {"file": seg["file"], "line": line_no,
                        "text": code.strip(), "seg_index": si}
    return None


def build_taint_graph(unit: CodeUnit, category: str) -> str:
    """生成 Mermaid flowchart LR 污点传播路径图（空串 = 没有可画的内容）。"""
    src = unit.source_code or ""
    if not src.strip():
        return ""
    mroute = _FULL_ROUTE_RE.search(src)
    route = mroute.group(1) if mroute else (unit.route_path or unit.unit_name)
    segs = _segments(src, unit.start_line, unit.file_path)
    if not segs:
        return ""
    sink = _find_sink(segs, category, unit.file_path)

    lines = ["```mermaid", "flowchart LR"]
    ids: list[str] = []
    node_of: dict[int, str] = {}
    for i, seg in enumerate(segs):
        if not any(x.strip() for x in seg["lines"]):
            continue
        # 非污点段不进传播链：框架装配证据 / 配置取值 / 视图模板是
        # "判定依据"，不是"数据流的一跳" —— 混进链里会让读者误以为
        # 数据流经��了这些组件。
        if seg["kind"] == "context":
            continue
        nid = _node_id("N", i)
        ids.append(nid)
        node_of[i] = nid
        if seg["kind"] == "entry":
            # 入口节点带**路由名**（Full-Route）—— 审阅者第一眼要看到的是
            # "哪条 HTTP 路由"，不是"哪个文件第几行"。
            title = f"{unit.unit_name}  {route}"
            label = _esc(title)
        else:
            title = seg["title"] or seg["kind"]
            fpart = (seg["file"] or unit.file_path or "").replace("\\", "/")
            if "/" in fpart:
                fpart = fpart.rsplit("/", 1)[-1]
            label = _esc(f"{title}  ({fpart})" if fpart else title)
        lines.append(f'  {nid}["{label}"]')
    if not ids:
        return ""
    # 链式相连：入口 → Hop1 → Hop2 → ...
    for a, b in zip(ids, ids[1:]):
        lines.append(f"  {a} --> {b}")
    if sink is not None:
        sid = "SINK"
        # 位置只留文件名 + 行号：全路径在 Mermaid 标签里太长，会把行号挤掉
        fpart = sink["file"] or "?"
        if "/" in fpart or "\\" in fpart:
            fpart = fpart.replace("\\", "/").rsplit("/", 1)[-1]
        loc = f"{fpart}:{sink['line']}" if sink["line"] else fpart
        lines.append(f'  {sid}["Sink: {_esc(sink["text"][:60])}<br/>{_esc(loc)}"]')
        # Sink 挂在**它实际所在**的段上（污点流到汇点的那一跳）
        host = node_of.get(sink["seg_index"]) or (ids[-1] if ids else None)
        if host:
            lines.append(f"  {host} --> {sid}")
    lines.append("```")
    return "\n".join(lines)


def graph_for_units(units: list[CodeUnit], category: str,
                    limit: int = 20) -> str:
    """批量生成：每个命中一段图。"""
    out: list[str] = []
    n = 0
    for u in units:
        g = build_taint_graph(u, category)
        if not g:
            continue
        out.append(f"### {u.unit_name}  ·  {category}")
        out.append("")
        out.append(g)
        out.append("")
        n += 1
        if n >= limit:
            break
    return "\n".join(out)
