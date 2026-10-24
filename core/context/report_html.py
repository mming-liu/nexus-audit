"""零外部依赖的单文件 HTML 交互式审计报告（Module 57）。

设计约束：
  · **零外部依赖** —— 纯内联 CSS，不引任何 JS/CSS 库，单文件可直接
    邮件/工单/IM 传阅，离线可开；
  · **防自注入** —— 所有源码/消息经 `html.escape` 严格转义后再入 HTML
    （被审计代码里出现 `<script>` 时，报告自身不能被执行）；
  · 可折叠详情卡片（`<details>`）：带行号与 Sink 行高亮的代码块、
    污点传播路径摘要、`--fix` 自检通过的 Diff 补丁展示框。

entries 与 SARIF 导出共用同一份 dict 结构（单一事实源）：
  {file, line, category, unit, message, level?, flow?, code?, fix_diff?}
  · code      —— 可选，入口单元完整源码（渲染带行号的代码块）
  · code_from —— code 的起始行号（默认 1），用于计算 Sink 行在代码块里的偏移
  · fix_diff  —— 可选，`--fix` 自检通过的 unified diff 文本
  · flow      —— 可选，污点路径 [{file, line, message?}, ...]
"""
from __future__ import annotations

import html
from collections import Counter


_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
       margin: 0; background: #f5f6f8; color: #1c2430; }
header { background: #16233a; color: #fff; padding: 20px 28px; }
header h1 { margin: 0 0 6px; font-size: 20px; }
header .meta { color: #9fb0c9; font-size: 13px; }
.stats { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 14px; }
.stat { background: #22334f; border-radius: 8px; padding: 10px 16px; }
.stat .num { font-size: 22px; font-weight: 700; }
.stat .lbl { font-size: 12px; color: #9fb0c9; }
main { padding: 18px 28px 40px; }
details.card { background: #fff; border: 1px solid #dfe3ea; border-radius: 10px;
               margin: 12px 0; overflow: hidden; }
details.card > summary { cursor: pointer; padding: 12px 16px; font-weight: 600;
               display: flex; gap: 10px; align-items: baseline; }
details.card > summary:hover { background: #f0f4fa; }
.badge { font-size: 11px; font-weight: 700; border-radius: 6px; padding: 2px 8px;
         color: #fff; background: #c23934; }
.badge.note { background: #8a6d3b; }
.badge.p1 { background: #b06f1f; }
.badge.p2 { background: #5c6b80; }
.badge.p0 { background: #c23934; }
.fileinfo { font-weight: 400; color: #5a6675; font-size: 13px; }
pre.code { background: #101826; color: #d6e2f3; padding: 12px 14px;
           overflow-x: auto; font-size: 12.5px; line-height: 1.55;
           margin: 0; tab-size: 4; }
pre.code .ln { color: #55677f; user-select: none; display: inline-block;
               width: 3.2em; text-align: right; margin-right: 1.2em; }
pre.code .sink-line { background: #3d1f1e; display: block; border-left: 3px solid #e0524b; }
pre.diff { background: #101826; color: #cfe3c8; padding: 12px 14px;
           overflow-x: auto; font-size: 12.5px; }
pre.diff .add { color: #7fd07f; }
pre.diff .del { color: #e07f7f; }
.flow { font-size: 13px; color: #33404f; margin: 10px 16px; }
.flow li { margin: 3px 0; }
.fixbox { margin: 10px 16px 16px; }
.fixbox h4 { margin: 0 0 6px; font-size: 13px; color: #1f6f3f; }
h2.sec { font-size: 15px; color: #3c4654; border-bottom: 1px solid #dfe3ea;
         padding-bottom: 6px; margin: 26px 0 10px; }
"""


def _code_block(code: str, sink_line: int | None, code_from: int) -> str:
    """带行号的代码块，Sink 行高亮。所有行先 html.escape。"""
    rows = []
    for i, ln in enumerate(code.splitlines() or [""]):
        n = code_from + i
        esc = html.escape(ln)
        ln_html = f'<span class="ln">{n}</span>{esc}'
        if sink_line is not None and n == sink_line:
            rows.append(f'<span class="sink-line">{ln_html}</span>')
        else:
            rows.append(ln_html)
    return '<pre class="code">' + "\n".join(rows) + "</pre>"


def _diff_block(diff: str) -> str:
    out = ['<pre class="diff">']
    for ln in diff.splitlines():
        esc = html.escape(ln)
        cls = ""
        if ln.startswith("+") and not ln.startswith("+++"):
            cls = ' class="add"'
        elif ln.startswith("-") and not ln.startswith("---"):
            cls = ' class="del"'
        out.append(f"<span{cls}>{esc}</span>")
    out.append("</pre>")
    return "\n".join(out)


def _card(e: dict) -> str:
    """单条检出项的折叠详情卡片。"""
    cat = html.escape(str(e.get("category") or "UNKNOWN"))
    unit = html.escape(str(e.get("unit") or ""))
    file_ = html.escape(str(e.get("file") or "?"))
    line = e.get("line")
    msg = html.escape(str(e.get("message") or ""))
    level = "note" if e.get("level") == "note" else "hit"
    prio = str(e.get("priority") or ("P0" if level == "hit" else "P2"))
    badge_cls = {"P0": "p0", "P1": "p1", "P2": "p2"}.get(prio, "")
    code = e.get("code")
    code_from = int(e.get("code_from") or 1)
    parts = [
        f'<details class="card">',
        "<summary>"
        f'<span class="badge {badge_cls or level}">{html.escape(prio)}</span>'
        f'<span class="badge {level}">{cat}</span>'
        f"<span>{unit}</span>"
        f'<span class="fileinfo">{file_}'
        f'{":" + str(line) if line else ""}</span>'
        "</summary>",
        f'<div class="flow">{msg}</div>' if msg else "",
    ]
    if e.get("flow"):
        items = "".join(
            f"<li>{html.escape(str(f_.get('file') or '?'))}"
            f"{':' + str(f_.get('line')) if f_.get('line') else ''}"
            f"{(' —— ' + html.escape(str(f_.get('message')))) if f_.get('message') else ''}"
            "</li>"
            for f_ in e["flow"])
        parts.append(f'<ul class="flow">{items}</ul>')
    if code:
        parts.append(_code_block(code, line, code_from))
    if e.get("fix_diff"):
        parts.append('<div class="fixbox"><h4>✔ 自检通过的确定性补丁'
                     "（重切片 + 规则翻转 False 验证）</h4>"
                     + _diff_block(str(e["fix_diff"])) + "</div>")
    parts.append("</details>")
    return "\n".join(parts)


def build_html_report(entries: list[dict], repo: str = ".",
                      title: str = "nexus-audit 审计报告",
                      funnel: dict | None = None) -> str:
    """把检出项序列化为单文件 HTML。entries 结构见模块 docstring。

    funnel（可选，M66）：{"total_units", "p0_confirmed", "funnel_filtered",
    "funnel_dispatched"} —— 顶部仪表盘渲染二级漏斗效率与类目热力条。
    """
    n_total = len(entries)
    n_hit = sum(1 for e in entries if e.get("level") != "note")
    by_cat = Counter(str(e.get("category") or "UNKNOWN").upper()
                     for e in entries)
    by_prio = Counter(str(e.get("priority") or ("P0" if e.get("level") != "note"
                                                else "P2")) for e in entries)
    stats = [f'<div class="stat"><div class="num">{n_total}</div>'
             '<div class="lbl">检出项</div></div>',
             f'<div class="stat"><div class="num">{n_hit}</div>'
             '<div class="lbl">实锤 / 高危</div></div>']
    stats += [f'<div class="stat"><div class="num">{by_prio.get(p, 0)}</div>'
              f'<div class="lbl">{p}</div></div>' for p in ("P0", "P1", "P2")]
    stats += [f'<div class="stat"><div class="num">{n}</div>'
              f'<div class="lbl">{html.escape(c)}</div></div>'
              for c, n in by_cat.most_common()]

    # M66：漏斗效率仪表盘 + 类目热力条
    funnel_html = ""
    if funnel:
        total = funnel.get("funnel_filtered", 0) + funnel.get(
            "funnel_dispatched", 0)
        eff = (funnel.get("funnel_filtered", 0) / total * 100) if total else 0
        max_cat = max(by_cat.values()) if by_cat else 0
        bars = "".join(
            f'<div style="display:flex;align-items:center;gap:8px;'
            f'margin:3px 0;">'
            f'<div style="width:64px;color:#9fb0c9;font-size:12px;'
            f'text-align:right;">{html.escape(c)}</div>'
            f'<div style="flex:1;background:#22334f;border-radius:4px;">'
            f'<div style="width:{(n / max_cat * 100) if max_cat else 0:.0f}%;'
            f'background:#e0524b;height:10px;border-radius:4px;"></div>'
            f'</div><div style="color:#c9d4e4;font-size:12px;">{n}</div></div>'
            for c, n in by_cat.most_common())
        funnel_html = f"""
  <div class="stats">
    <div class="stat"><div class="num">{funnel.get("total_units", 0)}</div>
      <div class="lbl">切片单元</div></div>
    <div class="stat"><div class="num">{eff:.1f}%</div>
      <div class="lbl">漏斗过滤率</div></div>
    <div class="stat"><div class="num">{funnel.get("funnel_dispatched", 0)}</div>
      <div class="lbl">模型派发</div></div>
    <div class="stat"><div class="num">{funnel.get("p0_confirmed", 0)}</div>
      <div class="lbl">P0 实锤</div></div>
  </div>
  <div style="margin-top:12px;background:#16233a;border-radius:8px;
              padding:10px 14px;">{bars or '<i style="color:#556;">无检出</i>'}
  </div>"""

    cards = "\n".join(_card(e) for e in entries)
    esc_repo = html.escape(str(repo))
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>{html.escape(title)}</h1>
  <div class="meta">仓库：{esc_repo} · 由 nexus-audit 规则层 + 确定性补丁自检生成</div>
  <div class="stats">{''.join(stats)}</div>
  {funnel_html}
</header>
<main>
{cards}
</main>
</body>
</html>
"""
