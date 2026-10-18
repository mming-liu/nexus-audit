"""模板文件介质：把「视图名 + 键名」解析到模板里的渲染点。

为什么需要这一层
----------------

串接模型原本只覆盖 Java 内部能寻址的介质（cookie / session / request /
model 的读写都在 .java 文件里）。但 Spring MVC 最典型的存储/反射型 XSS
形态是跨**文件类型**的：

    // Controller                          // templates/vul/xss/other.html
    model.addAttribute("html", payload);   <p th:utext="${html}"></p>
    return "vul/xss/other";

写入端在 .java，读取点在 .html —— 切片里只有前者，判定器看到的是
"方法把输入放进 model 就返回了"，既不回显也不落库，只能判"无此漏洞"。
真值是漏洞。**这不属于规则判错，是证据根本不在切片里**。

解析链路分两步，每步都必须是"可核对的事实"：

    1) 视图名 → 模板文件路径
       `return "vul/xss/other"`  +  `spring.thymeleaf.prefix=classpath:/templates/`
       →  src/main/resources/templates/vul/xss/other.html
       找不到就是找不到，**不做模糊匹配**（模糊匹配会把别的页面贴进来，
       等于给模型塞无关证据）。

    2) 键名 → 渲染点
       只认模板语法里**显式带 key** 的表达式：`${key}` / `#{key}` / `[[${key}]]`。
       命中 `th:utext` / `<#noescape>` / `v-html` / `<%= %>` → 不转义；
       命中 `th:text` / `${}` 在文本节点里 → 自动转义。

**范围只取"包含该键的那几行"**（含上下文），不贴整个模板：模板动辄几百行，
整份贴进去会把入口方法体稀释掉，模型反而更容易漏看真正的渲染点。

能力边界
--------

- 只做**模板内**的渲染点识别。`th:each` 里对循环变量渲染、片段引用
  (`th:replace`)、以及 JS 里 innerHTML 写入，都不在这里建模 —— 它们需要
  读懂模板结构，不是正则能定的事实。
- 只认"入口直接返回视图名"和"ModelAndView 构造里给视图名"两种。视图名
  由变量拼接（`return "vul/" + type;`）属于运行时才知道的值，直接放弃。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# 模板根的候选（相对项目根）。Thymeleaf 默认 classpath:/templates/，
# FreeMarker 常见 /templates/，JSP 常见 /WEB-INF/jsp/。多个候选按序探测。
_TEMPLATE_ROOTS = (
    ("src/main/resources/templates", (".html", ".ftl", ".jsp")),
    ("src/main/webapp/WEB-INF/jsp", (".jsp",)),
    ("src/main/webapp", (".jsp", ".html")),
)

# 入口方法里"给定视图名"的写法。只收字面量，不做拼接推断。
_VIEW_NAME_RES = (
    re.compile(r"\breturn\s+\"(?P<v>[A-Za-z0-9_./-]+)\"\s*;"),           # return "vul/xss/other";
    re.compile(r"new\s+ModelAndView\s*\(\s*\"(?P<v>[A-Za-z0-9_./-]+)\""),  # new ModelAndView("x");
    re.compile(r"setViewName\s*\(\s*\"(?P<v>[A-Za-z0-9_./-]+)\""),        # mav.setViewName("x");
)

# 键名写入：model.addAttribute("k", v) / modelMap.put("k", v) / addObject("k", v)
_MODEL_PUT_RE = re.compile(
    r"\b(?:model|modelMap|mv|mav|modelAndView)\s*\.\s*"
    r"(?:addAttribute|put|addObject)\s*\(\s*\"(?P<key>[^\"]+)\"\s*,")

# 渲染点：一条语句里出现该键，且该语句含"不转义"指令
_NOESCAPE_RE = re.compile(
    r"th:utext\s*=|"
    r"<#noescape\s*>|"
    r"\bv-html\s*=|"
    r"\[\$\{|"                       # Thymeleaf 内联未转义 [[${...}]]
    r"innerHTML\s*=", re.I)
_ESCAPE_RE = re.compile(
    r"th:text\s*=|"
    r"\$\{[^}]*\}|"                  # Thymeleaf 内联默认转义 + 普通 ${}
    r"th:attr\s*=|"
    r"v-text\s*=", re.I)

_MAX_CONTEXT = 3        # 渲染点上下各取几行


@dataclass(frozen=True)
class TemplateHit:
    """模板里的一处渲染点。"""
    path: str               # 相对项目根的模板路径
    line: int               # 1-based 行号
    key: str
    raw: str                # 命中的原始行（已 strip）
    unescaped: bool         # True = 不转义（th:utext 等）

    def describe(self) -> str:
        how = "不转义渲染" if self.unescaped else "转义渲染"
        return f"{self.path}:{self.line}  {how} 键 \"{self.key}\""


def view_names(source: str) -> list[str]:
    """入口方法里返回/设置的**字面量**视图名。"""
    out: list[str] = []
    for rx in _VIEW_NAME_RES:
        for m in rx.finditer(source):
            v = m.group("v")
            if v and v not in out:
                out.append(v)
    return out


def model_keys(source: str) -> list[str]:
    """入口方法放进 model 的键名。"""
    out: list[str] = []
    for m in _MODEL_PUT_RE.finditer(source):
        k = m.group("key")
        if k not in out:
            out.append(k)
    return out


def resolve_template_path(repo_root: str | Path, view: str) -> Path | None:
    """视图名 → 模板文件。**不做模糊匹配**：找不到就返回 None。

    模糊匹配（按名字前缀/相似度挑一个"最像"的模板）看起来能提高命中率，
    实际是给模型塞无关证据 —— 它会照着别的页面的 `th:utext` 判漏洞。
    宁可漏，不可错。
    """
    root = Path(repo_root)
    if not root.exists():
        return None
    v = view.strip().strip("/")
    if not v or v.startswith("redirect:") or v.startswith("forward:"):
        return None
    for base, exts in _TEMPLATE_ROOTS:
        for ext in exts:
            p = root / base / (v + ext)
            if p.is_file():
                return p
    return None


def find_render_points(template: Path, keys: list[str],
                       max_hits: int = 4) -> list[TemplateHit]:
    """在模板里找渲染这些键的位置。只返回命中行，不返回整个文件。"""
    try:
        text = template.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if not keys:
        return []
    lines = text.splitlines()
    hits: list[TemplateHit] = []
    for i, ln in enumerate(lines, 1):
        for k in keys:
            # 键必须作为一个完整表达式出现：`${html}` / `${ html }` / `#{html}`
            if not re.search(r"[\$#]\{\s*" + re.escape(k) + r"\s*\}", ln):
                continue
            unescaped = bool(_NOESCAPE_RE.search(ln)) and not _ESCAPE_RE.search(ln)
            # `th:utext` 与 `[[${}]]` 可能同时出现，此时按"不转义"算 ——
            # 一处不安全渲染就足以成立。
            if not unescaped and _NOESCAPE_RE.search(ln):
                unescaped = True
            hits.append(TemplateHit(path=str(template), line=i, key=k,
                                    raw=ln.strip(), unescaped=unescaped))
            break
    # 不转义的排前面，便于模型和规则先看到关键证据
    hits.sort(key=lambda h: (not h.unescaped, h.line))
    return hits[:max_hits]


def render_template_block(repo_root: str | Path, hits: list[TemplateHit],
                          context: int = _MAX_CONTEXT) -> str:
    """把渲染点连同上下文渲染成切片段落。

    上下文是必要的：`<p th:utext="${html}"></p>` 单独一行看不出它在哪个
    页面、哪个 `th:if` 分支里。但也不能贴整份模板 —— 上限 context 行。
    """
    if not hits:
        return ""
    root = Path(repo_root)
    lines = ["", "// ---- 关联视图模板（视图名解析到的模板文件，渲染点原文）----"]
    cache: dict[str, list[str]] = {}
    for h in hits:
        p = Path(h.path)
        if str(p) not in cache:
            try:
                cache[str(p)] = p.read_text(encoding="utf-8",
                                            errors="ignore").splitlines()
            except OSError:
                cache[str(p)] = []
        all_lines = cache[str(p)]
        try:
            rel = p.relative_to(root).as_posix()
        except ValueError:
            rel = p.name
        lines.append(f"// {rel}:{h.line}  {h.describe().split('  ', 1)[-1]}")
        lo = max(1, h.line - context)
        hi = min(len(all_lines), h.line + context)
        for n in range(lo, hi + 1):
            mark = ">>" if n == h.line else "  "
            lines.append(f"// {mark} {n:>4}| {all_lines[n - 1].strip()}")
        lines.append("//")
    lines.append("")
    return "\n".join(lines)


def template_evidence(repo_root: str | Path, source: str) -> str:
    """一站式：从入口方法体推出模板渲染证据。没有就返回空串。"""
    views = view_names(source)
    keys = model_keys(source)
    if not views or not keys:
        return ""
    hits: list[TemplateHit] = []
    for v in views:
        p = resolve_template_path(repo_root, v)
        if p is None:
            continue
        hits.extend(find_render_points(p, keys))
    return render_template_block(repo_root, hits)
