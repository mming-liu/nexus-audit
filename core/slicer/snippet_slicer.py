"""M273：单文件 / 代码片段宽容切片。

完整工程切片器依赖 pom.xml、路由表和全局配置；客户只发一个 Controller.java
或直接粘贴一段代码时，这些都不存在。本模块只做“尽量切出方法”，并把
evidence_scope 标成 single_file/snippet，提醒下游不要假装掌握全局装配。
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from core.models import CodeUnit, Language

_JAVA_SIG = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|"
    r"native|default|strictfp)\s+)+[\w<>\[\],.?\s]+\s+(\w+)\s*\(")
_JAVA_ANY_SIG = re.compile(
    r"^\s*(?:[\w<>\[\],.?]+\s+)+(\w+)\s*\([^;]*$")
_SOL_SIG = re.compile(
    r"^\s*(?:function\s+(\w+)|(constructor|modifier|fallback|receive))\s*\(")


def detect_language(filename: str, lang: str | None = None) -> str:
    if lang:
        lang = lang.lower()
        if lang in ("java", "python", "py", "solidity", "sol"):
            return {"py": "python", "sol": "solidity"}.get(lang, lang)
    ext = Path(filename).suffix.lower()
    return {".java": "java", ".py": "python", ".sol": "solidity"}.get(
        ext, "python")


def _language(lang: str) -> Language:
    return {"java": Language.JAVA_WEB, "python": Language.PYTHON_WEB,
            "solidity": Language.SOLIDITY_WEB3}.get(lang,
                                                    Language.PYTHON_WEB)


def _strip_non_code(line: str, in_block: bool) -> tuple[str, bool]:
    """去掉字符串/注释后再数括号，避免 { 出现在字符串里。"""
    out = []
    i = 0
    while i < len(line):
        if in_block:
            j = line.find("*/", i)
            if j < 0:
                return "".join(out), True
            i = j + 2
            in_block = False
            continue
        c = line[i]
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        if c == "/" and i + 1 < len(line) and line[i + 1] == "*":
            in_block = True
            i += 2
            continue
        if c in "\"'":
            quote = c
            i += 1
            while i < len(line):
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out), in_block


def _match_brace(lines: list[str], start: int, max_lines: int = 260) -> int:
    depth = 0
    seen = False
    in_block = False
    for k in range(start, min(len(lines), start + max_lines)):
        code, in_block = _strip_non_code(lines[k], in_block)
        depth += code.count("{") - code.count("}")
        if "{" in code:
            seen = True
        if seen and depth <= 0:
            return k
    return min(len(lines) - 1, start + max_lines - 1)


def _annotations_above(lines: list[str], start: int) -> int:
    j = start
    while j > 0:
        s = lines[j - 1].strip()
        if (s.startswith("@") or s.startswith("//") or s.startswith("/*")
                or s.startswith("*") or s.startswith("#")):
            j -= 1
            continue
        break
    return max(0, j)


def _java_units(text: str, filename: str) -> list[CodeUnit]:
    lines = text.splitlines()
    class_name = ""
    for ln in lines:
        m = re.search(r"\b(?:class|interface|enum)\s+(\w+)", ln)
        if m:
            class_name = m.group(1)
            break
    units: list[CodeUnit] = []
    for i, ln in enumerate(lines):
        m = _JAVA_SIG.match(ln) or _JAVA_ANY_SIG.match(ln)
        if not m:
            continue
        name = m.group(1)
        if name in ("if", "for", "while", "switch", "catch", "return", "new"):
            continue
        start = _annotations_above(lines, i)
        end = _match_brace(lines, i)
        unit_name = f"{class_name}.{name}" if class_name else name
        units.append(CodeUnit(
            file_path=filename, language=Language.JAVA_WEB,
            unit_name=unit_name, start_line=start + 1, end_line=end + 1,
            source_code="\n".join(lines[start:end + 1]),
            own_body="\n".join(lines[i:end + 1])))
    return units


def _python_units(text: str, filename: str) -> list[CodeUnit]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    units: list[CodeUnit] = []

    def visit(node, prefix: str = ""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = child.lineno - 1
                if child.decorator_list:
                    start = min(d.lineno for d in child.decorator_list) - 1
                end = getattr(child, "end_lineno", child.lineno)
                units.append(CodeUnit(
                    file_path=filename, language=Language.PYTHON_WEB,
                    unit_name=f"{prefix}{child.name}",
                    start_line=start + 1, end_line=end,
                    source_code="\n".join(lines[start:end]),
                    own_body="\n".join(lines[child.lineno - 1:end])))
            elif isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + ".")

    visit(tree)
    return units


def _solidity_units(text: str, filename: str) -> list[CodeUnit]:
    lines = text.splitlines()
    contract = ""
    for ln in lines:
        m = re.search(r"\b(?:contract|library|interface)\s+(\w+)", ln)
        if m:
            contract = m.group(1)
            break
    units: list[CodeUnit] = []
    for i, ln in enumerate(lines):
        m = _SOL_SIG.match(ln)
        if not m:
            continue
        name = m.group(1) or m.group(2) or "fallback"
        start = _annotations_above(lines, i)
        end = _match_brace(lines, i)
        unit_name = f"{contract}.{name}" if contract else name
        units.append(CodeUnit(
            file_path=filename, language=Language.SOLIDITY_WEB3,
            unit_name=unit_name, start_line=start + 1, end_line=end + 1,
            source_code="\n".join(lines[start:end + 1]),
            own_body="\n".join(lines[i:end + 1])))
    return units


def slice_text(text: str, filename: str = "<snippet>",
               lang: str | None = None) -> list[CodeUnit]:
    lang = detect_language(filename, lang)
    if lang == "java":
        units = _java_units(text, filename)
    elif lang == "solidity":
        units = _solidity_units(text, filename)
    else:
        units = _python_units(text, filename)
    if not units:
        units = [CodeUnit(
            file_path=filename, language=_language(lang),
            unit_name=f"Snippet.{Path(filename).stem or 'whole'}",
            start_line=1, end_line=max(1, text.count("\n") + 1),
            source_code=text, own_body=text)]
    for u in units:
        u.evidence_scope = "single_file" if filename != "<stdin>" else "snippet"
        u.snippet = True
    return units


def slice_file(path: str | Path, lang: str | None = None) -> list[CodeUnit]:
    p = Path(path)
    return slice_text(p.read_text(encoding="utf-8", errors="replace"),
                      str(p), lang)
