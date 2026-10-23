"""正则卫生自检（M50）。

三件事，doctor 第五段调用：

1. **死正则** —— 顶层 `re.compile(...)` 赋给的名字，全模块一次都没被引用。
   这类常量是"看起来在用、实际没人用"的残留：改它不会让任何判定变，
   留着只会让人以为它参与了判据（铁律：判据不许靠注释撑，也不许靠
   看起来在用的死代码撑）。
2. **遮蔽冲突** —— 顶层同名赋值出现多次。后者盖前者，判据可能被静默换掉。
3. **内联遮蔽** —— 函数体内 `re.<fn>("字面量")` 的 pattern 与某个顶层
   预编译正则相同。功能上没坏，但顶层那份被"遮蔽"成了死代码。

口径全部走 AST，不做文本匹配 —— 注释里的同名不会误判，字符串里的
`re.compile(` 也不会被当成真定义。

所有检查只读，不改任何文件。
"""
from __future__ import annotations

import ast
import pathlib
from dataclasses import dataclass, field

# 会用 pattern 实参的 re.* 函数（compile 不算 —— 它是"定义"不是"使用"）
_RE_USE_FUNCS = frozenset({
    "match", "search", "findall", "finditer", "sub", "subn",
    "split", "fullmatch",
})


@dataclass
class RegexIssue:
    kind: str          # "dead" | "shadow" | "inline_shadow"
    module: str
    line: int
    name: str
    detail: str = ""

    def __str__(self) -> str:
        tag = {"dead": "死正则", "shadow": "遮蔽冲突", "inline_shadow": "内联遮蔽"}[self.kind]
        extra = f" — {self.detail}" if self.detail else ""
        return f"{tag} {self.module}:{self.line} {self.name}{extra}"


@dataclass
class RegexAudit:
    modules: int = 0
    top_level_regexes: int = 0
    issues: list[RegexIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues

    def by_kind(self, kind: str) -> list[RegexIssue]:
        return [i for i in self.issues if i.kind == kind]


def _normalize(pattern: str) -> str:
    """归一化 pattern：去所有空白（`re.compile` 里的换行拼接与字面量等价）。"""
    return "".join(pattern.split())


def _is_compile_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    name = getattr(fn, "id", None) or getattr(fn, "attr", None)
    return name == "compile"


def _literal_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _self_referential(node: ast.AST, name: str) -> bool:
    """该赋值的右值是否引用了被赋值的名字本身（刻意的包装模式）。"""
    if not isinstance(node, ast.Assign):
        return False
    for sub in ast.walk(node.value):
        if isinstance(sub, ast.Name) and sub.id == name:
            return True
    return False


def audit_module(source: str, module_name: str) -> tuple[list[RegexIssue], int]:
    """审计单个模块源码，返回 (问题列表, 顶层正则数)。"""
    tree = ast.parse(source)
    issues: list[RegexIssue] = []

    # ---- 顶层赋值：名字 → (出现次数, 行号, 是不是 compile) ----
    top_assign: dict[str, list[tuple[int, bool]]] = {}
    top_pattern: dict[str, str] = {}   # 归一化 pattern → 顶层名字
    assign_nodes: dict[str, list[ast.AST]] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            is_compile = _is_compile_call(node.value)
            top_assign.setdefault(target.id, []).append((node.lineno, is_compile))
            assign_nodes.setdefault(target.id, []).append(node)
            if is_compile and node.value.args:
                pat = _literal_str(node.value.args[0])
                if pat is not None:
                    top_pattern.setdefault(_normalize(pat), target.id)

    # ---- 1) 遮蔽冲突：顶层同名赋值多次 ----
    # 自引用赋值不算冲突：`X = _CompatPrompt(X)` 是**刻意的包装**（给 str
    # 换掉 format 语义），后一次的值依赖前一次 —— 这是有意的，不是覆盖。
    # 真正的遮蔽是"后一次的值与前一次无关"，那才会静默换掉判据。
    for name, occ in top_assign.items():
        if len(occ) <= 1:
            continue
        nodes = assign_nodes.get(name, [])
        # 第一次赋值是原始值（必然不引用自己），后续每次都必须**包装**前一次
        # 的值 —— 这条链是有意的（逐层加语义），不是覆盖。
        if all(_self_referential(node, name) for node in nodes[1:]):
            continue
        lines = ", ".join(str(l) for l, _ in occ)
        issues.append(RegexIssue(
            "shadow", module_name, occ[0][0], name,
            f"顶层赋值 {len(occ)} 次（行 {lines}）"))

    # ---- 被引用过的顶层名字 ----
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            used.add(node.id)

    # ---- 2) 死正则：顶层 compile 出来的名字，一次都没被引用 ----
    n_regex = 0
    for name, occ in top_assign.items():
        compile_occ = [(l, c) for l, c in occ if c]
        if not compile_occ:
            continue
        n_regex += len(compile_occ)
        if name not in used:
            issues.append(RegexIssue(
                "dead", module_name, compile_occ[0][0], name,
                "顶层预编译但全模块零引用"))

    # ---- 3) 内联遮蔽：函数体内 re.<fn>("字面量") 与顶层正则同 pattern ----
    # 函数体覆盖的行号 —— **包括类里的方法**（`_iter_units` 这种方法体里的
    # 内联字面量才是最常见的遮蔽形态，只看模块顶层函数会漏掉一大半）。
    # 用"行号落在函数体区间内"判定，而不是收集 stmt 行号：表达式节点
    # （Call）不是 stmt，按 stmt 收集会漏判 return 语句里的调用。
    in_func: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lo = node.lineno
            hi = max((getattr(s, "lineno", lo) for s in ast.walk(node)), default=lo)
            in_func.update(range(lo, hi + 1))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno not in in_func:
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)):
            continue
        if fn.value.id != "re" or fn.attr not in _RE_USE_FUNCS or not node.args:
            continue
        pat = _literal_str(node.args[0])
        if pat is None:
            continue
        owner = top_pattern.get(_normalize(pat))
        if owner:
            issues.append(RegexIssue(
                "inline_shadow", module_name, node.lineno, owner,
                f"函数内 re.{fn.attr}(字面量) 与顶层正则同 pattern"))

    return issues, n_regex


def audit_paths(paths: list[str | pathlib.Path]) -> RegexAudit:
    """审计一组文件（相对仓库根或绝对路径均可）。"""
    audit = RegexAudit()
    for raw in paths:
        p = pathlib.Path(raw)
        if not p.exists():
            continue
        try:
            source = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            issues, n = audit_module(source, str(p).replace("\\", "/"))
        except SyntaxError as e:
            audit.issues.append(RegexIssue(
                "shadow", str(p).replace("\\", "/"), 0, "<syntax>",
                f"解析失败: {e}"))
            continue
        audit.modules += 1
        audit.top_level_regexes += n
        audit.issues.extend(issues)
    return audit


# doctor 审计的模块清单：判据层 + 切片层 + 上下文层 + 沙箱层
DOCTOR_REGEX_MODULES = [
    "core/agents/rule_detectors.py",
    "core/context/taint_graph.py",
    "core/context/taint_chain.py",
    "core/context/symbol_indexer.py",
    "core/context/java_impl_resolver.py",
    "core/context/framework_wiring.py",
    "core/context/argument_resolvers.py",
    "core/context/dependency_versions.py",
    "core/context/config_resolver.py",
    "core/context/view_templates.py",
    "core/slicer/java_servlet.py",
    "core/slicer/web_treesitter.py",
    "core/slicer/web3_slither.py",
    "core/sandbox/poc_synthesizer.py",
]
