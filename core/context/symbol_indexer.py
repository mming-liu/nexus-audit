"""全局符号表索引器（第1周实现）。

设计借鉴 vulnhuntr 的 SymbolExtractor（jedi 版），但改用零依赖正则实现，
保证在无第三方库环境可直接运行；后续可选升级为 Tree-sitter 精确解析。

职责：
  - 扫描仓库构建符号表：函数/类定义、路由装饰器、import 关系
  - get_symbol_code(symbol_name): 返回符号完整实现源码
  - find_middleware(route_path): 判断路由是否受全局鉴权中间件保护
  - 遍历时应排除 tests / docs / examples 等噪声目录（对齐 vulnhuntr 的 ignore 策略）
"""
import re
from pathlib import Path

from core.models import CodeUnit

# 对齐 vulnhuntr 的噪声目录策略
IGNORE_DIRS = {".git", "node_modules", "tests", "test", "docs", "examples",
               "example", "venv", ".venv", "__pycache__", "dist", "build"}

# Python 顶层定义：def/class（带缩进捕获以区分类方法）。
# 缩进只允许行内空白 —— `\s*` 会跨行吞空行，m.start() 落到空行处
# 导致 start_line 少 2、indent 变成 2，下一个顶层 def 被当成子函数，
# 符号段一路吞到文件尾（vulpy good/libuser 实测：do_login 的切片因此
# 混进 user_create 的拼接 sink，参数化版本被判成注入）。
DEF_RE = re.compile(r"^([ \t]*)(async\s+def|def|class)\s+([A-Za-z_]\w*)", re.M)
# import 捕获（含别名）
IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import\s+(.+)|import\s+([\w.]+)(?:\s+as\s+(\w+))?)", re.M)

# 常见 Web 框架的路由装饰器
ROUTE_DECORATOR_RE = re.compile(r"^(\s*)@(\w[\w.]*)\.?(route|get|post|put|patch|delete|head|options)?\s*\((.*)$", re.M)


class SymbolIndexer:
    def __init__(self, repo_path: str | Path, language: str = "python_web"):
        self.repo_path = Path(repo_path)
        self.language = language
        self.symbol_table: dict[str, dict] = {}   # name -> {file, start, end, kind, source, decorators}
        self.imports: dict[str, dict] = {}        # local_name -> {"from": module, "orig": symbol}
        self._built = False

    # ---------- 构建索引 ----------

    def build(self) -> None:
        for py in self._iter_python_files():
            try:
                text = py.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self._index_imports(py, text)
            self._index_definitions(py, text)
        self._built = True

    def _iter_python_files(self):
        for path in self.repo_path.rglob("*.py"):
            if not any(part in IGNORE_DIRS for part in path.parts):
                yield path

    def _index_imports(self, file: Path, text: str) -> None:
        for m in IMPORT_RE.finditer(text):
            if m.group(1):  # from module import a, b as c
                mod = m.group(1)
                for name in m.group(2).split(","):
                    name = name.strip()
                    if not name or name == "(":
                        continue
                    parts = [p.strip() for p in name.split(" as ")]
                    orig = parts[0]
                    local = parts[1] if len(parts) > 1 else orig
                    self.imports[local] = {"from": mod, "orig": orig, "file": str(file)}
            elif m.group(3):
                mod = m.group(3)
                local = m.group(4) or mod
                self.imports[local] = {"from": mod, "orig": mod, "file": str(file)}

    def _index_definitions(self, file: Path, text: str) -> None:
        lines = text.splitlines()
        matches = list(DEF_RE.finditer(text))
        for i, m in enumerate(matches):
            indent, kind, name = len(m.group(1)), m.group(2), m.group(3)
            # 符号结束：下一个同级或更浅缩进的定义/文件末尾
            start_line = text[: m.start()].count("\n") + 1
            end_line = len(lines)
            for m2 in matches[i + 1:]:
                indent2 = len(m2.group(1))
                if indent2 <= indent:
                    end_line = text[: m2.start()].count("\n")
                    break
            # 装饰器
            #
            # M107：**堆叠装饰器**。flaskr 的标准写法是路由 + 鉴权两层：
            #     @bp.route("/create", methods=("GET", "POST"))
            #     @login_required
            #     def create():
            # 旧实现只认"紧邻 def 上一行"（`start_line-1 <= d_start <= start_line`），
            # 而 `@login_required` 没有括号、ROUTE_DECORATOR_RE 匹配不上，
            # 于是 `@bp.route` 因为隔了一行被丢弃 —— 整个 create/update/delete
            # 三条路由在切片里**彻底消失**（flaskr 实测 5 个单元而非 8 个）。
            #
            # 现在先算出 `def` 上方**连续装饰器块**的起始行，块内全部装饰器
            # 都收。向上扫时遇空行即停；装饰器跨行（括号未闭合）时允许最多
            # 3 行续行，避免一路吃进上一个函数体。
            _blk_start = start_line
            _i = start_line - 1
            _seen_at = False
            _extra = 0
            while _i >= 1:
                _ln = lines[_i - 1].strip()
                if not _ln:
                    break
                if _ln.startswith("@"):
                    _blk_start = _i
                    _seen_at = True
                    _i -= 1
                    continue
                if _seen_at and _extra < 3:
                    _extra += 1
                    _blk_start = _i
                    _i -= 1
                    continue
                break
            decorators = []
            for dm in ROUTE_DECORATOR_RE.finditer(text[: m.start()]):
                deco_anchor = dm.start() + len(dm.group(1))
                d_start = text[:deco_anchor].count("\n") + 1
                if _blk_start <= d_start <= start_line:
                    decorators.append(dm.group(0).strip())
            # 相对/绝对文件标识
            # Module 24：键改为 name -> **列表**。此前 setdefault(name) 首见
            # 即占，多应用仓库（pygoat 20 个 Flask lab 都有 index/lab1/
            # health_check）整库切片时后面的文件被静默丢弃——50 个单元
            # 掩盖了 20 个应用。列表语义下 get_symbol_code 仍取首个
            # （与旧行为一致），调用方可传 prefer_file 优先同文件命中。
            key = name
            self.symbol_table.setdefault(key, []).append({
                "file": str(file), "start": start_line, "end": end_line,
                "kind": "class" if kind == "class" else "function",
                "decorators": decorators, "indent": indent,
            })

    # ---------- 查询接口（对应第2层工具） ----------

    def get_symbol_code(self, symbol_name: str, *, prefer_file: str | None = None) -> dict | None:
        """返回 {name, file_path, source, decorators}，未命中返回 None。

        支持：
          1. 精确符号名（同名符号多文件共存时，prefer_file 优先同文件）
          2. 裁剪到 class 下方法（如 Service.get_item -> Service + get_item）
          3. import 别名还原（from service import Service as FlowService）
        """
        if not self._built:
            self.build()

        def _pick(cands: list[dict]) -> dict | None:
            if not cands:
                return None
            if prefer_file:
                for c in cands:
                    if Path(c["file"]).name == Path(prefer_file).name:
                        return c
            return cands[0]

        sym = _pick(self.symbol_table.get(symbol_name, []))
        if sym is None and "." in symbol_name:
            cls_name, method_name = symbol_name.rsplit(".", 1)
            # 别名还原
            alias = self.imports.get(cls_name)
            if alias:
                symbol_name = f"{alias['orig']}.{method_name}"
            # 类下方法
            for name in (symbol_name, f"{method_name}"):
                cand = _pick(self.symbol_table.get(method_name, []))
                if cand is not None:
                    sym = cand
                    break
        if sym is None:
            # 别名还原（不带点）
            alias = self.imports.get(symbol_name)
            if alias:
                sym = _pick(self.symbol_table.get(alias["orig"], []))
        if sym is None:
            return None
        return self._read_symbol(sym)

    def _read_symbol(self, sym: dict) -> dict | None:
        try:
            lines = Path(sym["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        source = "\n".join(lines[sym["start"] - 1: sym["end"]])
        # 裁剪尾部误入的空行/下一个符号的装饰器（第1周收尾项）
        src_lines = source.splitlines()
        while src_lines and (not src_lines[-1].strip() or src_lines[-1].lstrip().startswith("@")):
            src_lines.pop()
        source = "\n".join(src_lines)
        return {"name": sym.get("name", ""), "file_path": sym["file"],
                "start_line": sym["start"], "end_line": sym["end"],
                "decorators": sym["decorators"], "source": source}

    def find_middleware(self, route_path: str) -> list[dict]:
        """查询路由是否受全局鉴权中间件保护（Flask/FastAPI 常见模式）。"""
        if not self._built:
            self.build()
        hits = []
        for path in self._iter_python_files():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for pat in (r"MIDDLEWARE\s*=\s*\[(.*?)\]", r"app\.middleware\(",
                        r"app\.before_request", r"dependencies\s*=\s*\[(.*?)\]"):
                for m in re.finditer(pat, text, re.S):
                    hits.append({"file": str(path), "pattern": pat, "match": m.group(0)[:500]})
        return hits

    # ---------- 与 CodeUnit 对接 ----------

    def make_code_unit(self, sym: dict, decorators: list[str], name: str = "") -> CodeUnit | None:
        """把符号表条目转成 CodeUnit（Module 37：Connexion/OpenAPI 通道）。

        Connexion 的路由不在 Python 装饰器里，而在 openapi*.yml 的
        `operationId: api_views.users.get_by_username` —— 函数本体没有任何
        装饰器，`to_code_units` 永远看不见。调用方解析 yml 得到
        (module, func, method, path) 后用本方法造单元，
        decorators_or_modifiers 填 `connexion:<method> <path>` 保留路由
        证据（与 Flask `@app.route` 同一契约位）。
        """
        if not self._built:
            self.build()
        data = self._read_symbol(sym)
        if not data:
            return None
        return CodeUnit(
            file_path=sym["file"], language=self.language,
            unit_name=name or sym.get("name", ""), start_line=sym["start"],
            end_line=sym["end"], decorators_or_modifiers=decorators,
            called_symbols=self._extract_called_symbols(data["source"]),
            source_code=data["source"],
        )

    def to_code_units(self) -> list[CodeUnit]:
        """把带路由装饰器的符号转成第一层 CodeUnit（含 called_symbols）。"""
        units = []
        for name, syms in self.symbol_table.items():
            for sym in syms:
                if not sym["decorators"]:
                    continue
                data = self._read_symbol(sym)
                if not data:
                    continue
                called = self._extract_called_symbols(data["source"])
                units.append(CodeUnit(
                    file_path=sym["file"], language=self.language, unit_name=name,
                    start_line=sym["start"], end_line=sym["end"],
                    decorators_or_modifiers=sym["decorators"],
                    called_symbols=called, source_code=data["source"],
                ))
        return units

    @staticmethod
    def _extract_called_symbols(source: str) -> list[str]:
        exclude = {"if", "for", "while", "with", "range", "len", "str", "int",
                   "float", "bool", "print", "set", "dict", "list", "sorted",
                   "isinstance", "super", "enumerate", "zip", "open"}
        called: set[str] = set()
        for m in re.finditer(r"(\w+)\s*\(", source):
            name = m.group(1)
            if name not in exclude and not name.isupper():
                called.add(name)
        return sorted(called)
