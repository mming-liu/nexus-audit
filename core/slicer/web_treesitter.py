"""Web 路由入口提取器（第1周实现，借鉴 vulnhuntr）。

当前实现：基于 SymbolIndexer 的零依赖路由提取，覆盖 Flask / FastAPI / DRF
的路由装饰器。升级点：tree_sitter 可用时用精确 AST 解析替换正则回退。

2026-10-21（Module 5）：补上与 Java 赛道对齐的**多跳展开** ——
入口调用的辅助函数/Service/DAO 方法体按 `[Hop N]` 段拼进切片，深度
`MAX_HOPS`，带 `_visited` 防环与段数预算（与 Java 侧
`MAX_HELPER_SEGMENTS` 同思路：深度与 token 同时管）。
没有这一层，Python 入口的 sink 藏在第 2/3 跳时，规则与模型都只能
看到第 1 跳的转发语句 —— 断链的表现是"静默退回"。

段头格式与 Java 对齐（`// 来自 文件:行 [Hop N]`），证据解析与
`entry_body()` 的截断逻辑可直接复用。辅助方法体**不加 `//` 前缀**：
它们是真实代码（可被引证核验），段头注释只负责分界。

用法：
    slicer = WebTreeSitterSlicer(repo_path)
    units = slicer.extract_entry_units(repo_path)   # -> List[CodeUnit]
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from core.context.symbol_indexer import IGNORE_DIRS, SymbolIndexer
from core.models import CodeUnit

try:  # 可选增强：tree-sitter 就绪时切换精确解析
    import tree_sitter  # noqa: F401
    HAVE_TREE_SITTER = True
except ImportError:
    HAVE_TREE_SITTER = False

MAX_HOPS = 3                 # 与 Java 侧同深度：1 跳转发 + 2 跳实现
MAX_HELPER_SEGMENTS = 6      # 段数预算：防止单入口把切片撑爆

_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_CALL_EXCLUDE = {"if", "for", "while", "with", "range", "len", "str", "int",
                 "float", "bool", "print", "set", "dict", "list", "sorted",
                 "isinstance", "super", "enumerate", "zip", "open",
                 "getattr", "hasattr", "type", "id", "repr", "format"}


# ---------------- Module 88：Django `urls.py` 路由表通道 ----------------
#
# 第三条路由发现通道（前两条：装饰器 → Connexion/OpenAPI yml）。
#
# Django 把路由**整体外置**到 `urls.py` 的 `urlpatterns` 列表里，视图函数
# 本体零装饰器。只看装饰器时，DjanGoat 这类纯 Django 应用的绝大多数视图
# 根本进不了切片（实测只有 13 个入口，其中 9 个还是 `@require_http_methods`
# 里"GET"三个字母碰巧命中 route_kw 的 `get` 才被收进来的 —— 证据位是错的）。
#
# 三代路由函数语义等价，全部收：
#   `url(r'^x/', views.f)`      —— Django 1.x（DjanGoat/pygoat 用的就是这个）
#   `re_path(r'^x/', views.f)`  —— Django 2.0+
#   `path('x/', views.f)`       —— Django 2.0+ 简写
_DJ_URL_CALL_RE = re.compile(r"(?<![\w.])(?:url|re_path|path)\s*\(")
# M121：DRF 类视图两条通道。
#   · `url(r'^x$', XxxAPIView.as_view())`
#   · `router.register(r'articles', ArticleViewSet)`
_DJ_AS_VIEW_RE = re.compile(r"^([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\.\s*as_view\s*\(")
_DJ_ROUTER_REG_RE = re.compile(r"\.\s*register\s*\(")
# APIView/GenericAPIView 的 HTTP 动作方法
_DJ_CBV_ACTIONS = ("get", "post", "put", "patch", "delete")
# ViewSet 的六个标准动作（DefaultRouter 会把它们映射到 GET/POST/PUT/PATCH/DELETE）
_DJ_VIEWSET_ACTIONS = ("list", "create", "retrieve", "update",
                       "partial_update", "destroy")
# 只认 `urlpatterns` 真的被赋值成列表的文件 —— 否则 `pathlib.Path(...)`、
# `re_path` 之类同名词在任何 Python 文件里都会触发本通道。
_DJ_URLPATTERNS_RE = re.compile(r"(?m)^\s*urlpatterns\s*(?:\+?=)\s*\[")
_DJ_IMPORT_RE = re.compile(
    # M121：`from .views import (\n  A, B,\n  C\n)` —— **括号跨行**的导入是 DRF
    # 项目里的标准写法（django-realworld 每个 urls.py 都这么写）。只认单行
    # 的话名字一个都进不了 alias map，类视图路由全部落不到模块（实测 63 条
    # 路由的 mod 全是 None）。这里允许行为 `(` 时跨行取到配平的 `)`。
    r"(?m)^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+(\([^)]*\)|[^\n#]+)"
    r"|^[ \t]*import[ \t]+([\w.]+)", re.S)


def _dj_split_args(s: str) -> list[str]:
    """按**顶层**逗号切分（引号与括号感知）。

    Django 的正则路由串里天然含 `(`、`)` 与 `,`：
    `url(r'^(?P<user_id>[0-9]+)/messages/', ...)`。朴素的 `split(",")`
    会把 `(?P<user_id>` 当成一个实参切出去。
    """
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = ""
    i = 0
    while i < len(s):
        c = s[i]
        if quote:
            buf.append(c)
            if c == "\\" and i + 1 < len(s):
                buf.append(s[i + 1])
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c in "([{":
            depth += 1
            buf.append(c)
        elif c in ")]}":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    if "".join(buf).strip():
        out.append("".join(buf))
    return [x.strip() for x in out]


def _dj_call_args(text: str, open_idx: int) -> str:
    """取 `text[open_idx]` 处 `(` 开始的配平实参串（引号感知）。"""
    depth = 0
    quote = ""
    i = open_idx
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return ""


def _dj_module_rel(mod: str, leaf: str, base: Path, repo: Path) -> str | None:
    """把 `from <mod> import <leaf>` 解析成仓库内相对路径。解析不出返回 None。

    三种形态：
      · 绝对点号模块 `app.views.users` + leaf `views` → `app/views/users/views.py`
      · 相对导入 `from . import views`（mod=".", leaf="views"）→ `pkg/views/...`
      · 相对导入 `from .users import views`（mod=".users"）→ `pkg/users/views.py`
    包则落到 `__init__.py`（后面还要沿再导出解析一层）。
    """
    if mod.startswith("."):
        dots = len(mod) - len(mod.lstrip("."))
        rest = mod[dots:]
        d = base
        for _ in range(dots - 1):
            d = d.parent
        comps = [c for c in rest.split(".") if c]
        # ① 先按"leaf 也是模块名"解（`from . import views` / `from .users import views`）
        dd = d
        for comp in comps + [leaf]:
            dd = dd / comp
        for cand in (dd.with_suffix(".py"), dd / "__init__.py"):
            if cand.is_file():
                return cand.relative_to(repo).as_posix()
        # ② M121：leaf 是**模块内的符号名**（`from .views import ArticleViewSet`）。
        #    此时模块就是 `mod` 本身，leaf 不该参与路径拼接 —— 直接落到
        #    `views.py`，符号由 indexer 的 symbol_table 去取。
        dd = d
        for comp in comps:
            dd = dd / comp
        for cand in (dd.with_suffix(".py"), dd / "__init__.py"):
            if cand.is_file():
                return cand.relative_to(repo).as_posix()
        return None
    parts = [p for p in mod.split(".") if p] + [leaf]
    # 包的根可能是仓库根，也可能被仓库根下的一层目录包着（DjanGoat/app/...）；
    # 从最长的解释开始试，逐层剥掉前导组件，命中即用。
    for skip in range(0, len(parts)):
        rel = "/".join(parts[skip:])
        for cand in (repo / (rel + ".py"), repo / rel / "__init__.py"):
            if cand.is_file():
                return cand.relative_to(repo).as_posix()
    return None


def _dj_alias_map(text: str, path: Path, repo: Path) -> dict[str, str]:
    """单个 `urls.py` 的局部名字 → 模块相对路径（含 `as` 别名）。"""
    aliases: dict[str, str] = {}
    base = path.parent
    for m in _DJ_IMPORT_RE.finditer(text):
        mod, names = m.group(1), m.group(2)
        if not mod or not names:
            continue                     # `import a.b.c` 只绑 a，路由里用不到
        for nm in _dj_split_args(names.strip().strip("()")):
            nm = nm.strip().strip("()").strip()
            if not nm or nm in ("(", ")"):
                continue
            bits = [b.strip() for b in nm.split(" as ")]
            orig = bits[0]
            alias = bits[1] if len(bits) > 1 else orig
            rel = _dj_module_rel(mod, orig, base, repo)
            if rel:
                aliases[alias] = rel
    return aliases


def _dj_reexport(rel_path: str, attr: str, repo: Path) -> str | None:
    """包的 `__init__.py` 里 `from X import ... as attr` 的再导出解析。

    DjanGoat 的 `app/views/__init__.py` 就是这个形态：
      `from app.views.users import views as users_views`
    于是 `app/urls.py` 里的 `views.users_views.signup` 要两跳才落到
    `app/views/users/views.py`。
    """
    p = repo / rel_path
    if not p.is_file():
        return None
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return _dj_alias_map(text, p, repo).get(attr)


def _dj_resolve(parts: list[str], aliases: dict[str, str],
                repo: Path) -> str | None:
    """把点号属性链解析成模块相对路径（最长前缀匹配 + 逐层再导出）。"""
    for k in range(len(parts), 0, -1):
        head = ".".join(parts[:k])
        if head not in aliases:
            continue
        path = aliases[head]
        for attr in parts[k:]:
            nxt = _dj_reexport(path, attr, repo)
            if not nxt:
                return None
            path = nxt
        return path
    return None



class WebTreeSitterSlicer:
    language = "python_web"

    def __init__(self, repo_path: str | Path):
        self.repo_path = repo_path

    def extract_entry_units(self, repo_path: str | Path | None = None) -> List[CodeUnit]:
        """提取带路由装饰器的入口函数为 CodeUnit。

        过滤策略（对齐计划书第一层契约）：
          - 仅保留带路由装饰器的符号
          - 剔除 GET-only 且无请求体读取的纯只读接口可在此扩展
        """
        indexer = SymbolIndexer(repo_path or self.repo_path)
        indexer.build()
        units = indexer.to_code_units()
        # 只保留真正带路由标记的（decorators 含 route/get/post 等）
        route_kw = ("route", "get", "post", "put", "patch", "delete", "api_view", "mapping")
        filtered = [u for u in units
                    if any(any(k in d.lower() for k in route_kw) for d in u.decorators_or_modifiers)]
        for u in filtered:
            self._expand_helpers(indexer, u)
        if not filtered:
            # Module 37：Connexion/OpenAPI 通道。装饰器位为空不代表没有
            # 路由 —— Connexion 把路由声明放在 openapi*.yml 的 operationId
            # 里，函数本体零装饰器。仅当仓库里真有含 operationId 的 yml
            # 才启用（不影响其它靶场的现有切片）。
            filtered = self._connexion_entries(indexer)
            for u in filtered:
                self._expand_helpers(indexer, u)
        # Module 88：Django `urls.py` 路由表通道。**追加式**：装饰器命中集
        # 原样保留（既有靶场的切片不缩水），路由表指向但装饰器没覆盖到的
        # 视图补进来。DjanGoat 实测 13 → 全量视图入口。
        repo = Path(repo_path or self.repo_path)
        extra = self._django_entries(indexer, filtered, repo)
        for u in extra:
            self._expand_helpers(indexer, u)
        filtered = filtered + extra
        return filtered

    @staticmethod
    def _connexion_routes(repo_path: Path) -> dict[tuple[str, str], str]:
        """解析 openapi*.yml：operationId → (module, func) 与 method+path。

        零依赖手写解析（venv 无 pyyaml）：OpenAPI 的 paths 层级是固定的
        `  /path:` → `    method:` → `      operationId:`，按缩进状态机跟
        踪即可，不需要完整 YAML。返回 {(module, func): "get /users/v1"}。
        """
        routes: dict[tuple[str, str], str] = {}
        for yml in sorted(repo_path.rglob("*.yml")):
            try:
                text = yml.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "operationId" not in text:
                continue
            cur_path = cur_method = ""
            for line in text.splitlines():
                m = re.match(r"^  (/\S*):\s*$", line)
                if m:
                    cur_path, cur_method = m.group(1), ""
                    continue
                m = re.match(r"^    (get|post|put|delete|patch):\s*$", line)
                if m:
                    cur_method = m.group(1)
                    continue
                m = re.match(r"^\s*operationId:\s*([\w.]+)\s*$", line)
                if m and cur_method:
                    # operationId: api_views.users.get_by_username
                    # 模块路径 = 去掉末段函数名 → api_views/users.py
                    parts = m.group(1).split(".")
                    if len(parts) >= 2:
                        func = parts[-1]
                        module = "/".join(parts[:-1]) + ".py"
                        routes[(module, func)] = f"{cur_method} {cur_path}"
        return routes

    def _connexion_entries(self, indexer: SymbolIndexer) -> List["CodeUnit"]:
        """把 yml 路由表对回符号表里的同名函数，产出带 connexion: 标记的
        CodeUnit。按 (module 相对路径, func) 精确匹配（铁律 10 的 pick
        语义：路由声明本身就是唯一入口点名，重名函数不收）。"""
        repo = self.repo_path or indexer.repo_path
        routes = self._connexion_routes(Path(repo))
        if not routes:
            return []
        if not indexer._built:
            indexer.build()
        out: List[CodeUnit] = []
        for name, syms in indexer.symbol_table.items():
            for sym in syms:
                rel = Path(sym["file"]).as_posix()
                hit = next((v for k, v in routes.items()
                            if k[1] == name and rel.endswith(k[0])), None)
                if hit is None:
                    continue
                unit = indexer.make_code_unit(
                    sym, [f"connexion:{hit}"], name=name)
                if unit:
                    out.append(unit)
        return out

    # ---------------- Module 88：Django 路由表通道 ----------------

    @staticmethod
    def _django_route_label(pattern: str) -> str:
        """路由证据标签：`r'^signup/'` → `^signup/`（去前缀字母与引号）。"""
        p = pattern.strip()
        if p[:1] in ("r", "u", "b", "f"):
            p = p[1:]
        return p.strip().strip("'\"") or "?"

    @classmethod
    def _django_routes(cls, repo_path: Path) -> list[tuple[str, str | None, str]]:
        """解析全仓 `urls.py`，返回 [(view 函数名, 模块相对路径 or None, 路由标签)]。

        只认 `urlpatterns = [` / `+=` 真的被赋值的文件；`include(...)` 与
        解析不出的点号链一律跳过 —— 宁可这条路由不进来，也不拿一个猜的
        模块名去匹同名函数。

        M121：**DRF 类视图**两条通道都打通了（此前一律跳过，django-realworld
        整个仓库只切出 1 个单元）：
          · `url(r'^x$', XxxAPIView.as_view())` → 取 `XxxAPIView` 的
            `get/post/put/patch/delete` 动作方法；
          · `router.register(r'articles', ArticleViewSet)` → 取 ViewSet 的
            `list/create/retrieve/update/partial_update/destroy`。
        两条都以 `("Class.method", mod, label)` 形式返回，由
        `_django_entries` 走**类方法**解析（`symbol_table` 里键是
        `Class.method`）。
        """
        routes: list[tuple[str, str | None, str]] = []
        for pf in sorted(repo_path.rglob("*.py")):
            if any(part in IGNORE_DIRS for part in pf.parts):
                continue
            try:
                text = pf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            is_urlconf = bool(_DJ_URLPATTERNS_RE.search(text))
            if not is_urlconf and not _DJ_ROUTER_REG_RE.search(text):
                continue
            aliases = _dj_alias_map(text, pf, repo_path)
            if is_urlconf:
                for m in _DJ_URL_CALL_RE.finditer(text):
                    args = _dj_split_args(_dj_call_args(text, m.end() - 1))
                    if len(args) < 2:
                        continue
                    view = args[1].strip()
                    if not view or "include" in view:
                        continue
                    label = cls._django_route_label(args[0])
                    avm = _DJ_AS_VIEW_RE.search(view)
                    if avm:
                        dotted = [p.strip() for p in avm.group(1).split(".")
                                  if p.strip()]
                        if not dotted:
                            continue
                        klass = dotted[-1]
                        mod = (aliases.get(klass) if len(dotted) == 1
                               else _dj_resolve(dotted[:-1], aliases, repo_path))
                        for act in _DJ_CBV_ACTIONS:
                            routes.append((f"{klass}.{act}", mod, label))
                        continue
                    vm = re.fullmatch(
                        r"([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)", view)
                    if not vm:
                        continue
                    dotted = [p.strip() for p in vm.group(1).split(".")
                              if p.strip()]
                    if not dotted:
                        continue
                    func = dotted[-1]
                    if len(dotted) == 1:
                        mod = aliases.get(func)
                    else:
                        mod = _dj_resolve(dotted[:-1], aliases, repo_path)
                    routes.append((func, mod, label))
            # DRF Router：`router.register(r'articles', ArticleViewSet)`
            for rm in _DJ_ROUTER_REG_RE.finditer(text):
                rargs = _dj_split_args(_dj_call_args(text, rm.end() - 1))
                if len(rargs) < 2:
                    continue
                prefix = cls._django_route_label(rargs[0].lstrip("r"))
                vs = rargs[1].strip()
                vm2 = re.fullmatch(r"([A-Za-z_]\w*)", vs)
                if not vm2:
                    continue
                klass = vm2.group(1)
                mod = aliases.get(klass)
                for act in _DJ_VIEWSET_ACTIONS:
                    routes.append((f"{klass}.{act}", mod, f"/{prefix}"))
        return routes

    @staticmethod
    def _django_class_method(indexer, klass: str, meth: str,
                             mod: str | None) -> dict | None:
        """在类体行号范围内找同名方法（M121）。

        三条约束缺一不可：① 类符号存在（可带模块限定）；② 方法符号与类
        **同文件**；③ 方法起始行落在 `[类起始行, 类结束行]` 之间。
        `__init__` 之类的噪声天然被"方法名 + 范围"两条挡住。
        """
        classes = indexer.symbol_table.get(klass, [])
        if not classes:
            return None
        if mod:
            classes = [c for c in classes
                       if Path(c["file"]).as_posix().endswith(mod)] or classes
        for c in classes:
            cf = Path(c["file"]).resolve()
            for cand in indexer.symbol_table.get(meth, []):
                if Path(cand["file"]).resolve() != cf:
                    continue
                if c["start"] <= cand["start"] <= c["end"]:
                    return cand
        return None

    @staticmethod
    def _drf_header(path: Path, klass: str, meth: str) -> str:
        """类视图切片头（M121）：`// Permission-Classes:` + `// View-Action:`。

        从**类体范围内**取 `permission_classes = (...)` 的字面量内容。
        取不到就只写动作名 —— 缺证据时宁可让判据看到"没有权限类声明"，
        也不要凭空补一个 `IsAuthenticated`（那会把真漏洞洗成安全）。
        """
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        m = re.search(rf"(?ms)^class\s+{re.escape(klass)}\b.*?(?=^class\s|\Z)",
                      text)
        body = m.group(0) if m else ""
        perms = ""
        pm = re.search(r"(?m)^[ \t]*permission_classes\s*=\s*\(([^)]*)\)", body)
        if pm:
            perms = ", ".join(
                x.strip() for x in pm.group(1).split(",") if x.strip())
        hdr = f"// View-Action: {meth}\n"
        if perms:
            hdr += f"// Permission-Classes: {perms}\n"
        return hdr

    def _django_entries(self, indexer: SymbolIndexer, existing: list,
                        repo_path: Path) -> List["CodeUnit"]:
        """把路由表指向的视图函数补成入口 CodeUnit（**追加**，不替换前两条通道）。

        匹配语义（铁律：判据挂机制不挂名字）：
          · 模块解析出来 → 按「函数名 + 文件路径后缀」精确命中；
          · 模块解析不出但全仓只有**唯一**同名定义 → 接受（无歧义）；
          · 同名多处且模块解析不出 → **跳过**，不猜。
        """
        routes = self._django_routes(repo_path)
        if not routes:
            return []
        if not indexer._built:
            indexer.build()
        have = {(Path(u.file_path).resolve(), u.start_line) for u in existing}
        out: List[CodeUnit] = []
        for func, mod, label in routes:
            # M121：`Class.method` 形态（DRF 类视图）。indexer 里类与方法都按
            # **裸名**索引（没有 `Class.method` 键），所以按"方法行号落在类体
            # 范围内 + 同文件"精确定位 —— 不靠名字猜。
            if "." in func:
                klass, meth = func.rsplit(".", 1)
                picked = self._django_class_method(indexer, klass, meth, mod)
                if picked is None:
                    continue
                key = (Path(picked["file"]).resolve(), picked["start"])
                if key in have:
                    continue
                unit = indexer.make_code_unit(
                    picked, [f"django:{label}"], name=func)
                if unit:
                    # M121：把类级 `permission_classes` 与动作名写进切片头。
                    # DRF 的鉴权声明在**类属性**上，方法级切片里看不到 ——
                    # 不注入的话 authz 只能看到 `self.queryset.get(slug=slug)`，
                    # 无从判断"这个动作是公开读还是需登录写"。
                    hdr = self._drf_header(Path(picked["file"]), klass, meth)
                    if hdr:
                        unit.source_code = hdr + (unit.source_code or "")
                    out.append(unit)
                    have.add(key)
                continue
            cands = indexer.symbol_table.get(func, [])
            if not cands:
                continue
            picked = None
            if mod:
                for c in cands:
                    if Path(c["file"]).as_posix().endswith(mod):
                        picked = c
                        break
            if picked is None:
                if len(cands) == 1:
                    picked = cands[0]
                else:
                    continue
            key = (Path(picked["file"]).resolve(), picked["start"])
            if key in have:
                continue
            unit = indexer.make_code_unit(picked, [f"django:{label}"], name=func)
            if unit:
                out.append(unit)
                have.add(key)
        return out

    # ---------------- 多跳展开 ----------------

    @staticmethod
    def _called_names(source: str) -> list[str]:
        """源码里的调用名（保序去重）。与 SymbolIndexer._extract_called_symbols
        同口径但保留出现顺序 —— 展开顺序必须可复现，否则切片文本抖动。"""
        out: list[str] = []
        for m in _CALL_RE.finditer(source):
            n = m.group(1)
            if n not in _CALL_EXCLUDE and not n.isupper() and n not in out:
                out.append(n)
        return out

    def _expand_helpers(self, indexer: SymbolIndexer, u: CodeUnit) -> None:
        """把入口可达的辅助方法体按跳拼进切片（BFS，带防环与预算）。

        只展开"索引里真有定义"的符号 —— 内置名/未导入名直接跳过。
        `_visited` 防环：A→B→A 的循环依赖在真实项目里存在（service 与
        dao 互引），没有它 BFS 会把同一方法体贴进来两次。
        """
        visited = {u.unit_name}
        segments: list[tuple[str, int, int, str]] = []   # (file, line, hop, src)
        frontier = self._called_names(u.own_body or u.source_code)
        for hop in range(1, MAX_HOPS + 1):
            if not frontier or len(segments) >= MAX_HELPER_SEGMENTS:
                break
            nxt: list[str] = []
            for name in frontier:
                if len(segments) >= MAX_HELPER_SEGMENTS:
                    break
                if name in visited:
                    continue
                visited.add(name)
                code = indexer.get_symbol_code(name, prefer_file=u.file_path)
                if not code or not (code.get("source") or "").strip():
                    continue
                segments.append((code["file_path"], code["start_line"],
                                 hop, code["source"]))
                if len(segments) < MAX_HELPER_SEGMENTS:
                    nxt.extend(self._called_names(code["source"]))
            frontier = [n for n in dict.fromkeys(nxt) if n not in visited]
        if not segments:
            return
        block = ["", "// ---- 跨文件辅助方法实现（入口方法调用的外部方法，按跳展开）----"]
        for fp, line, hop, src in segments:
            block.append(f"// 来自 {Path(fp).name}:{line} [Hop {hop}]")
            block.extend(src.splitlines())
        u.source_code = (u.source_code or "") + "\n".join(block) + "\n"
        u.called_symbols = sorted({n for n in self._called_names(u.source_code)
                                   if n not in _CALL_EXCLUDE})
