"""Java Web 入口切片器（第5周补充：为 OWASP Benchmark 跑分打通 Java 赛道）。

覆盖范围：
  - Servlet 3.0 注解式路由：@WebServlet(value = "/x") + doGet/doPost/doPut/doDelete
  - Spring MVC 注解式路由：@RequestMapping/@GetMapping/@PostMapping 方法
  - JAX-RS：@Path + @GET/@POST 方法

输出 CodeUnit：
  - unit_name 取 「类名.methodName」，便于与 expectedresults 中的类名对齐
  - source_code 包含入口方法整体 + 同文件内的私有辅助方法（doSomething 等），
    因为静态可达性判断必须看到辅助方法里对参数的清洗，否则一律误判为漏洞

设计取舍：零依赖正则 + 花括号配平切片。Java 方法体边界靠大括号计数确定，
比纯行正则可靠；不引入 javalang/tree-sitter-java 以保持可离线运行。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

from core.models import CodeUnit, Language

IGNORE_DIRS = {".git", "target", "build", "node_modules", "test", "tests"}

# 类声明：class Foo extends HttpServlet
CLASS_RE = re.compile(r"\b(?:public\s+)?(?:final\s+|abstract\s+)?class\s+([A-Za-z_]\w*)")
# @WebServlet(value = "/path") 或 @WebServlet("/path")
WEBSERVLET_RE = re.compile(r"@WebServlet\s*\(\s*(?:value\s*=\s*)?\"([^\"]*)\"")
# Spring / JAX-RS 方法级路由注解
SPRING_ROUTE_RE = re.compile(r"@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(([^)]*)\)")
JAXRS_ROUTE_RE = re.compile(r"@(GET|POST|PUT|DELETE|PATCH)\b")
JAXRS_PATH_RE = re.compile(r"@Path\s*\(\s*\"([^\"]*)\"\s*\)")

# 方法声明（含返回类型、方法名、参数列表），排除 if/for/while/catch 等关键字误匹配。
# 注意：不要在这里用 ^ 锚定匹配注解行 —— 方法体的缩进会漂移，^[ \t]* 对嵌套代码块失效。
# 注解与声明分开扫描，见 _slice_file。
METHOD_RE = re.compile(
    r"(?:^|(?<=[\n;{}]))[ \t]*"                              # 行首或紧跟 ; { } 之后
    r"(?:public|protected|private)\s+"                       # Java 方法必有访问修饰符
    r"(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?"
    r"([\w<>\[\],\.\s\?]+?)\s+"                              # 返回类型
    r"([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w\s,\.]+)?\s*\{",
    re.M,
)
# 注解行：单独扫描，用于给方法挂 @Override / @GetMapping 等
ANNOTATION_RE = re.compile(r"^[ \t]*@([A-Za-z_]\w*)(?:\(([^)]*)\))?", re.M)

SERVLET_METHODS = {"doGet", "doPost", "doPut", "doDelete", "doPatch", "service"}
HTTP_VERB_OF = {"doGet": "GET", "doPost": "POST", "doPut": "PUT",
                "doDelete": "DELETE", "doPatch": "PATCH"}


def _brace_match(text: str, open_idx: int) -> int:
    """从 open_idx 处的 '{' 起做花括号配平，返回匹配的 '}' 下标（找不到返回 -1）。"""
    depth = 0
    i = open_idx
    n = len(text)
    in_str = None      # 当前字符串定界符
    in_char = False
    in_line_comment = False
    in_block_comment = False
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_str:
            if ch == "\\":
                i += 1
            elif ch == in_str:
                in_str = None
        elif in_char:
            if ch == "\\":
                i += 1
            elif ch == "'":
                in_char = False
        else:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and nxt == "*":
                in_block_comment = True
                i += 1
            elif ch == '"':
                in_str = '"'
            elif ch == "'":
                in_char = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


class JavaSlicer:
    """Java Web 入口切片器（Servlet / Spring MVC / JAX-RS）。"""

    language = Language.JAVA_WEB

    def __init__(self, repo_path: str | Path, config_root: str | Path | None = None):
        self.repo_path = Path(repo_path)
        # 配置解析根目录：默认取 repo_path 上溯 4 层（testcode -> benchmark -> owasp
        # -> java -> main -> 项目根，足够覆盖 src/main/resources 这类标准布局）
        root = Path(config_root) if config_root else self._guess_project_root(self.repo_path)
        self.config_root = root
        self._cfg = None

    @staticmethod
    def _guess_project_root(p: Path) -> Path:
        """向上寻找项目根：优先含 src/main/resources 的目录（Maven 标准布局）。"""
        cur = p.resolve()
        for _ in range(8):
            if (cur / "src" / "main" / "resources").is_dir():
                return cur
            if (cur / "pom.xml").exists():
                return cur
            if cur.parent == cur:
                break
            cur = cur.parent
        return p.resolve()

    def _config_block(self, source: str) -> str:
        from core.context.config_resolver import ConfigResolver
        if self._cfg is None:
            self._cfg = ConfigResolver(self.config_root)
        return self._cfg.resolve_for(source)

    # ---------- 跨文件辅助方法解析 ----------

    # 只追踪"可能决定安全语义"的调用，避免把整个仓库拖进切片
    TRACE_EXCLUDE = {
        "getWriter", "println", "print", "getParameter", "getParameterMap",
        "getHeaders", "getHeader", "getHeaderNames", "getCookies", "getName",
        "getValue", "setAttribute", "getAttribute", "addCookie", "setContentType",
        "getSession", "getRequestURI", "getRequestURL", "getHost", "length",
        "equals", "toString", "substring", "lastIndexOf", "indexOf", "add",
        "get", "remove", "isEmpty", "copyOf", "getBytes", "doFinal", "init",
        "read", "write", "close", "flush", "hasMoreElements", "nextElement",
        "getClass", "setSecure", "setHttpOnly", "setPath", "setDomain",
        "setMaxAge", "append", "format", "valueOf", "getBytes", "generateSeed",
    }

    def _resolve_cross_file_helpers(self, source: str, depth: int = 1,
                                    max_methods: int = 6) -> str:
        """顺着源码里调用的方法名，在其他 Java 文件中找出方法体并附上。

        动机：`Utils.getCipher()` 这类工厂方法把算法/配置藏在 helper 类里，
        只看入口文件会缺失关键证据（OWASP Benchmark 的 crypto 误报主因）。
        用惰性构建的方法索引查找，避免对每个用例重复扫描全仓库。
        """
        if depth <= 0:
            return ""
        calls = {m.group(1) for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", source)}
        calls -= self.TRACE_EXCLUDE
        calls -= SERVLET_METHODS
        if not calls:
            return ""

        index = self._method_index()
        found: list[str] = []
        used = 0
        # 按「安全相关性」排序：名字或方法体里出现算法/加密/随机/编解码/密钥等
        # 关键字的优先。否则 max_methods 名额会被 doSomething/encodeForHTML
        # 这类无关键噪声方法占满，真正的 getCipher 反而进不来。
        ranked = []
        for name in sorted(calls):
            hit = index.get(name)
            if hit is None:
                continue
            path, start_line, body = hit
            score = self._security_relevance(name, body)
            ranked.append((score, name, path, start_line, body))
        ranked.sort(key=lambda x: -x[0])

        for _score, _name, path, start_line, body in ranked:
            found.append(f"// 来自 {Path(path).name}:{start_line}\n{body}")
            used += 1
            if used >= max_methods:
                break

        if not found:
            return ""
        header = ("\n\n// ---- 跨文件辅助方法实现（入口方法调用的外部方法，含真实算法/参数）----\n")
        return header + "\n\n".join(found)

    SECURITY_KEYWORDS = (
        "cipher", "algorithm", "getinstance", "messagedigest", "securedrandom",
        "securerandom", "random", "digest", "encrypt", "decrypt", "key",
        "hash", "md5", "sha", "des", "aes", "ecb", "cbc", "salt", "token",
        "session", "auth", "password", "credential", "ldap", "xpath",
        "execute", "exec", "statement", "query", "path", "file",
    )

    @classmethod
    def _security_relevance(cls, name: str, body: str) -> int:
        """粗排安全相关性：名字与方法体命中关键字越多，越可能藏着关键证据。"""
        text = (name + "\n" + body).lower()
        return sum(1 for kw in cls.SECURITY_KEYWORDS if kw in text)

    def _method_index(self) -> dict[str, tuple[str, int, str]]:
        """惰性构建「方法名 -> (文件, 起始行, 方法体)」全局索引。

        索引根用配置根（项目根），而非切片目录：辅助类通常在 helpers/ 等
        与 testcode 平级的兄弟目录下，只扫切片目录会漏掉。
        """
        if getattr(self, "_midx", None) is not None:
            return self._midx
        root = self.config_root if self.config_root != self.repo_path else self.repo_path
        idx: dict[str, tuple[str, int, str]] = {}
        for java in root.rglob("*.java"):
            if any(part in IGNORE_DIRS for part in java.parts):
                continue
            try:
                text = java.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in METHOD_RE.finditer(text):
                name = m.group(2)
                if name in idx:
                    continue
                open_idx = text.find("{", m.end() - 1)
                if open_idx == -1:
                    continue
                close_idx = _brace_match(text, open_idx)
                if close_idx == -1:
                    continue
                decl_start = text.rfind("\n", 0, m.start(2)) + 1
                idx[name] = (str(java), _line_of(text, decl_start),
                             text[decl_start:close_idx + 1])
        self._midx = idx
        return idx

    def _iter_java_files(self) -> Iterable[Path]:
        for p in self.repo_path.rglob("*.java"):
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            yield p

    def extract_entry_units(self, repo_path: str | Path | None = None) -> List[CodeUnit]:
        root = Path(repo_path or self.repo_path)
        units: List[CodeUnit] = []
        for java in self._iter_java_files() if root == self.repo_path else self._iter_under(root):
            try:
                text = java.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            units.extend(self._slice_file(java, text))
        return units

    @staticmethod
    def _iter_under(root: Path):
        for p in root.rglob("*.java"):
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            yield p

    # ---------- 单文件切片 ----------

    def _slice_file(self, path: Path, text: str) -> List[CodeUnit]:
        cls_m = CLASS_RE.search(text)
        if not cls_m:
            return []
        cls_name = cls_m.group(1)

        # 收集本文件所有方法：name -> (start, end, source)
        methods: dict[str, tuple[int, int, str]] = {}
        for m in METHOD_RE.finditer(text):
            ret_type, name, params = m.group(1).strip(), m.group(2), m.group(3)
            if name in {"if", "for", "while", "switch", "catch", "return", "new"}:
                continue
            if ret_type in {"else", "try", "do"}:
                continue
            # 声明起点回退到方法名所在行首（去掉匹配到的前导空白/大括号）
            line_start = text.rfind("\n", 0, m.start(2)) + 1
            open_idx = text.find("{", m.end() - 1)
            if open_idx == -1:
                continue
            close_idx = _brace_match(text, open_idx)
            if close_idx == -1:
                continue
            # 把紧邻的注解行（@Override / @GetMapping(...)）并入方法源码：
            # 从方法名行首向上逐行回溯，只要上一行是注解行就继续上移
            decl_idx = line_start
            while decl_idx > 0:
                prev_line_end = decl_idx - 1
                prev_line_start = text.rfind("\n", 0, prev_line_end) + 1
                prev_line = text[prev_line_start:prev_line_end].strip()
                if prev_line.startswith("@"):
                    decl_idx = prev_line_start
                else:
                    break
            start_line = _line_of(text, decl_idx)
            end_line = _line_of(text, close_idx)
            methods.setdefault(name, (start_line, end_line, text[decl_idx:close_idx + 1]))

        if not methods:
            return []

        wl = WEBSERVLET_RE.search(text)
        spring_routes = {mm.group(1): mm.group(2) for mm in SPRING_ROUTE_RE.finditer(text)}
        jaxrs_verbs = {mm.group(1) for mm in JAXRS_ROUTE_RE.finditer(text)}
        jaxrs_path = JAXRS_PATH_RE.search(text)

        units: List[CodeUnit] = []
        # 辅助方法 = 非入口方法。注意不能用 startswith("do") 判断：
        # OWASP Benchmark 的清洗辅助方法就叫 doSomething(request, param)。
        helper_src = "\n\n".join(src for n, (_, _, src) in methods.items()
                                 if n not in SERVLET_METHODS)

        for name, (start, end, src) in methods.items():
            decorators: List[str] = []
            route_path = ""

            # Servlet：类级 @WebServlet + 方法名决定 HTTP 动词
            if name in SERVLET_METHODS and wl:
                route_path = wl.group(1)
                decorators.append(f"@WebServlet({route_path})")
                verb = HTTP_VERB_OF.get(name)
                if verb:
                    decorators.append(f"@{verb}")

            # Spring：方法名 + 注解
            if name in spring_routes:
                decorators.append(f"@{name}({spring_routes[name].strip()})")
                route_path = route_path or self._first_string_literal(spring_routes[name])

            # JAX-RS：@Path + @GET/@POST（HTTP 动词用方法名近似）
            if jaxrs_path and (name.upper() in jaxrs_verbs or
                               any(v in name.upper() for v in ("GET", "POST", "PUT", "DELETE"))):
                decorators.append(f"@Path({jaxrs_path.group(1)})")
                route_path = route_path or jaxrs_path.group(1)

            if not decorators:
                continue

            # 入口方法 + 同文件私有辅助方法（污点清洗常发生在辅助方法里）
            source = src if not helper_src else f"{src}\n\n// ---- 同文件辅助方法 ----\n{helper_src}"
            # 回填配置实际取值：算法名/参数常来自配置文件，缺了它模型只能猜
            source += self._config_block(source)
            # 跨文件辅助方法：工厂方法里的真实算法是关键证据
            source += self._resolve_cross_file_helpers(source)

            units.append(CodeUnit(
                file_path=str(path),
                language=self.language,
                unit_name=f"{cls_name}.{name}",
                start_line=start,
                end_line=end,
                decorators_or_modifiers=decorators,
                called_symbols=self._called_symbols(src),
                source_code=source,
            ))
        return units

    @staticmethod
    def _first_string_literal(args: str) -> str:
        m = re.search(r"\"([^\"]*)\"", args)
        return m.group(1) if m else ""

    @staticmethod
    def _called_symbols(source: str) -> List[str]:
        exclude = {"if", "for", "while", "switch", "catch", "return", "new",
                   "super", "this", "println", "String", "Integer"}
        out = set()
        for m in re.finditer(r"(?:\.|\b)([A-Za-z_]\w*)\s*\(", source):
            n = m.group(1)
            if n not in exclude:
                out.add(n)
        return sorted(out)
