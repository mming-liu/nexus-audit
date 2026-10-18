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

# 方法声明（含返回类型、方法名、参数列表）。
# 不用「前面必须是 行首/;/{/}」这类锚点：真实代码里方法前面通常紧跟注解行，
# 注解以 ")" 结尾，锚点会直接失效（java-sec-code 的 SQLI.java 11 个路由只切出 1 个）。
# 改为不锚定 + 由调用方做上下文校验（必须是类体内、有访问修饰符或返回类型合法）。
# 返回类型：禁止嵌套量词。原写法 `(?:[\w.]+(?:<[^>]*>)?(\[\])*\s*)+?` 在匹配失败时
# 会产生灾难性回溯（java-sec-code 的 SQLI.java 直接卡死），改为单层字符类：
# 允许 标识符/点/泛型尖括号/数组方括号/逗号/空格/问号，整体不限量但无嵌套。
METHOD_RE = re.compile(
    r"[ \t]*"
    r"(?:public|protected|private)\s+"
    r"(?:(?:static|final|synchronized|abstract|native|default)\s+)*"
    r"([\w\.\<\>\[\]\,\?\s]+?)\s+"                          # 返回类型（单层字符类，无回溯风险）
    r"([A-Za-z_]\w*)\s*"                                     # 方法名
    r"\(",                                                   # 左括号（参数列表用配平解析）
    re.M,
)


def _match_paren(text: str, open_idx: int) -> int:
    """从 '(' 起做圆括号配平，返回匹配的 ')' 下标。

    必须配平：Spring 参数上常带注解，如
    `foo(@RequestParam("username") String username)`，
    用 `\\([^)]*\\)` 会在注解的内层 ')' 处提前收尾，导致整个方法无法识别。
    """
    depth = 0
    in_str = None
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == in_str:
                in_str = None
        elif ch in "\"'":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1
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
        self._impls = None

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

    # ---------- 跨文件实现体证据（MyBatis / 接口实现） ----------

    MAX_IMPL_HITS = 3

    def _impl_resolver(self):
        """懒加载跨文件实现体索引（MyBatis Mapper / 接口实现 / @Select）。"""
        if self._impls is None:
            from core.context.java_impl_resolver import JavaImplResolver
            self._impls = JavaImplResolver(self.config_root)
        return self._impls

    def _impl_block(self, source: str) -> str:
        """为「真正传了外部入参的调用」补实现体，再为「防护类静态调用」补工具类实现。

        为什么必须按实参过滤：`userMapper.findByUserName(username)` 与
        `userMapper.findByUserNameVuln01(username)` 的方法体完全同构，
        唯一差别在 Mapper 里是 `#{}` 还是 `${}`。若只按方法名索引而不核对实参，
        就会把同类其它路由的漏洞语句注入当前样本（审 sec 却看到 vuln 的 SQL）。

        为什么要单独补「无参静态调用」：java-sec-code 的 SSRF 防护思路是
        `SecurityUtil.startSSRFHook()` 开启 socket 层域名解析校验。这是一个
        **零参数**调用，按「有没有外部入参」过滤会被整体丢掉，模型只看到
        "没有 IP 校验" 就判成漏洞 —— 实测 8 条 SSRF 误报全部源于此。
        防护类调用恰恰常常不带参数，所以按方法名再补一轮。
        """
        from core.context.java_impl_resolver import _entry_only, _iter_methods as _im

        r = self._impl_resolver()
        r.build()
        body = _entry_only(source)
        local = {n for n, _b, _i in _im(body)}
        picked: list = []
        seen: set[str] = set()

        for m in self.DATA_CALL_RE.finditer(body):
            var, name, args = m.group(1), m.group(2), m.group(3)
            if name in seen or len(name) < 3 or var in ("this", "super"):
                continue
            if name in local:
                continue
            a = args.strip()
            # 无参 / 纯字面量调用不可能是数据汇聚点，跳过省 token
            if not a or not re.search(r"[A-Za-z_]\w*", a):
                continue
            seen.add(name)
            for h in r.lookup(name, limit=1):
                if h.kind == "java_interface":
                    continue
                picked.append(h)

        # 第二轮：防护语义的无参静态调用（startXxxHook / checkXxx / isHttp ...）
        for name in {m.group(2) for m in self.DATA_CALL_RE.finditer(body)}:
            if name in seen or name in local or len(name) < 4:
                continue
            if not self._GUARD_NAME.search(name):
                continue
            seen.add(name)
            for h in r.lookup(name, limit=1):
                if h.kind == "java_interface":
                    continue
                picked.append(h)

        if not picked:
            return ""
        order = {"mybatis_anno": 0, "mybatis_xml": 0, "java_impl": 1}
        picked.sort(key=lambda h: order.get(h.kind, 2))
        picked = picked[: self.MAX_IMPL_HITS]
        head = ("\n\n// ---- 跨文件证据：以下为实现体，"
                "判定汇聚点实际行为时以此为准确认 ----\n")
        return head + "\n".join(h.render() for h in picked)

    # 调用点：`obj.method(args)`，实参用括号配平无法用正则表达，
    # 这里只取到第一个 `(` 之后的一段，够用于「是否带标识符实参」的判断
    DATA_CALL_RE = re.compile(
        r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(([^()]{0,120})", re.S
    )

    # 防护语义命名：这类方法往往零参数（如 startSSRFHook()），但正是判定的关键
    _GUARD_NAME = re.compile(
        r"^(?:start|stop|check|is|has|verify|validate|sanitize|filter|escape|"
        r"encode|block|allow|deny|prevent|assert)\w*$", re.I
    )

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

    @staticmethod
    def _collect_annotations_upward(text: str, line_start: int) -> tuple[int, list[str]]:
        """从方法声明行向上回溯，收集连续的注解行（允许中间有空行）。

        真实 Spring 代码里注解与签名之间常有空行、Javadoc、或者注解带多参数换行，
        只判断"紧邻上一行"会全部漏掉 —— java-sec-code 上入口提取为 0 就是这个原因。
        返回 (声明起始下标, 注解文本列表)。
        """
        decl_idx = line_start
        anns: list[str] = []
        cur = line_start
        blank_seen = 0
        while cur > 0:
            prev_end = cur - 1
            prev_start = text.rfind("\n", 0, prev_end) + 1
            prev_line = text[prev_start:prev_end].strip()
            if not prev_line:
                blank_seen += 1
                if blank_seen > 1:      # 连续两个空行视为注解块结束
                    break
                cur = prev_start
                continue
            blank_seen = 0
            if prev_line.startswith("@"):
                anns.insert(0, prev_line)
                decl_idx = prev_start
                cur = prev_start
                continue
            # 注解参数跨行：上一行是参数续行（以 "," 结尾或未闭合括号）
            if anns and (prev_line.endswith(",") or prev_line.endswith("(")
                         or (prev_line.count("(") > prev_line.count(")"))):
                anns[0] = prev_line + " " + anns[0]
                decl_idx = prev_start
                cur = prev_start
                continue
            break
        return decl_idx, anns

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

        # 类级路由前缀：Spring 的 @RequestMapping("/sqli") 加在类上
        class_prefix = ""
        head = text[:cls_m.start()]
        cp = SPRING_ROUTE_RE.search(head)
        if cp:
            class_prefix = self._first_string_literal(cp.group(2))
        elif JAXRS_PATH_RE.search(head):
            class_prefix = JAXRS_PATH_RE.search(head).group(1)

        # 收集本文件所有方法：name -> (start, end, source, annotations)
        # 先用正则粗扫，再用「不落在其他方法体内」过滤掉嵌套误匹配
        methods: dict[str, tuple[int, int, str, list[str]]] = {}
        occupied: list[tuple[int, int]] = []      # 已确认方法体区间
        cands = []
        for m in METHOD_RE.finditer(text):
            ret_type, name = m.group(1).strip(), m.group(2)
            if name in {"if", "for", "while", "switch", "catch", "return", "new"}:
                continue
            if ret_type in {"else", "try", "do"}:
                continue
            # 参数列表配平：跳过 annotation 里的内层括号
            paren_open = m.end() - 1
            paren_close = _match_paren(text, paren_open)
            if paren_close == -1:
                continue
            # 参数之后应当是 throws 子句或方法体 '{'
            after = text[paren_close + 1: paren_close + 400]
            body_off = re.match(r"\s*(?:throws\s+[\w\s,\.]+?)?\s*\{", after)
            if not body_off:
                continue
            open_idx = paren_close + 1 + body_off.end() - 1
            close_idx = _brace_match(text, open_idx)
            if close_idx == -1:
                continue
            cands.append((m, ret_type, name, open_idx, close_idx))

        # 外层优先（方法体更长的先占位），内层误匹配被剔除
        cands.sort(key=lambda c: c[4] - c[3], reverse=True)
        for m, ret_type, name, open_idx, close_idx in cands:
            if any(a <= m.start(2) <= b for a, b in occupied):
                continue            # 落在已确认的方法体内，是嵌套代码而非方法声明
            occupied.append((open_idx, close_idx))
            line_start = text.rfind("\n", 0, m.start(2)) + 1
            decl_idx, anns = self._collect_annotations_upward(text, line_start)
            start_line = _line_of(text, decl_idx)
            end_line = _line_of(text, close_idx)
            methods.setdefault(name, (start_line, end_line,
                                      text[decl_idx:close_idx + 1], anns))

        if not methods:
            return []

        wl = WEBSERVLET_RE.search(text)

        units: List[CodeUnit] = []
        # 辅助方法 = 非入口方法。注意不能用 startswith("do") 判断：
        # OWASP Benchmark 的清洗辅助方法就叫 doSomething(request, param)。
        helper_src = "\n\n".join(src for n, (_, _, src, _a) in methods.items()
                                 if n not in SERVLET_METHODS)

        for name, (start, end, src, anns) in methods.items():
            decorators: List[str] = []
            route_path = ""

            # Servlet：类级 @WebServlet + 方法名决定 HTTP 动词
            if name in SERVLET_METHODS and wl:
                route_path = wl.group(1)
                decorators.append(f"@WebServlet({route_path})")
                verb = HTTP_VERB_OF.get(name)
                if verb:
                    decorators.append(f"@{verb}")

            # Spring：方法级映射注解（@RequestMapping/@GetMapping/...）
            for ann in anns:
                m = SPRING_ROUTE_RE.match(ann)
                if not m:
                    continue
                decorators.append(ann)
                sub = self._first_string_literal(m.group(2))
                route_path = route_path or (class_prefix.rstrip("/") + "/" + sub.lstrip("/")).rstrip("/")

            # JAX-RS：@Path + @GET/@POST（方法级注解）
            jax_verb = next((a[1:].split("(")[0] for a in anns
                             if re.match(r"@(GET|POST|PUT|DELETE|PATCH)\b", a)), None)
            jax_path = next((a for a in anns if a.startswith("@Path")), None)
            if jax_verb and (jax_path or class_prefix):
                decorators.append(jax_path or f"@{jax_verb}")
                if jax_path:
                    sub = self._first_string_literal(jax_path)
                    route_path = class_prefix.rstrip("/") + "/" + sub.lstrip("/")

            if not decorators:
                continue

            # 入口方法 + 同文件私有辅助方法（污点清洗常发生在辅助方法里）
            source = src if not helper_src else f"{src}\n\n// ---- 同文件辅助方法 ----\n{helper_src}"
            # 回填配置实际取值：算法名/参数常来自配置文件，缺了它模型只能猜
            source += self._config_block(source)
            # 跨文件辅助方法：工厂方法里的真实算法是关键证据
            source += self._resolve_cross_file_helpers(source)
            # 跨文件实现体：MyBatis Mapper 的 #{} / ${} 决定 SQL 注入真值
            source += self._impl_block(source)

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
