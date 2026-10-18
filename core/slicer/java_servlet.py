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
        self._wiring = None

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

    def _wiring_resolver(self):
        """懒加载框架装配索引（URL → 全局 Filter / Interceptor）。

        为什么不复用 JavaImplResolver：那个索引的方向是"方法 → 它调用了什么"，
        而 CORS 这类的防护根本不在调用链上 —— `/cors/sec/originFilter` 的方法体
        是 `return token;`，防护靠 `@WebFilter(urlPatterns=...)` 挂上去。
        方向相反，必须单独建索引。
        """
        if self._wiring is None:
            from core.context.framework_wiring import FrameworkWiringResolver
            self._wiring = FrameworkWiringResolver(self.config_root,
                                                   source_root=self.repo_path)
        return self._wiring

    def _impl_resolver(self):
        """懒加载跨文件实现体索引（MyBatis Mapper / 接口实现 / @Select）。"""
        if self._impls is None:
            from core.context.java_impl_resolver import JavaImplResolver
            self._impls = JavaImplResolver(self.config_root,
                                           source_root=self.repo_path)
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

        为什么"本地方法"不能用 `_iter_methods` 判（真实根因，踩过一次）：
        Controller 和 Mapper **方法同名**是 MyBatis 的常规写法 ——

            // MyBatis.java（Controller）
            public List<User> orderBySafe(String field) {
                return userMapper.orderBySafe(field);      // 调的是 Mapper
            }
            // UserMapper.java（interface）
            List<User> orderBySafe(String field);          // 同名声明

        旧实现用 `{n for n,_b,_i in _iter_methods(body)}` 算"本地已定义的方法"，
        而 `_iter_methods` 会把接口的抽象声明也算进去 —— 于是 `orderBySafe`
        被判成"本地方法"，`continue` 掉，Mapper 实现体永远不注入。
        Hello-Java-Sec 的 6 条 MyBatis 样本全部栽在这里，而且**不报错**：
        切片看起来完整（有配置块、有装配证据），只是缺了最关键的那段 SQL。

        正确判据是"切片里有没有它的**实现体**"，不是"有没有这个名字"。
        """
        from core.context.java_impl_resolver import _entry_only, _iter_methods as _im

        r = self._impl_resolver()
        r.build()
        body = _entry_only(source)
        # 只看**带方法体**的定义（`_iter_methods` 第三位是 is_interface）。
        local = {n for n, _b, is_iface in _im(body) if not is_iface}
        picked: list = []
        seen: set[str] = set()

        for m in self.DATA_CALL_RE.finditer(body):
            var, name, args = m.group(1), m.group(2), m.group(3)
            if name in seen or len(name) < 3 or var in ("this", "super"):
                continue
            a = args.strip()
            # 无参 / 纯字面量调用一般不可能是数据汇聚点，跳过省 token。
            # **但 Mapper / Repository 调用必须例外**：`userMapper.OrderByUsername()`
            # 零参，可它的语句在 Mapper XML 里 —— 那才是判定注入的面。
            zero_arg_ok = bool(re.search(
                r"(?i)(mapper|repository|dao|daoimpl)$", var)) or \
                bool(re.search(r"(?i)(Mapper|Repository|Dao)$", name))
            if not a and not zero_arg_ok:
                continue
            if a and not re.search(r"[A-Za-z_]\w*", a) and not zero_arg_ok:
                continue
            # "本地方法"判定必须放在过滤之后，而且只挡**切片里真有实现体**的同名方法。
            #
            # 为什么不能简单地 `if name in local: continue`：
            # Controller 和 Mapper 同名是 MyBatis 的常规写法 ——
            #     // MyBatis.java（Controller）
            #     public List<User> orderBySafe(String field) {
            #         return userMapper.orderBySafe(field);   // 调的是 Mapper
            #     }
            # `_entry_only` 保留了 Controller 这一个方法，`local` 里必然有
            # `orderBySafe`，于是 Mapper 的 SQL 永远不注入 —— 而且不报错，
            # 切片看起来完整（配置块、装配证据都在），只缺最关键那段 SQL。
            # Hello-Java-Sec 的 6 条 MyBatis 样本全栽在这里。
            #
            # 正确判据是「调用点是不是自调用」：`this.x()` 或无接收者的 `x()`
            # 才是自调用；`userMapper.x()` 的接收者是另一个对象，即使同名
            # 也不是本地方法。这里用接收者判断，`local` 只作为
            # "接收者等于当前类实例"的补充证据。
            if name in local and var in ("this", "super"):
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

    def _template_block(self, own_body: str) -> str:
        """视图模板渲染点证据（见 `core/context/view_templates.py`）。

        只用**入口方法自己的体**去取视图名和 model 键：切片里已经拼进来的
        同文件辅助方法/证据段会让视图名取自别的路由，贴错页面比不贴更糟。
        """
        try:
            from core.context.view_templates import template_evidence
            return template_evidence(self.config_root or self.repo_path, own_body)
        except Exception:                       # noqa: BLE001 —— 增强项，宁可没有
            return ""

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
                                    max_methods: int = 4) -> str:
        """顺着源码里调用的方法名，在其他 Java 文件中找出方法体并附上。

        动机：`Utils.getCipher()` 这类工厂方法把算法/配置藏在 helper 类里，
        只看入口文件会缺失关键证据（OWASP Benchmark 的 crypto 误报主因）。

        三道防污染闸门（都是真实项目评测里踩出来的）：
          1. 只认数据/工厂类调用 `obj.method(...)`，不认裸调用 `foo(...)`
             —— 否则 `source.indexOf(x)` 会把整个仓库里所有叫 indexOf 的方法
             吸进来。
          2. 方法名必须真的在代码里被 `obj.` 修饰调用过。
          3. 本文件内已定义的方法体不再重复注入 —— 同文件里往往并排放着
             「安全写法」和「漏洞写法」两个路由，重复注入等于把 vuln 代码
             塞进 sec 样本，模型必然误报（实测 SpEL.spel_sec 与
             SQLI.mybatisOrderBySec04 两条误报全部源于此）。
        """
        if depth <= 0:
            return ""
        # 先掐掉已注入的部分，避免把上一轮附加的代码再扫一遍
        body = source.split("// ---- ", 1)[0]
        from core.context.java_impl_resolver import _iter_methods as _im
        local = {name for name, _b, _i in _im(body)}

        calls: set[str] = set()
        for m in self.DATA_CALL_RE.finditer(body):
            name = m.group(2)
            if name in local or len(name) < 4:
                continue
            if name in self.TRACE_EXCLUDE or name in SERVLET_METHODS:
                continue
            calls.add(name)
        if not calls:
            return ""

        index = self._method_index()
        found: list[str] = []
        ranked = []
        for name in sorted(calls):
            hit = index.get(name)
            if hit is None:
                continue
            path, start_line, hb = hit
            # 同文件的方法体已在切片里，跳过
            if Path(path).resolve() == getattr(self, "_current_file", None):
                continue
            ranked.append((self._security_relevance(name, hb), name, path, start_line, hb))
        ranked.sort(key=lambda x: -x[0])

        for _score, _name, path, start_line, hb in ranked[:max_methods]:
            found.append(f"// 来自 {Path(path).name}:{start_line}\n{hb}")

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
            from core.context.java_impl_resolver import _read_cached
            text = _read_cached(java)
            if not text:
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
            from core.context.java_impl_resolver import _read_cached
            text = _read_cached(java)
            if not text:
                continue
            units.extend(self._slice_file(java, text))
        self._attach_chains(units)
        return units

    def _attach_chains(self, units: List[CodeUnit]) -> None:
        """为每个入口补「跨路由串接证据」：本方法写进介质的键，被谁读走了。

        必须放在整库切片**之后**做，不能放进 `_slice_file` —— 存储型漏洞的
        读取点常在另一个文件里，单文件视角看不到。

        证据只贴在**写入方**上。理由是判定语义：写入方是"输入的来源入口"，
        读取方本身没有外部参数，单看它无从谈起污点；而写入方缺的恰恰是
        "我写出去的值最终会原样出现在别处的响应里"这个事实。

        例外是 db 介质：同一仓储字段上的"调用"分不出写和读（`xssMapper.add`
        与 `xssMapper.list()` 形态相同），所以两侧都贴 —— 谁写谁读交给判定层。

        失败必须静默降级：串接是增强项，索引出错不能拖垮整个切片流程。
        """
        if not units:
            return
        try:
            from core.context.taint_chain import build_chains, render_chain_block
            # 不传 entries_only：build_chains 默认优先读 CodeUnit.own_body，
            # 那里存的正是未追加辅助方法的入口方法体。
            chains = build_chains(units, repo_root=self.config_root or self.repo_path)
        except Exception:                       # noqa: BLE001 —— 增强项，宁可没有
            return
        if not chains.links:
            return

        by_name = {u.unit_name: u for u in units}
        for u in units:
            links = chains.links_of_writer(u.unit_name)
            if not links:
                continue
            # 读取点方法体：只贴方法本体，不贴它的跨文件证据（避免切片膨胀）。
            # 必须按读取方逐个给（db 介质一次会连上多个读取点，只贴第一个
            # 会让判定层以为"读取点没回显"）。
            reader_bodies: dict[str, str] = {}
            for l in links:
                if l.reader.unit_name in reader_bodies:
                    continue
                reader = by_name.get(l.reader.unit_name) or l.reader
                text = reader.source_code or ""
                sep = text.find("// ----")
                reader_bodies[l.reader.unit_name] = (
                    text[:sep].strip() if sep > 0 else text.strip())
            block = render_chain_block(links, reader_bodies)
            if block:
                u.source_code += block

    @staticmethod
    def _iter_under(root: Path):
        for p in root.rglob("*.java"):
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            yield p

    # ---------- 单文件切片 ----------

    def _slice_file(self, path: Path, text: str) -> List[CodeUnit]:
        self._current_file = path.resolve()      # 供跨文件注入时排除本文件
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

        # 先判定哪些方法是**路由方法**，再做辅助方法拼接。
        #
        # 这里必须单独算一遍，不能只看 SERVLET_METHODS：
        # Servlet 的路由方法确实叫 doGet/doPost，但 Spring/JAX-RS 的路由方法
        # 名字是任意的（`store` / `safe` / `getImage`）。若只排除 SERVLET_METHODS，
        # 同一个 Controller 里的 vuln 路由和 sec 路由会互相被当成"辅助方法"
        # 拼进对方的切片 —— 实测 XSS.safe 的切片里出现了 store 的 `addCookie`
        # 和 reflect 的整个方法体，审 sec 时模型看到了 vuln 代码。
        #
        # 这条对规则层无害（规则用 entry_body() 截断），但走模型的分支
        # （pathtraver / cmdi 等）会直接吃到污染证据。
        route_methods: set[str] = set()
        for _n, (_s, _e, _src, _anns) in methods.items():
            if _n in SERVLET_METHODS and wl:
                route_methods.add(_n)
                continue
            if any(SPRING_ROUTE_RE.match(a) for a in _anns):
                route_methods.add(_n)
                continue
            if any(re.match(r"@(GET|POST|PUT|DELETE|PATCH)\b", a) for a in _anns):
                route_methods.add(_n)
            elif any(a.startswith("@Path") for a in _anns):
                route_methods.add(_n)

        # 辅助方法 = 既非 Servlet 动词、也非路由方法。
        # 注意不能用 startswith("do") 判断：
        # OWASP Benchmark 的清洗辅助方法就叫 doSomething(request, param)。
        helper_src = "\n\n".join(src for n, (_, _, src, _a) in methods.items()
                                 if n not in SERVLET_METHODS
                                 and n not in route_methods)

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
            # 视图模板：`model.addAttribute("k", v)` + `return "view"` 的渲染点
            # 在 .html/.ftl 里，不在 Java 里。这是存储/反射型 XSS 最常见的
            # 跨文件形态，不贴进来判定层就只能看到"放进 model 就返回了"。
            source += self._template_block(src)
            # 跨文件辅助方法：工厂方法里的真实算法是关键证据
            source += self._resolve_cross_file_helpers(source)
            # 跨文件实现体：MyBatis Mapper 的 #{} / ${} 决定 SQL 注入真值
            source += self._impl_block(source)
            # 框架装配：CORS 这类的防护在 Filter/Bean 里，方法体里根本看不到。
            # 放在 config 之后单独补一个换行，避免和配置块最后一行粘连。
            if route_path:
                w = self._wiring_resolver().describe(route_path)
                if w:
                    source += "\n" + w

            units.append(CodeUnit(
                file_path=str(path),
                language=self.language,
                unit_name=f"{cls_name}.{name}",
                start_line=start,
                end_line=end,
                decorators_or_modifiers=decorators,
                called_symbols=self._called_symbols(src),
                source_code=source,
                own_body=src,
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
