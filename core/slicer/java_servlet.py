"""Java Web 入口切片器（第5周补充：为 OWASP Benchmark 跑分打通 Java 赛道）。

覆盖范围：
  - Servlet 3.0 注解式路由：@WebServlet(value = "/x") + doGet/doPost/doPut/doDelete
  - Spring MVC 注解式路由：@RequestMapping/@GetMapping/@PostMapping 方法
  - JAX-RS：@Path + @GET/@POST 方法

输出 CodeUnit：
  - unit_name 取 「类名.methodName」，便于与 expectedresults 中的类名对齐。
    同名重载（RESTful 控制器里很常见）追加 `#2`/`#3` 后缀区分，裸名留给
    源码顺序的第一个 —— 见 `_slice_file` 里的 `occur` 计数。
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
from core.text_utils import strip_java_comments

IGNORE_DIRS = {".git", "target", "build", "node_modules", "test", "tests"}

# 接口头（含 extends 子句）。`_interface_index()` 靠它拿到「这个方法是框架
# 派生查询」的唯一依据 —— `extends JpaRepository<Person, String>`。
# 泛型里可以有逗号和空格，所以 extends 段用 `[^{]+` 一路吃到左花括号。
INTERFACE_HEAD_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:public|protected|abstract|static|final)\s+)*"
    r"interface\s+(\w+)\s*(?:extends\s+[^{]+)?\{")

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
        self._deps = None
        self._subjects = None

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

    def _dep_resolver(self):
        """懒加载构建文件里的敏感组件版本（fastjson / shiro / jackson …）。

        与 `_wiring_resolver` 同理：版本是**方法体外的证据**，
        但 `JSON.parseObject(x)` 在 fastjson 1.2.31 与 1.2.83 上是两个结论。
        没有这一块，判定层只能退回模型，而模型手里根本没有 pom.xml。
        """
        if self._deps is None:
            from core.context.dependency_versions import DependencyVersionResolver
            self._deps = DependencyVersionResolver(self.config_root)
        return self._deps

    def _subject_resolver(self):
        """懒加载「哪个形参注解注入的是当前用户」。

        前后端分离项目的主体在**签名**上（`@TokenToMallUser MallUser user`），
        方法体里一行 `session.getAttribute` 都没有，判定层便把它当成"不取主体
        → 入参直查资源"，newbee-mall-api 实测 17 条如此误报。
        索引来自 `implements HandlerMethodArgumentResolver` 的 `supportsParameter`，
        不按注解名猜。
        """
        if self._subjects is None:
            from core.context.argument_resolvers import SubjectParamResolver
            self._subjects = SubjectParamResolver(self.repo_path)
        return self._subjects

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

        for var, name, args in self._iter_data_calls(body):
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
            h = self._pick_impl(r.lookup(name, limit=6), var, name)
            if h is not None and h.kind != "java_interface":
                picked.append(h)

        # 第二轮：防护语义的无参静态调用（startXxxHook / checkXxx / isHttp ...）
        for name in {n for _v, n, _a in self._iter_data_calls(body)}:
            if name in seen or name in local or len(name) < 4:
                continue
            if not self._GUARD_NAME.search(name):
                continue
            seen.add(name)
            h = self._pick_impl(r.lookup(name, limit=6), "", name)
            if h is not None and h.kind != "java_interface":
                picked.append(h)

        if not picked:
            return ""
        order = {"mybatis_anno": 0, "mybatis_xml": 0, "java_impl": 1}
        picked.sort(key=lambda h: order.get(h.kind, 2))
        picked = picked[: self.MAX_IMPL_HITS]
        head = ("\n\n// ---- 跨文件证据：以下为实现体，"
                "判定汇聚点实际行为时以此为准确认 ----\n")
        return head + "\n".join(h.render() for h in picked)

    # 调用点头部：`obj.method(`。**实参不在正则里捕获**，见 `_iter_data_calls`。
    #
    # 旧写法把实参一起捕获：`\(([^()]{0,120})`。`[^()]` 遇到内层调用的 `(` 就停，
    # 但 finditer 从**停止处**继续扫，于是外层实参把内层调用的接收者整段吃掉：
    #
    #     request.setAttribute("pageResult", newBeeMallGoodsService.searchNewBeeMallGoods(pageUtil));
    #     └─ 匹配 setAttribute，实参一路吃到 "...searchNewBeeMallGoods" 的 '('
    #        下一轮从 '(' 开始扫 → `newBeeMallGoodsService.` 再也不会被匹配
    #
    # 真实业务里几乎**所有**服务调用都嵌在 return / setAttribute / Result.success
    # 里面，内层调用的接收者被外层实参吃掉就再也不会被匹配 —— 不报错，只是
    # 那几个入口的跨文件实现体永远不展开。newbee-mall 实测：8 个入口、8 个调用点，
    # 全是分页列表与商品搜索（最可能出 SQLi 的那批）。
    DATA_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(", re.S)

    def _call_args(self, text: str, start: int) -> str:
        """从 `(` 之后取配平实参，能穿过嵌套调用与字符串里的括号。"""
        depth, i, n = 1, start, len(text)
        while i < n and depth:
            c = text[i]
            if c == '"':
                i += 1
                while i < n and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        return text[start:i]

    def _iter_data_calls(self, text: str):
        """产出 `(接收者, 方法名, 配平实参)`；嵌套调用各自成为独立一条。"""
        for m in self.DATA_CALL_RE.finditer(text):
            yield m.group(1), m.group(2), self._call_args(text, m.end())

    # 零参、只 `return 字段;` / 只 `this.字段 = 参数;` 的读写器。它们**不携带任何
    # 汇聚点证据**，却会占掉每跳 4 个名额里的一半 —— newbee-mall 实测：searchPage
    # 的第 2 跳被 `getCategoryId` / `setCurrentCategoryName` 这类访问器占满，
    # 真正含 SQL 的 `findNewBeeMallGoodsListBySearch` 一个名额都没有。
    #
    # 与「返回字面量的方法」要区分开：`return "bob";` 是**常量来源**证据
    # （OWASP `getTheValue` 那类跨方法常量回溯靠它），不能一起滤掉 —— 这里的
    # 判据要求返回/赋值两端都是**裸标识符**，字面量与调用都不匹配。
    _TRIVIAL_ACCESSOR_RE = re.compile(
        r"^[^{]*\)\s*\{\s*(?:return\s+(?:this\s*\.\s*)?[A-Za-z_]\w*\s*;"
        r"|(?:this\s*\.\s*)?[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*;)\s*\}\s*$", re.S)

    # 接收者语义 → 期望的实现体种类。`login` 在 newbee-mall 有 4 处定义
    # （AdminUserMapper.xml / AdminUserServiceImpl / NewBeeMallUserServiceImpl /
    # AdminController 自己），`lookup(name, limit=1)` 取到哪个纯看索引顺序。
    # 实测后果：Mapper 的 SQL 被贴到 Controller 的登录调用上，真正的
    # ServiceImpl 反倒没进来 —— 证据看起来"有 SQL"，但那不是这条链路的 SQL。
    #
    # 接收者变量名本身就是消歧键，和实参消歧（第 38 条）是同一个道理：
    # `xxxMapper/xxxDao` 期望 XML/注解语句，`xxxService` 期望接口实现类。
    _SVC_RECV_RE = re.compile(r"(?:Service|Manager|Facade)$", re.I)
    _MAP_RECV_RE = re.compile(r"(?:Mapper|Repository|Dao|DAO)$", re.I)

    def _pick_impl(self, hits, var: str, name: str):
        """在多个同名实现体里按「接收者 + 类名前缀」挑一个，挑不出就取最优。"""
        if not hits:
            return None
        want_xml = bool(self._MAP_RECV_RE.search(var)) or \
            bool(re.search(r"(?:Mapper|Repository|Dao|DAO)$", name))
        want_java = bool(self._SVC_RECV_RE.search(var))

        def rank(h):
            is_xml = h.kind in ("mybatis_xml", "mybatis_anno")
            if want_xml:
                return 0 if is_xml else 1
            if is_xml:
                return 2 if want_java else 1
            if want_java and h.kind != "java_impl":
                return 1
            # 类名与接收者变量同前缀：`adminUserService` ↔ AdminUserServiceImpl
            stem = Path(h.file).stem.lower()
            if var and stem.startswith(var.lower()):
                return 0
            # mall 前缀包形态：变量 productCategoryService ↔
            # PmsProductCategoryServiceImpl（stem 是 `pms` + var）。
            # 后缀比对能唯一区分同貌接口：pmsproductattributecategoryservice
            # 不以 productcategoryservice 结尾，不会误配（Module 38 实测）。
            if var and stem.removesuffix("impl").endswith(var.lower()):
                return 0
            return 1
        return sorted(hits, key=rank)[0]

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

    # 跨文件调用链的最大跳数。企业项目真实链路是
    # Controller → Facade → Service(I) → ServiceImpl → Manager/Helper → DAO → Mapper，
    # 4~6 跳。1 跳只够拿"工厂方法里的算法"，够不到"第 3 跳里的 SQL 拼接"。
    #
    # 实测（2026-10-20，`.hop_probe` 四跳探针）：
    #   Controller.detail → Facade.query → Service.getDetail → Dao.rawQuery → sink
    #   深度 1 时切片里只有 Facade.query，`SELECT * FROM orders` 完全不在，
    #   sqli 规则只能返回 None，模型看不到 sink 必然答 No —— **静默漏报**。
    MAX_HOPS = 4

    # 整条链允许注入的段落总数。跳数放宽后必须同时限总量，否则每跳 4 个方法
    # 会变成 4^4：既烧 token，也会把不相关的方法体塞进来淹没真证据。
    MAX_HELPER_SEGMENTS = 10

    def _resolve_cross_file_helpers(self, source: str, depth: int | None = None,
                                    max_methods: int = 4,
                                    _visited: set[str] | None = None,
                                    _budget: list[int] | None = None) -> str:
        """顺着源码里调用的方法名，在其他 Java 文件中找出方法体并附上（支持多跳）。

        动机：`Utils.getCipher()` 这类工厂方法把算法/配置藏在 helper 类里，
        只看入口文件会缺失关键证据（OWASP Benchmark 的 crypto 误报主因）。

        **多跳的理由不是"更全"，而是"没有它就看错方向"**：4 跳链路里
        SQL 拼接在第 4 跳，切片只到第 1 跳时规则看不到任何 sink，只能返回
        None；模型同样看不到，于是答"没有 SQL 注入"—— 这不是保守，是把
        真漏洞判成了安全。

        三道防污染闸门（都是真实项目评测里踩出来的）：
          1. 只认数据/工厂类调用 `obj.method(...)`，不认裸调用 `foo(...)`
             —— 否则 `source.indexOf(x)` 会把整个仓库里所有叫 indexOf 的方法
             吸进来。
          2. 方法名必须真的在代码里被 `obj.` 修饰调用过。
          3. 本文件内已定义的方法体不再重复注入 —— 同文件里往往并排放着
             「安全写法」和「漏洞写法」两个路由，重复注入等于把 vuln 代码
             塞进 sec 样本，模型必然误报（实测 SpEL.spel_sec 与
             SQLI.mybatisOrderBySec03 两条误报全部源于此）。

        多跳新增的两道闸门：
          4. `_visited` 按方法名去重 —— A→B→A 这类环不展开。
          5. `_budget` 限总段落数 —— 跳数放宽不等于无限展开。
        """
        if depth is None:
            depth = self.MAX_HOPS
        top = _visited is None
        if _visited is None:
            _visited = set()
        if _budget is None:
            _budget = [self.MAX_HELPER_SEGMENTS]
        if depth <= 0 or _budget[0] <= 0:
            return ""
        # 先掐掉已注入的部分，避免把上一轮附加的代码再扫一遍
        body = source.split("// ---- ", 1)[0]
        from core.context.java_impl_resolver import _iter_methods as _im
        local = {name for name, _b, _i in _im(body)}

        calls: set[str] = set()
        call_var: dict[str, str] = {}
        for var, name, _args in self._iter_data_calls(body):
            if name in local or len(name) < 4:
                continue
            if name in self.TRACE_EXCLUDE or name in SERVLET_METHODS:
                continue
            if name in _visited:
                continue
            calls.add(name)
            call_var.setdefault(name, var)
        if not calls:
            return ""

        index = self._method_index()
        # MyBatis 的 SQL 只写在 XML / @Select 里，`_method_index` 只收「有方法体的
        # Java 方法」，天然看不见它们。真实分层项目的第 2~3 跳正是这一层：
        #
        #   Controller.searchPage → ServiceImpl.searchNewBeeMallGoods  [Hop 1]
        #     └ newBeeMallGoodsMapper.findNewBeeMallGoodsListBySearch( ) [Hop 2 = XML]
        #
        # 不接这一层，四跳链永远停在 ServiceImpl：模型看到的全是 Java 取值逻辑，
        # 一条 SQL 都没有，却要它判断有没有注入 —— 只有"没有 SQL 就没有注入"
        # 这一条路可走，真漏洞被静默放行。
        try:
            impl = self._impl_resolver()
            impl.build()
        except Exception:                       # noqa: BLE001 —— 增强项，宁可没有
            impl = None

        found: list[str] = []
        ranked = []
        for name in sorted(calls):
            hit = index.get(name)
            if hit is not None:
                path, start_line, hb = hit
                if Path(path).resolve() == getattr(self, "_current_file", None):
                    # 同文件方法体已在切片里；但**同名 Mapper 语句仍可能存在**
                    # （控制器 `list()` ↔ Mapper XML `<select id="list">` 是
                    # CRUD 命名的常态）。不能就此跳过 —— 否则 XML 语句被入口
                    # 的同名方法遮蔽，SQL 段整段丢失（迷你仓库实测复现）。
                    # 继续落到下面的 impl 查找。
                    hit = None
                elif self._TRIVIAL_ACCESSOR_RE.match(hb.strip()):
                    continue
                else:
                    ranked.append((self._security_relevance(name, hb), name, path,
                                   start_line, hb, ""))
                    continue
            if hit is None and impl is None:
                continue
            # **重名不猜，但可以按接收者消歧**：`selectByPrimaryKey` / `insert`
            # 这类通用 CRUD 在 9 个 Mapper 里同名，按方法名取第一个会把
            # CarouselMapper 的 SQL 贴到商品查询的切片里。接收者变量名
            # `newBeeMallGoodsMapper` 与 Mapper 文件名完全对应 —— 唯一匹配时才注入。
            var = call_var.get(name, "")
            xhits = [h for h in impl.lookup(name, limit=8)
                     if h.kind in ("mybatis_xml", "mybatis_anno")]
            if len(xhits) != 1:
                # 后缀匹配而不是全等：真实代码里接收者常被缩写
                # （`goodsMapper` ↔ NewBeeMallGoodsMapper.xml）。仍要求
                # **唯一命中**，`mapper` 这种泛化变量名会撞上多个 → 放弃。
                same = [h for h in xhits
                        if var and Path(h.file).stem.lower().endswith(var.lower())]
                xhits = same if len(same) == 1 else []
            if not xhits:
                continue
            h = xhits[0]
            ranked.append((self._security_relevance(name, h.body), name, h.file,
                           0, h.body, h.kind))
        ranked.sort(key=lambda x: -x[0])

        hop = self.MAX_HOPS - depth + 1
        for _score, _name, path, start_line, hb, kind in ranked[:max_methods]:
            if _budget[0] <= 0:
                break
            _visited.add(_name)
            _budget[0] -= 1
            if kind:
                seg = f"// 来自 {Path(path).name} [Hop {hop}] —— {kind}\n{hb}"
            else:
                seg = f"// 来自 {Path(path).name}:{start_line} [Hop {hop}]\n{hb}"
            found.append(seg)
            # 递归：把**这一跳的段**当作新的 source 继续往下找。
            # 不能拿整份 source 递归 —— 那会把入口体再扫一遍，每跳都重复注入。
            # XML 段没有 Java 调用，不必再展开。
            if depth > 1 and not kind:
                deeper = self._resolve_cross_file_helpers(
                    seg, depth - 1, max_methods, _visited, _budget)
                if deeper:
                    found.append(deeper)

        # 方法体跳展开完之后，再补「接口声明」段。
        #
        # 为什么不放在上面的 ranked 循环里：接口名不该占用方法体跳的名额
        # （`max_methods` 是给真正的方法体留的），而且接口声明不带实现，
        # 不需要递归。只在最外层补一次，避免每跳重复注入同一段。
        #
        # 这一段的存在意义是"补上被方法体索引天然丢掉的那一半"：
        # Spring Data 仓库、MyBatis Mapper 的方法都只有声明。缺了它，
        # 规则只能看到 `personRepository.findPersonByUsername(name)` 一行 ——
        # 既看不到 SQL，也看不到"这是框架派生查询"。
        iface_hits: list[str] = []
        if top:
            iidx = self._interface_index()
            cur = getattr(self, "_current_file", None)
            for name in sorted(calls - _visited):
                hits = iidx.get(name) or []
                if not hits:
                    continue
                # 同名多接口：优先取与入口同 Maven 模块（路径共享
                # `mall-xxx/` 一级工程目录）的声明 —— 跨模块同名方法的
                # 接口头是别的调用方的证据，贴错模块的声明会误导判定。
                def _rank(h):
                    ipath, _ = h
                    if cur:
                        pm = Path(cur).parts[: -3]
                        pi = Path(ipath).parts[:-3]
                        shared = len(set(pm) & set(pi))
                    else:
                        shared = 0
                    return -shared
                ipath, idecl = sorted(hits, key=_rank)[0]
                if Path(ipath).resolve() == (Path(cur).resolve()
                                             if cur else None):
                    continue
                iface_hits.append(f"// 来自 {Path(ipath).name}\n{idecl}")
                if len(iface_hits) >= 3:
                    break

        if not found and not iface_hits:
            return ""
        joined = "\n\n".join(found)
        iface_block = ""
        if iface_hits:
            iface_block = (
                "\n\n// ---- 跨文件证据：被调方法的接口声明"
                "（方法无方法体，实现由框架/子类提供）----\n"
                + "\n\n".join(iface_hits))
        if not top:
            return joined + iface_block
        # 段头只在真有方法体跳时输出。此前写成无条件拼接，`found` 为空、
        # 只有接口声明时会在切片里留一个**空段头**——模型看到"跨文件辅助方法
        # 实现"却没有任何内容，会以为证据被截断了。
        header = ("\n\n// ---- 跨文件辅助方法实现（入口方法调用的外部方法，含真实算法/参数）----\n"
                  if found else "")
        return header + joined + iface_block
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

    def _interface_index(self) -> dict[str, tuple[str, str]]:
        """「方法名 -> (文件, 接口头 + 该方法声明)」索引。

        为什么需要它：`_method_index()` 只收**有方法体**的方法（`METHOD_RE`
        要求后面有 `{`），而 Spring Data 仓库的方法天生没有方法体 ——
            public List<Person> findPersonByUsername(String username);
        于是 `personRepository.findPersonByUsername(name)` 在索引里查不到，
        切片器既不补实现体、也不补声明，规则与模型都只看到一行调用。

        索引内容必须包含**接口头**（`extends JpaRepository<Person, String>`），
        因为"这个方法是框架派生/参数绑定"这一事实的唯一依据就在 extends 子句里。
        只贴方法声明等于把证据又切掉了。

        实测样本（micro_service_seclab `/sqlinjection/jpaone`）：
        补上之前规则返回 None，模型只能按"看到了 personRepository 调用"猜；
        补上之后 `extends JpaRepository` 是逐行可核对的事实。
        """
        if getattr(self, "_iidx", None) is not None:
            return self._iidx
        root = self.config_root if self.config_root != self.repo_path else self.repo_path
        idx: dict[str, tuple[str, str]] = {}
        for java in root.rglob("*.java"):
            if any(part in IGNORE_DIRS for part in java.parts):
                continue
            from core.context.java_impl_resolver import _read_cached
            text = _read_cached(java)
            if not text or "interface " not in text:
                continue
            for hm in INTERFACE_HEAD_RE.finditer(text):
                open_idx = hm.end() - 1
                close_idx = _brace_match(text, open_idx)
                if close_idx == -1:
                    continue
                head = text[hm.start():open_idx + 1]
                body = text[open_idx + 1:close_idx]
                # 按 `;` 切成员声明。注解里的字符串可能含 `;`（罕见），
                # 切成碎段只会让那一条方法查不到，不会串到别的方法上。
                for seg in body.split(";"):
                    seg = seg.strip()
                    if not seg:
                        continue
                    # **必须剥注释**。java-sec-code 的 `UserMapper.findByUserName`
                    # 上方那行 Javadoc 写着「If using ${username}, application will
                    # send a error」—— 注释里出现 `${}`，规则读到就判成
                    # MyBatis 字符串替换 → 把 `#{username}` 安全样本判成注入
                    # （实测这一条让 java-sec-code 从 1.000 掉到 0.971）。
                    # 与 memory 第 10 条同型：不许模型被误导的东西，规则也不许读到。
                    seg = strip_java_comments(seg, keep_lines=False).strip()
                    if not seg:
                        continue
                    mm = re.search(r"(\w+)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*$",
                                   seg, re.S)
                    if not mm:
                        continue
                    # Module 38：name -> **列表**。此前 setdefault 首见即占，
                    # mall 的 `getList` 被 OmsOrderDao 抢占后
                    # PmsProductCategoryService.getList 永远进不了索引，
                    # Hop 展开断链 → 整个模块静默退回（铁律 24 同构坑）。
                    # 消费点按"与入口同 Maven 模块"优先挑选。
                    idx.setdefault(mm.group(1), []).append(
                        (str(java), head + "\n" + seg + ";\n}"))
        self._iidx = idx
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
        self._mark_global_authz(root, units)
        self._mark_param_validated(root, units)
        self._mark_explicit_auth_module(root, units)
        return units

    # 仓库级全局鉴权的机器标记（Module 38，mall 形态）。铁律 4 的反面：
    # "入口体没鉴权就判漏洞"是高频陷阱 —— mall-admin 的所有 controller
    # 都没有方法级注解，但 Spring Security 的 JwtAuthenticationTokenFilter
    # 经 addFilterBefore 统一拦截认证（未登录 401）。过滤器是仓库级事实，
    # 单文件视角看不到，必须在整库切片后统一标记。判定层看到标记就不再
    # 把"无主体的形参直查"判成 True（降 None）—— 认证已由过滤器强制，
    # 是否还有水平/垂直越权留给过滤器配置级别的分析，不归 controller
    # 逐方法判定管。
    # 标记**不能**用 `// ---- ...` 形态 —— 那是 entry_body 的分隔注释，
    # 会把入口体截成空（实测 M38 首跑 body len 0）。用方括号标签。
    _GLOBAL_AUTHZ_MARK = ("// [global-authz] Spring Security 过滤器统一认证"
                          "（JwtAuthenticationTokenFilter / addFilterBefore）")

    def _mark_global_authz(self, root: Path, units: List[CodeUnit]) -> None:
        """仓库级统一鉴权检测（机器标记，检测失败静默跳过）。

        两种真实形态（M63 My-Blog 淬火补第二种）：
          ① Spring Security 过滤器：addFilterBefore + *Filter 类
             → 认证由过滤器统一强制，全部入口打标记；
          ② Spring MVC 拦截器前缀覆盖：WebMvcConfigurer 的
             `addInterceptor(x).addPathPatterns("/admin/**")`
             → 仅给**路由路径落在前缀下**的入口打标记
             （`/admin/**` 只保护 /admin 前缀，公开页不打）。
        """
        try:
            for java in root.rglob("*.java"):
                try:
                    text = java.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if ("addFilterBefore" in text
                        and "JwtAuthenticationTokenFilter" in text):
                    for u in units:
                        src = u.source_code or ""
                        if src and self._GLOBAL_AUTHZ_MARK not in src:
                            u.source_code = self._GLOBAL_AUTHZ_MARK + "\n" + src
                    return
            # ② 前缀级统一保护（M63 MvcConfigurer + M64 Shiro 过滤链）：
            #    · addPathPatterns("/admin/**")（Spring MVC 拦截器）
            #    · filterChainDefinitionMap.put("/admin/**", "authc")
            #      （Shiro 过滤链 —— 非 anon 的过滤器 = 认证/授权强制）
            #    路由路径落在保护前缀下的入口打标记；`/**` 全覆盖。
            prefixes: list[str] = []
            for java in root.rglob("*.java"):
                try:
                    text = java.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "addInterceptors" in text:
                    prefixes += re.findall(
                        r'addPathPatterns\(\s*"(/\w+)/\*\*\s*"\s*\)', text)
                for fm in re.finditer(
                        r'filterChainDefinitionMap\.put\(\s*"([^"]+)"\s*,'
                        r'\s*"([^"]*)"\s*\)', text):
                    fpath, filters = fm.group(1), fm.group(2)
                    if "anon" in filters:
                        continue          # anon = 放行，不构成保护
                    if not any(k in filters for k in ("authc", "user")):
                        continue          # 无认证语义的过滤器（csrf 等）不算
                    if fpath == "/**":
                        prefixes.append("/**")
                    elif fpath.endswith("/**"):
                        m2 = re.match(r"^(/\w+)/\*\*$", fpath)
                        if m2:
                            prefixes.append(m2.group(1))
            if not prefixes:
                return
            full = "/**" in prefixes
            for u in units:
                rp = u.route_path or ""
                if not full and not any(
                        rp == p or rp.startswith(p + "/") for p in prefixes):
                    continue
                src = u.source_code or ""
                if src and self._GLOBAL_AUTHZ_MARK not in src:
                    u.source_code = self._GLOBAL_AUTHZ_MARK + "\n" + src
        except Exception:
            pass

    # 框架自带的非校验注解 —— 出现在形参上不构成"白名单校验"证据
    _NON_VALIDATING_ANNOT = {
        "RequestParam", "PathVariable", "RequestBody", "RequestHeader",
        "ModelAttribute", "LoginUser", "Valid", "Validated", "NotNull",
        "NotEmpty", "NotBlank", "Size", "Min", "Max", "Email", "Deprecated",
    }

    def _mark_param_validated(self, root: Path, units: List[CodeUnit]) -> None:
        """Bean Validation 白名单注解标记（M64，litemall 淬火）。

        仓库里定义了 `@Constraint(validatedBy = ...)` 且带 `accepts()` 白
        名单字面量（或 @Pattern(regexp="...")）的自定义注解（litemall 的
        `@Sort(accepts = {"add_time","id"})` / `@Order({"desc","asc"})`），
        绑定在入口形参上 + 类级 @Validated —— 框架在参数解析阶段就强制
        白名单，非法值 400，根本进不了方法体。这是**机制级防护事实**。

        给入口切片头打 `// [param-validated] sort, order` 标记，规则层
        （sqli C2b MBG Example 出口）据此豁免这些形参的注入面。
        """
        try:
            whitelist_annot: set[str] = set()
            for java in root.rglob("*.java"):
                try:
                    text = java.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for m in re.finditer(r"@interface\s+([A-Za-z_]\w*)", text):
                    name = m.group(1)
                    # @Constraint 元注解出现在 @interface 声明**之前**
                    seg = text[max(0, m.start() - 400):m.start() + 1200]
                    if "@Constraint" not in seg:
                        continue
                    if re.search(r"accepts\s*\(\s*\)\s*default\s*\{[^}]*\"",
                                 seg) or re.search(r"@Pattern\([^)]*regexp",
                                                   seg):
                        whitelist_annot.add(name)
            if not whitelist_annot:
                return
            for u in units:
                body = u.own_body or ""
                # 入口签名：own_body 开头到方法体的第一个 `{` 前的括号段
                pm = re.search(r"\bpublic\s+[^({]*\(", body)
                if not pm:
                    continue
                depth = 1
                j = pm.end()
                while j < len(body) and depth:
                    if body[j] == "(":
                        depth += 1
                    elif body[j] == ")":
                        depth -= 1
                    j += 1
                sig = body[pm.end():j - 1]
                # 括号感知切分实参段（注解实参里可能有逗号）
                parts: list[str] = []
                buf = []
                d = 0
                for ch in sig:
                    if ch in "({[":
                        d += 1
                    elif ch in ")}]":
                        d -= 1
                    if ch == "," and d == 0:
                        parts.append("".join(buf))
                        buf = []
                    else:
                        buf.append(ch)
                parts.append("".join(buf))
                validated: list[str] = []
                for part in parts:
                    annots = re.findall(r"@([A-Za-z_]\w*)", part)
                    if not any(a in whitelist_annot for a in annots):
                        continue
                    vm = re.search(
                        r"(?:String|Integer|Long|int)\s+([A-Za-z_]\w*)\s*$",
                        part.strip())
                    if vm:
                        validated.append(vm.group(1))
                if not validated:
                    continue
                src = u.source_code or ""
                if src:
                    u.source_code = (f"// [param-validated] "
                                     f"{', '.join(validated)}\n" + src)
        except Exception:
            pass

    def _mark_explicit_auth_module(self, root: Path,
                                   units: List[CodeUnit]) -> None:
        """显式 token 鉴权模块标记（M64 litemall 淬火）。

        模块（同目录）里 ≥3 个入口带「形参主体注解」段（@LoginUser 一类
        自定义 resolver 把 token 解析为主体形参）且目录内没有任何
        @RequiresPermissions —— 该模块采用**显式声明主体**的鉴权模型：
        声明了主体的路由由主体比对保护，未声明的就是匿名面（设计意图，
        如 C 端商品/品牌/专题浏览）。形参直查在这种模块上不构成"缺鉴权"
        的结论 —— authz 判定看到标记后退 None（匿名面 ≠ 越权面）。
        """
        try:
            by_dir: dict = {}
            for u in units:
                if "形参主体注解" not in (u.source_code or ""):
                    continue
                by_dir.setdefault(str(Path(u.file_path).parent), []).append(u)
            if not by_dir:
                return
            annotated_dirs = {d for d, us in by_dir.items() if len(us) >= 3}
            if not annotated_dirs:
                return
            for u in units:
                d = str(Path(u.file_path).parent)
                if d not in annotated_dirs:
                    continue
                src = u.source_code or ""
                if not src or "[explicit-auth-module]" in src:
                    continue
                if "@RequiresPermissions" in src:
                    continue          # 该入口自己声明了权限 → 非匿名面
                u.source_code = "[explicit-auth-module]\n" + src
        except Exception:
            pass

    def _attach_chains(self, units: List[CodeUnit]) -> None:
        """为每个入口补「跨路由串接证据」：本方法写进介质的键，被谁读走了。

        必须放在整库切片**之后**做，不能放进 `_slice_file` —— 存储型漏洞的
        读取点常在另一个文件里，单文件视角看不到。

        证据只贴在**写入方**上。理由是判定语义：写入方是"输入的来源入口"，
        读取方本身没有外部参数，单看它无从谈起污点；而写入方缺的恰恰是
        "我写出去的值最终会原样出现在别处的响应里"这个事实。

        db 介质以前是例外（写读两侧都贴，方向交给判定层），现在不再是：
        `build_chains` 按方法名动词锁定了「写内容 → 读内容」这一个方向，
        所以「写入方」是确定的一侧。只读路由不会再被贴上串接段 ——
        那是 newbee-mall 切片 26% 噪声的来源。

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
        #
        # 取**紧邻类声明之前的那一个**，不是文件里第一个。一个 .java 里两个类
        # 的情况真实存在（controller 里塞内部类 / 同文件放个 DTO），取第一个会把
        # 前一个类的 `@RequestMapping("/admin")` 扣到后一个类头上 —— 于是
        # 一个前台路由被算成 `/admin/...`，鉴权判定直接翻向 "受全局拦截器保护"。
        class_prefix = ""
        class_prefixes: list[str] = []
        head = text[:cls_m.start()]
        cp = None
        for _cand in SPRING_ROUTE_RE.finditer(head):
            cp = _cand
        if cp:
            # 数组形式 `@RequestMapping({"/v1/api", "/api"})` 的**每一个**字面量
            # 都是一条真实别名路径。路径本身取第一个（route_path 只能存一个），
            # 但"这条路由受不受全局拦截器保护"必须对**所有**别名取交集 ——
            # 攻击者只会走没有被拦的那一个。
            class_prefixes = self._all_string_literals(cp.group(2))
            class_prefix = class_prefixes[0] if class_prefixes else ""
        elif JAXRS_PATH_RE.search(head):
            class_prefix = JAXRS_PATH_RE.search(head).group(1)
            class_prefixes = [class_prefix]

        # 收集本文件所有方法：[(name, start, end, source, annotations)]
        #
        # 这里**不能**用 `dict[name]`：RESTful 控制器里同名重载是常态，
        # `ShoppingCartController` 的 `PUT /shop-cart` 与 `DELETE /shop-cart/{id}`
        # 都叫 `updateNewBeeMallShoppingCartItem`。按名字去重会让后一条入口
        # 静默消失 —— 不报错、不进日志、指标上看不出来，只有人工数入口才会发现。
        # 全仓实测这样丢掉 5 条（newbee 3 个文件 / HJS 的 SSTI 与 MyBatis 各 1）。
        #
        # 唯一性由 unit_name 的 `#N` 后缀保证（见下方 occur 计数）：裸名留给
        # 第一个（源码顺序），后续重载依次 `#2`、`#3`。这样既让每个方法独立
        # 成单元（跨路由串接、按名索引都不会串味），又不改任何"唯一定义"的
        # 入口名 —— 五个靶场的真值表都按 `类.方法` 硬编码，改名等于全盘失配。
        methods: list[tuple[str, int, int, str, list[str]]] = []
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
            methods.append((name, start_line, end_line,
                            text[decl_idx:close_idx + 1], anns))

        if not methods:
            return []

        # 源码顺序：既让输出稳定（原来按方法体长度倒序，纯属排序副作用），
        # 也让"第一个同名方法"有确定含义 —— 它就是拿到裸 unit_name 的那个。
        methods.sort(key=lambda t: (t[1], t[2]))

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
        #
        # 按名字判断（而非逐个重载）：只要某个名字有一条是路由，同名的其他重载
        # 也不当辅助方法 —— 保守方向，宁可少拼不少拼。
        route_methods: set[str] = set()
        for _n, _s, _e, _src, _anns in methods:
            if _n in SERVLET_METHODS and wl:
                route_methods.add(_n)
                continue
            if any(SPRING_ROUTE_RE.match(a) for a in _anns):
                route_methods.add(_n)
                continue
            if any(JAXRS_ROUTE_RE.match(a) for a in _anns):
                route_methods.add(_n)
            elif any(a.startswith("@Path") for a in _anns):
                route_methods.add(_n)

        # 辅助方法 = 既非 Servlet 动词、也非路由方法。
        # 注意不能用 startswith("do") 判断：
        # OWASP Benchmark 的清洗辅助方法就叫 doSomething(request, param)。
        helper_parts: list[str] = []
        _seen_helper: set[str] = set()
        for _n, _s, _e, _src, _a in methods:
            if _n in SERVLET_METHODS or _n in route_methods:
                continue
            if _src in _seen_helper:      # 同名重载若方法体逐字相同，只贴一次
                continue
            _seen_helper.add(_src)
            helper_parts.append(_src)
        helper_src = "\n\n".join(helper_parts)

        # 同名重载的出现序号：1 → 裸名，2/3… → `#N` 后缀
        occur: dict[str, int] = {}

        for name, start, end, src, anns in methods:
            occur[name] = occur.get(name, 0) + 1
            unit_name = (f"{cls_name}.{name}" if occur[name] == 1
                         else f"{cls_name}.{name}#{occur[name]}")
            decorators: List[str] = []
            route_path = ""
            subs: list[str] = []          # 方法级映射的别名后缀

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
                _subs = self._all_string_literals(m.group(2))
                if not _subs:
                    _subs = [""]
                subs = subs or _subs          # 以第一处映射注解为准
                sub = _subs[0]
                route_path = route_path or (class_prefix.rstrip("/") + "/" + sub.lstrip("/")).rstrip("/")

            # JAX-RS：@Path + @GET/@POST（方法级注解）
            jax_verb = next((a[1:].split("(")[0] for a in anns
                             if JAXRS_ROUTE_RE.match(a)), None)
            jax_path = next((a for a in anns if a.startswith("@Path")), None)
            if jax_verb and (jax_path or class_prefix):
                decorators.append(jax_path or f"@{jax_verb}")
                if jax_path:
                    sub = self._first_string_literal(jax_path)
                    subs = subs or [sub]
                    route_path = class_prefix.rstrip("/") + "/" + sub.lstrip("/")

            if not decorators:
                continue

            # 这条单元在 HTTP 上真正可达的**全部**路径（类级别名 × 方法级别名）。
            # 只有一条时就是 route_path 本身，行为与从前一致。
            #
            # Servlet 分支走不到任何 Spring/JAX-RS 映射，`subs`/前缀都是空串，
            # 拼出来是一个空字符串 —— 必须回落到 `route_path`（@WebServlet 的
            # 路径），否则 @WebFilter 那类证据会被静默丢掉。
            prefixes = class_prefixes or [class_prefix]
            route_aliases = [a for a in dict.fromkeys(
                (p.rstrip("/") + "/" + s.lstrip("/")).rstrip("/")
                for p in prefixes for s in (subs or [""])) if a]
            if not route_aliases and route_path:
                route_aliases = [route_path]

            # 完整路由写进切片的**第一行**：判定层（authz / 装配）和模型都需要
            # "这条路由到底叫什么"，而方法级注解只给出后缀 `/list`。
            # 放在最前面而不是塞进证据段，是因为 `entry_body()` 会剥掉注释、
            # `_impl_segment()` 从 `// ----` 起截 —— 两个消费方都不受影响，
            # 但 `_strip_comments` 之后仍留在正文里的**方法签名**不受污染。
            if route_path:
                source = f"// Full-Route: {route_path}\n"
                if len(route_aliases) > 1:
                    source += "// Alias-Route: " + ", ".join(route_aliases) + "\n"
            else:
                source = ""

            # 入口方法 + 同文件私有辅助方法（污点清洗常发生在辅助方法里）
            source += src if not helper_src else f"{src}\n\n// ---- 同文件辅助方法 ----\n{helper_src}"
            # 形参主体注解：主体在签名上而不在方法体里时，判定层唯一的线索。
            # 放在辅助方法段之后、配置块之前，`entry_body()` 到第一个 `// ----`
            # 就截断，方法体不受影响。
            _subj = self._subject_resolver().describe(src)
            if _subj:
                source += "\n" + _subj
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
                w = self._wiring_resolver().describe_aliases(route_aliases or [route_path])
                if w:
                    source += "\n" + w
            # 依赖组件版本：只列该仓库真有的敏感组件（其余仓库一块都不多写）。
            # 放在最后，`entry_body()` 早在第一个 `// ----` 处就截断了。
            dep = self._dep_resolver().describe()
            if dep:
                source += "\n" + dep

            units.append(CodeUnit(
                file_path=str(path),
                language=self.language,
                unit_name=unit_name,
                start_line=start,
                end_line=end,
                decorators_or_modifiers=decorators,
                called_symbols=self._called_symbols(src),
                source_code=source,
                own_body=src,
                route_path=route_path,
            ))
        return units

    @staticmethod
    def _first_string_literal(args: str) -> str:
        m = re.search(r"\"([^\"]*)\"", args)
        return m.group(1) if m else ""

    @staticmethod
    def _all_string_literals(args: str) -> List[str]:
        """注解参数里**路径取值**的全部字面量（数组形式 `{"/a", "/b"}`）。

        只取第一个是安全的，取不到才是错的：
        `@RequestMapping({"/v1/api", "/api"})` 的两个路径都能被访问到，
        受保护与否必须看"全都被拦"而不是"第一个被拦"。

        但**不能**把参数里所有引号串都当成路径：`@GetMapping(value = "/x",
        produces = "application/json")` 的第二个字符串是媒体类型，
        当成别名会造出 `/x/application/json` 这种不存在的路由。
        所以先定位 `value=` / `path=` 的取值段，再截到顶层逗号为止。
        """
        m = re.search(r"\b(?:value|path)\s*=\s*", args)
        seg = args[m.end():] if m else args
        depth, end = 0, len(seg)
        for i, c in enumerate(seg):
            if c in "{[(":
                depth += 1
            elif c in "}])":
                if depth == 0:
                    end = i
                    break
                depth -= 1
            elif c == "," and depth == 0:
                end = i
                break
        return [s for s in re.findall(r"\"([^\"]*)\"", seg[:end]) if s]

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
