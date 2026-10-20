"""框架装配解析：从 URL 路由反查"哪些 Filter / Interceptor / Bean 会作用于它"。

**为什么需要这一层**

java-sec-code 的 `/cors/sec/webMvcConfigurer` 长这样：

    @GetMapping("/sec/webMvcConfigurer")
    public CsrfToken getCsrfToken_01(CsrfToken token) { return token; }

方法体里一行 CORS 代码都没有，防护在 `CorsConfig.java` 里。
`/sec/originFilter` 更远 —— 防护在 `OriginFilter.doFilter()`，靠
`@WebFilter(urlPatterns = "/cors/sec/originFilter")` 挂上去的。

切片器做的是"方法 → 它调用了什么"，永远看不到这条反向路径。
结果是这类样本既没有证据也没有结论，模型只能盲猜 —— 8 条 CORS 里 7 条抖动，
主要原因在这里，不在模型。

**本模块做的三件事**

1. 收集 Filter：`@WebFilter(urlPatterns=...)`、`FilterRegistrationBean`
   （`addUrlPatterns` / `setUrlPatterns`）、以及 `OncePerRequestFilter` 子类
2. 收集 Interceptor：`addInterceptors` 的 `addPathPatterns`
3. 为每个入口 URL 算出真正会作用于它的全局组件，取回方法体作为证据

**不做什么**（避免变成半成品框架实现）

- 不解析 Spring Security 的 `http.cors()` / `antMatchers` 规则链
  （DSL 链式调用的语义解析成本极高，且 Spring 版本差异大）
- 不解析 `@CrossOrigin` 注解的取值（注解直接写在入口方法上，切片里本来就有）

对于解析不了的，`describe()` 会明确写出"未能解析"，而不是假装没有防护 ——
**沉默和"确认无防护"是两回事**，前者不该被判成漏洞。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from core.text_utils import strip_java_comments

# 只扫这些目录，避免把 target/ 里的编译产物和测试代码带进来
SKIP_DIR_PARTS = {".git", "target", "build", "node_modules", "test", "tests"}


@dataclass
class Wiring:
    kind: str                    # filter | interceptor
    name: str                    # 简单类名
    url_patterns: list[str]      # 生效路径
    body: str = ""               # 方法体或配置片段（作为证据注入切片）
    source: str = ""             # 文件相对路径，便于人工核对
    note: str = ""
    # 前缀级排除路径：`addPathPatterns("/admin/**").excludePathPatterns("/admin/login")`。
    #
    # 不记这一项会把"被排除的路由"也算成受保护 —— newbee-mall 的
    # `/admin/login`、`/admin/dist/**`、`/admin/plugins/**` 全在 exclude 里，
    # 报告却写着"该路由受 /admin/** 拦截器保护"，方向正好相反。
    # 对 authz 是致命错误：一条**不受鉴权保护**的后台路由会被当成受保护而退回。
    exclude_patterns: list[str] = field(default_factory=list)


@dataclass
class WiringReport:
    applied: list[Wiring] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)   # 见到但解析不了的全局装配

    def is_empty(self) -> bool:
        return not self.applied and not self.unparsed


WEBFILTER_RE = re.compile(r"@WebFilter\s*\(([^)]*)\)", re.S)
URLPATTERNS_RE = re.compile(r"""urlPatterns\s*=\s*(\{[^}]*\}|"[^"]*")""", re.S)
CLASS_DECL_RE = re.compile(
    r"(?:public\s+|final\s+|abstract\s+)*class\s+(\w+)[^{]*\{(.*)", re.S)
# FilterRegistrationBean 注册片段
REG_BEAN_RE = re.compile(
    r"new\s+FilterRegistrationBean\s*(?:<[^>]*>)?\s*\(([^)]*)\)(.*?)(?:return\s+\w+\s*;|\)\s*;)",
    re.S)
ADD_PATTERNS_RE = re.compile(r"addUrlPatterns|setUrlPatterns")
# Interceptor 注册
INTERCEPTOR_RE = re.compile(r"registry\s*\.\s*addInterceptor\s*\(([^)]*)\)(.*?);", re.S)
PATH_PATTERNS_RE = re.compile(r"addPathPatterns\s*\(([^)]*)\)", re.S)
# 前缀级排除：`addPathPatterns("/admin/**").excludePathPatterns("/admin/login", ...)`
EXCLUDE_PATTERNS_RE = re.compile(r"excludePathPatterns\s*\(([^)]*)\)", re.S)


def _split_patterns(raw: str) -> list[str]:
    """`{"/a", "/b"}` 或 `"/a"` → ["/a", "/b"]。"""
    return re.findall(r'"([^"]+)"', raw)


def _strip_comments(text: str) -> str:
    """去掉 `//` 行注释与 `/* */` 块注释，保留换行以维持行号。

    这一步不能省。java-sec-code 的 `CorsConfig2.java` 是**整文件被注释掉的死配置**
    （作者保留的历史写法），不剥注释就会把 `registerCorsConfiguration` 当成生效，
    把一条已废弃的 CORS 白名单注入切片 —— 和 MyBatis XML 那次
    "注释掉的旧版本被当成当前版本"是同一类错误。
    注释保留换行是为了让后续 _method_body 的偏移仍然对得上。

    特别注意：行注释替换成空串（而非整行删除）。`//` 注释不吞掉换行，
    如果整行删掉，后面紧跟的链式调用会被"粘"到上一行末尾的分号之后，
    看起来像已经结束 —— CustomCorsConfig 里就是这样：

        registry.addMapping("/cors/sec/webMvcConfigurer") // 注释
                //.allowedOrigins(allowOrigins)
                .allowedMethods("GET", "POST")
                .allowCredentials(true);

    如果 `//.allowedOrigins(...)` 整行消失，`.allowedMethods(...)` 会贴到
    `addMapping(...)` 那一行，从此与真正的链尾脱节。
    """
    text = _strip_java_comments(text, keep_lines=True)
    return text


_JAVA_COMMENT_RE = re.compile(
    r'"(?:\\.|[^"\\])*"'        # 字符串字面量整体跳过，避免把 "//" 当注释
    r"|'(?:\\.|[^'\\])*'"       # 字符字面量
    r"|//[^\n]*"                # 行注释
    r"|/\*.*?\*/",              # 块注释
    re.S,
)


def _strip_java_comments(text: str, keep_lines: bool = True) -> str:
    """单遍词法剥离 Java 注释。实现已移到 `core.text_utils`，规则层共用同一份。

    两处共用一份很重要：装配分析和规则判定都靠"注释里的代码不算数"这条，
    各自维护一份迟早会漂移 —— 一边修好了 `// /**` 的坑，另一边不知道。
    """
    return strip_java_comments(text, keep_lines)


def _ant_match(pattern: str, url: str) -> bool:
    """极小 ant 匹配：支持 `*`（单段）、`**`（任意段）、精确串。

    只用于"这个 Filter 会不会作用于该 URL"，宁可多匹配也不少匹配 ——
    多匹配最坏是注入了不相关的证据（模型能自己判断），
    少匹配则会静默漏掉真正的防护。
    """
    if pattern in ("/*", "/**", "*", "**"):
        return True
    if pattern == url:
        return True
    if "*" not in pattern:
        return False
    regex = re.escape(pattern).replace(r"\*\*", "\x00").replace(r"\*", "[^/]*")
    regex = regex.replace("\x00", ".*")
    return re.fullmatch(regex, url) is not None


def _chain_until_semicolon(text: str, start: int, limit: int = 800) -> str:
    """从 start 起截取链式调用，直到分号为止。

    只接受"紧接着"的链。一段空白算不算"链还连着"，看两侧：
      - 下一个非空白字符是 `.` `,` `;` → 继续
      - **上一个非空白字符是 `,`** → 继续（参数列表里的下一个值，
        如 `.allowedMethods("GET", "POST")` 中逗号后的空格）
    其余情况视为链条已断，就地停止 —— 否则会跨过几十行空白一路吃到
    下一个类的花括号里（CustomCorsConfig 的真实踩坑：链尾后面紧跟内部类声明）。
    """
    out: list[str] = []
    depth, i, n = 0, start, min(len(text), start + limit)
    while i < n:
        c = text[i]
        # 注意顺序：先记字符，再按新层级判断，避免 ")" 让 depth 变成负数
        # 后 `depth <= 0` 恒真、把参数内的空白误判成链结束。
        if c == "(":
            depth += 1
        if c in " \t\r\n":
            j = i
            while j < n and text[j] in " \t\r\n":
                j += 1
            prev = next((ch for ch in reversed(out) if ch not in " \t"), "")
            nxt = text[j] if j < n else ""
            if depth <= 0 and nxt not in ".,;" and prev != ",":
                return re.sub(r"\s+", " ", "".join(out)).rstrip()
            out.append(" ")
            i = j
            continue
        out.append(c)
        if c == ")":
            depth -= 1
        if c == ";" and depth <= 0:
            return re.sub(r"\s+", " ", "".join(out)).strip()
        i += 1
    return re.sub(r"\s+", " ", "".join(out)).strip()


def _enclosing_class(text: str, pos: int) -> str:
    """找 pos 之前最近的一个类声明名（用于给内部类里的装配起个可读名字）。"""
    names = [m.group(1) for m in re.finditer(r"\bclass\s+(\w+)", text[:pos])]
    return names[-1] if names else "CorsConfig"


def _find_class_body(text: str, classname: str, root: Path | None = None) -> str:
    """在给定文本里取某个类的类体；找不到则到仓库里按文件名搜一遍。"""
    m = re.search(rf"class\s+{re.escape(classname)}\b[^{{]*\{{", text)
    if m:
        return _method_body(text, m.end() - 1)
    if root is None:
        return ""
    for p in Path(root).rglob(f"{classname}.java"):
        if any(part in SKIP_DIR_PARTS for part in p.parts):
            continue
        try:
            body = _strip_java_comments(p.read_text(encoding="utf-8", errors="replace"),
                                        keep_lines=True)
        except OSError:
            continue
        m = re.search(rf"class\s+{re.escape(classname)}\b[^{{]*\{{", body)
        if m:
            return _method_body(body, m.end() - 1)
    return ""


def _cors_mapping_for(text: str, pos: int) -> list[str]:
    """setCorsProcessor 所在的 Mapping 配置类，其 addMapping 路径即其作用域。"""
    pats = re.findall(r"addMapping\s*\(\s*\"([^\"]+)\"", text)
    return pats or ["/*"]


def _config_builder_snippet(text: str, reg_pos: int, limit: int = 2000) -> str:
    """取构造 CorsConfiguration 的那段方法体作为 CORS 配置证据。

    优先选择"包含 new CorsConfiguration() 且包含 registerCorsConfiguration"的
    **同一个方法**；找不到时退化为 register 所在方法体。这样拿到的才是
    `setAllowCredentials(true)` / `addAllowedOrigin("...")` 这类带取值的事实，
    而不是 `http.cors()` 这种不含任何取值的链式 DSL。
    """
    # 收集所有方法起始位置（按花括号配对切出候选方法体）
    starts = [m.start() for m in re.finditer(
        r"(?:public|private|protected|static|final|\s)+\s[\w<>\[\],\s]+\s+\w+\s*\([^;{]*\)\s*\{",
        text)]
    best = ""
    for s in starts:
        if s > reg_pos:
            break
        body = _method_body(text, text.find("{", s), limit=limit)
        end = text.find("{", s) + len(body)
        if s <= reg_pos <= end or reg_pos < end + 200:
            if "new CorsConfiguration" in body and "registerCorsConfiguration" in body:
                return body
            if "new CorsConfiguration" in body and not best:
                best = body
    if best:
        return best
    # 兜底：直接截 register 调用附近一段
    lo = max(0, reg_pos - 900)
    return text[lo: reg_pos + 200]


def _method_body(text: str, start: int, limit: int = 3000) -> str:
    """从 start 起截一段（到花括号配平或 limit）。"""
    depth, i = 0, start
    n = min(len(text), start + limit)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start: i + 1]
        i += 1
    return text[start:n]


class FrameworkWiringResolver:
    """扫描仓库，建立「URL → 全局 Filter / Interceptor」的映射。"""

    def __init__(self, repo_root: str | Path, source_root: str | Path | None = None):
        self.repo_root = Path(repo_root)
        self.source_root = Path(source_root) if source_root else self.repo_root
        self._wiring: list[Wiring] | None = None
        self._unparsed: list[str] | None = None

    # ---------- 索引 ----------

    def _iter_java(self):
        for p in self.source_root.rglob("*.java"):
            if any(part in SKIP_DIR_PARTS for part in p.parts):
                continue
            yield p

    def _build(self) -> None:
        wirings: list[Wiring] = []
        unparsed: list[str] = []
        for p in self._iter_java():
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            text = _strip_comments(raw)
            if not text.strip():
                continue        # 整个文件都是注释（历史遗留），跳过
            rel = str(p.relative_to(self.repo_root)) if self.repo_root in p.parents else p.name

            # --- @WebFilter ---
            for m in WEBFILTER_RE.finditer(text):
                args = m.group(1)
                pats = []
                pm = URLPATTERNS_RE.search(args)
                if pm:
                    pats = _split_patterns(pm.group(1))
                elif "urlPatterns" not in args and "value" not in args:
                    pats = ["/*"]      # @WebFilter 不带 urlPatterns 时默认拦全部
                cls = CLASS_DECL_RE.search(text, m.end())
                if not cls:
                    continue
                name, body = cls.group(1), cls.group(2)
                do_filter = re.search(r"doFilter\s*\(", body)
                snippet = ""
                if do_filter:
                    snippet = _method_body(body, body.find("{", do_filter.start()))
                wirings.append(Wiring(kind="filter", name=name, url_patterns=pats,
                                      body=snippet, source=rel))

            # --- FilterRegistrationBean ---
            for m in REG_BEAN_RE.finditer(text):
                seg = m.group(0)
                pats: list[str] = []
                if ADD_PATTERNS_RE.search(seg):
                    for pm in re.finditer(r'(?:addUrlPatterns|setUrlPatterns)\s*\(([^)]*)\)', seg):
                        pats += _split_patterns(pm.group(1))
                fname = re.search(r"(\w+Filter)\s*\(|new\s+(\w+)\s*\(", m.group(1))
                name = next((g for g in (fname.groups() if fname else ()) if g), "FilterRegistrationBean")
                wirings.append(Wiring(kind="filter", name=name,
                                      url_patterns=pats or ["/*"],
                                      body=seg.strip(), source=rel,
                                      note="通过 FilterRegistrationBean 注册"))

            # --- Interceptor ---
            for m in INTERCEPTOR_RE.finditer(text):
                pm = PATH_PATTERNS_RE.search(m.group(2))
                pats = _split_patterns(pm.group(1)) if pm else []
                iname = re.search(r"new\s+(\w+)", m.group(1))
                ex_pats: list[str] = []
                for em in EXCLUDE_PATTERNS_RE.finditer(m.group(2)):
                    ex_pats += _split_patterns(em.group(1))
                wirings.append(Wiring(kind="interceptor",
                                      name=iname.group(1) if iname else "interceptor",
                                      url_patterns=pats or ["/**"],
                                      body=m.group(0).strip(), source=rel,
                                      exclude_patterns=ex_pats))

            # --- CorsConfigurationSource：registerCorsConfiguration 带的是
            #     明确的 ant 路径，可以精确映射到 URL，不该丢进 unparsed。
            #     证据取同一个方法体内的 new CorsConfiguration() 配置块。     ---
            for m in re.finditer(
                    r"registerCorsConfiguration\s*\(\s*\"([^\"]+)\"", text):
                path_pat = m.group(1)
                # 证据优先取**同文件里构造 CorsConfiguration 的那个方法体**，
                # 而不是 registerCorsConfiguration 所在的方法体。
                # 反例：WebSecurityConfig 里 registerCorsConfiguration 在
                # corsConfigurationSource() 内，但如果按"最近的 public/private"
                # 回退去找，会落到 configure(HttpSecurity) 上，
                # 取到的是 http.cors() 这种没有取值的 DSL —— 等于没证据。
                snippet = _config_builder_snippet(text, m.start())
                cls = CLASS_DECL_RE.search(text)
                cname = cls.group(1) if cls else "CorsConfiguration"
                wirings.append(Wiring(
                    kind="cors-config", name=cname, url_patterns=[path_pat],
                    body=snippet, source=rel,
                    note="CorsConfigurationSource 显式注册"))

            # --- WebMvcConfigurer.addCorsMappings：registry.addMapping("/path")
            #     后面跟 .allowedOrigins(...) / .allowedOriginPatterns(...) /
            #     .allowCredentials(true) 链式调用。
            #     getCsrfToken_01 就是这种写法，此前完全没被解析，
            #     切片里只剩一个全文匹配的 ReferFilter，等于没有 CORS 证据。 ---
            for m in re.finditer(r"addMapping\s*\(\s*\"([^\"]+)\"", text):
                path_pat = m.group(1)
                chain = _chain_until_semicolon(text, m.end())
                wirings.append(Wiring(
                    kind="cors-mvc", name=_enclosing_class(text, m.start()),
                    url_patterns=[path_pat],
                    body=f'registry.addMapping("{path_pat}"){chain}',
                    source=rel,
                    note="WebMvcConfigurer.addCorsMappings"))

            # --- 自定义 CorsProcessor：setCorsProcessor(new Xxx())。
            #     这是 CORS 白名单的第五种藏法 —— 既不在入口里、也不在
            #     allowedOrigins 里，而是重写了 CorsProcessor.checkOrigin()。
            #     CustomCorsConfig 就是这种：allowedOrigins(...) 整行被注释，
            #     真正生效的是 CustomCorsProcessor 里的 SecurityUtil.checkURL。
            #     不解析它，`/cors/sec/webMvcConfigurer` 会被误判成"不限 Origin"。---
            for m in re.finditer(r"setCorsProcessor\s*\(\s*new\s+(\w+)", text):
                pname = m.group(1)
                pbody = _find_class_body(text, pname, self.source_root)
                if pbody:
                    wirings.append(Wiring(
                        kind="cors-processor", name=pname,
                        url_patterns=_cors_mapping_for(text, m.start()),
                        body=pbody, source=rel,
                        note="自定义 CorsProcessor.checkOrigin"))

            # --- 见到但解析不了的全局装配：显式记录，别假装没有 ---
            if re.search(r"http\s*\.\s*cors\s*\(\s*\)", text):
                unparsed.append(f"{rel}: Spring Security `http.cors()`（CORS 配置在别处定义）")

        self._wiring = wirings
        self._unparsed = unparsed

    @property
    def wiring(self) -> list[Wiring]:
        if self._wiring is None:
            self._build()
        return self._wiring or []

    @property
    def unparsed(self) -> list[str]:
        if self._unparsed is None:
            self._build()
        return self._unparsed or []

    # ---------- 查询 ----------

    def for_url(self, url: str) -> WiringReport:
        """返回作用于该 URL 的全部全局组件。

        `excludePathPatterns` 必须参与判断：Spring 的拦截器语义是
        "先匹配 addPathPatterns，再被 excludePathPatterns 减掉"。
        少了减法，`/admin/login` 会被报告成"受 /admin/** 拦截器保护" ——
        而它恰恰是登录入口，本来就不该被拦。这条错法会让鉴权判定把
        **无保护的路由当成受保护**，方向性错误。
        """
        rep = WiringReport()
        for w in self.wiring:
            if not any(_ant_match(p, url) for p in w.url_patterns):
                continue
            if any(_ant_match(p, url) for p in w.exclude_patterns):
                continue
            rep.applied.append(w)
        rep.unparsed = list(self.unparsed)
        return rep

    def describe(self, url: str, max_body: int = 1200) -> str:
        """渲染成可直接拼进切片的证据块。"""
        rep = self.for_url(url)
        if rep.is_empty():
            return ""
        lines = ["", "// ---- 框架装配证据：以下全局组件会作用于本路由 ----"]
        for w in rep.applied:
            ex = f"  exclude={w.exclude_patterns}" if w.exclude_patterns else ""
            lines.append(f"// [{w.kind}] {w.name}  urlPatterns={w.url_patterns}{ex}"
                         f"  来源 {w.source}{('  ' + w.note) if w.note else ''}")
            for ln in w.body.strip().splitlines()[:40]:
                lines.append(f"//   {ln.strip()}")
            if len(w.body) > max_body:
                lines.append("//   ...（截断）")
        # 只提与本路由**路径相近**的未解析装配。把全仓库的 registerCorsConfiguration
        # 都塞进来的后果是每个 CORS 切片都会看到别的路由的路径，模型会误以为
        # 那些也是当前路由的防护 —— 这属于证据污染，比信息不足更糟。
        rel = [u for u in rep.unparsed if _mentions_path(u, url)]
        if rel:
            lines.append("// [注意] 以下装配可能与本路由相关，但无法静态确定生效路径；"
                         "**不代表本路由没有防护**，请结合下方证据判断：")
            for u in rel:
                lines.append(f"//   - {u}")
        return "\n".join(lines) + "\n"


def _mentions_path(desc: str, url: str) -> bool:
    """未解析条目里提到的路径是否与当前 url 有公共前缀（至少两段）。"""
    for p in re.findall(r'"([^"]+)"', desc):
        a, b = p.strip("/").split("/"), url.strip("/").split("/")
        shared = 0
        for x, y in zip(a, b):
            if x != y:
                break
            shared += 1
        if shared >= 2:
            return True
    return False
