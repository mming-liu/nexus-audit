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
    """
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


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
                wirings.append(Wiring(kind="interceptor",
                                      name=iname.group(1) if iname else "interceptor",
                                      url_patterns=pats or ["/**"],
                                      body=m.group(0).strip(), source=rel))

            # --- CorsConfigurationSource：registerCorsConfiguration 带的是
            #     明确的 ant 路径，可以精确映射到 URL，不该丢进 unparsed。
            #     证据取同一个方法体内的 new CorsConfiguration() 配置块。     ---
            for m in re.finditer(
                    r"registerCorsConfiguration\s*\(\s*\"([^\"]+)\"", text):
                path_pat = m.group(1)
                # 向后找这个 register 调用所属的方法体
                mstart = text.rfind("private", 0, m.start())
                mstart = max(mstart, text.rfind("public", 0, m.start()))
                mstart = max(mstart, text.rfind("protected", 0, m.start()))
                snippet = _method_body(text, mstart) if mstart > 0 else ""
                cls = CLASS_DECL_RE.search(text)
                cname = cls.group(1) if cls else "CorsConfiguration"
                wirings.append(Wiring(
                    kind="cors-config", name=cname, url_patterns=[path_pat],
                    body=snippet[-1600:], source=rel,
                    note="CorsConfigurationSource 显式注册"))

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
        """返回作用于该 URL 的全部全局组件。"""
        rep = WiringReport()
        for w in self.wiring:
            if any(_ant_match(p, url) for p in w.url_patterns):
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
            lines.append(f"// [{w.kind}] {w.name}  urlPatterns={w.url_patterns}"
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
