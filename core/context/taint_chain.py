"""跨路由串接：把「写入点」与「读取点」分居两方法的漏洞接成一条链。

为什么需要这一层
----------------

现有的单入口分析有个结构性盲区：每个路由方法独立判定"外部输入是否可达本方法内的
汇聚点"。对**反射型**漏洞这没问题，但对**存储型 / 二阶**漏洞必然漏报 —— 因为

    写入点（store）：收外部输入 → 落到某个存储介质 → 回显的是常量
    读取点（show） ：从存储介质取出 → 写进响应体

两个方法各自看都是"干净的"：store 没写响应体，show 没有外部参数。
java-sec-code 的 `/xss/stored/store` + `/xss/stored/show` 就是标准形态：

    // store：xss 落进 Cookie，返回的是常量字符串
    Cookie cookie = new Cookie("xss", xss);
    response.addCookie(cookie);
    return "Set param into cookie";

    // show：从 Cookie 读出，原样写进响应体
    public String show(@CookieValue("xss") String xss) { return xss; }

Truth 说 `/stored/store` 有漏洞（作者注释 "StoredXSS Step1"），而按 xss 类目的
判据（"是否把外部可控字符串写进响应体"）它确实答 No。**这不是判定器错了，
是判据的粒度不够** —— 漏洞的成立要件跨了两个方法。

设计原则
--------

沿用整个项目的原则：**能用确定性事实判定的，不交给 LLM。**

写入点和读取点之间的连接，本身就是客观事实 —— 同一个键名（Cookie 名 /
session attribute 名 / 存储方法参数）出现在一个方法的"写"和另一个方法的"读"
两侧。这个匹配不需要语义理解，正则足以判定，而且错判方向可控：
- 只连"写"+ "读"都成立的对，不做模糊推测
- 连接的证据原样带进切片，让人和模型都能复核

本模块只负责**发现连接、生成证据**。是否构成漏洞仍交给上层判定器 ——
串接本身不等于漏洞（比如 store 写了经过编码的值、show 又做了解码，就不成立）。

介质
----

按 Java Web 里最常见、且键名可静态识别的四种：

    cookie      response.addCookie(new Cookie("k", v))  →  @CookieValue("k")
    session     session.setAttribute("k", v)            →  session.getAttribute("k")
    request     request.setAttribute("k", v)            →  request.getAttribute("k")
    model       model.addAttribute("k", v)              →  ${k}（模板）/ @ModelAttribute

`/stored/store` 与 `/stored/show` 走的就是第一种（键名都是 `"xss"`）。

第五种介质：数据库持久层（`db`）
--------------------------------

上面前四种的键是**字符串字面量**（`"xss"`），因为介质本身按名字寻址。
数据库不一样：它是按**表**寻址的，而 Java 代码里表的代言人就是那个
DAO / Mapper 字段。所以 `db` 介质的"键"是**字段名**：

    @Autowired private XssMapper xssMapper;
    ...
    xssMapper.insertAll(content, ua);     →  db:"xssMapper" 写入
    xssMapper.selectAll();                →  db:"xssMapper" 读出

同一个 Controller 里两个路由共用同一个 Mapper 字段，是最常见的存储型
XSS 形态（写入路由 `insert`、列表路由 `select` 后回显）。

**为什么只认字段名，不认"方法名像 insert/select"。** 后者要求我们读懂
方法名语义，`xssService.insertOne(...)` / `xssService.page(...)` /
`xssService.listByCondition(...)` 各有各的命名习惯，靠词根枚举必然漏；
而"是不是同一个仓储对象"是**结构事实** —— 两个路由调了同一个字段，
无论它叫 insertOne 还是 addFeed，写读关系都成立。代价是同一字段上的
`deleteById` 也会被标成"写"，但那只是多一条证据，判定仍看读取点是否
把值原样回显（删除不影响这个结论）。

真正的边界在**判定层**：字段背后是不是真的落库，要看 Mapper 接口声明
或 Service 实现体。所以这里只产出证据，是否成立由上层判。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from core.models import CodeUnit


# ---------------- 介质识别 ----------------
#
# 每个介质给出 (写正则, 读正则, 说明)。键名统一放在 group("key")。
# 写：`new Cookie("xss", xss)` 里的第一个字面量 / `setAttribute("k", v)` 的第一个字面量
# 读：`@CookieValue("xss")` / `getAttribute("k")` 里的字面量

@dataclass(frozen=True)
class Medium:
    key: str
    label: str
    write_re: re.Pattern[str]
    read_re: re.Pattern[str]
    # 写/读是否共用同一个正则（db 介质写读都是"调了该字段的方法"）
    symmetric: bool = False


# 仓储字段的命名特征。`xssMapper` / `xssService` / `userDao` / `orderRepository`。
# 必须以这些词结尾，且前面还有内容（纯 `mapper` 这种太宽，容易撞上局部变量）。
_REPO_FIELD_RE = re.compile(
    r"\b([A-Za-z_]\w*(?:Mapper|Dao|DAO|Repository|Service))\s*\.\s*([A-Za-z_]\w*)\s*\(")


MEDIA: tuple[Medium, ...] = (
    Medium(
        key="cookie",
        label="Cookie",
        # new Cookie("xss", xss)  /  Cookie c = new Cookie(名, 值)
        write_re=re.compile(
            r"new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(\s*\"(?P<key>[^\"]+)\"\s*,"),
        # @CookieValue("xss")  /  @CookieValue(value = "xss")  /  getCookies 遍历里的 getName 比较
        read_re=re.compile(
            r"@CookieValue\s*\(\s*(?:value\s*=\s*)?\"(?P<key>[^\"]+)\"|"
            r"getCookie\s*\(\s*\"(?P<key2>[^\"]+)\""),
    ),
    Medium(
        key="session",
        label="Session 属性",
        write_re=re.compile(
            r"\.\s*setAttribute\s*\(\s*\"(?P<key>[^\"]+)\"\s*,"),
        read_re=re.compile(
            r"\.\s*getAttribute\s*\(\s*\"(?P<key>[^\"]+)\""),
    ),
    Medium(
        key="request",
        label="Request 属性",
        write_re=re.compile(
            r"\brequest\s*\.\s*setAttribute\s*\(\s*\"(?P<key>[^\"]+)\"\s*,"),
        read_re=re.compile(
            r"\brequest\s*\.\s*getAttribute\s*\(\s*\"(?P<key>[^\"]+)\""),
    ),
    Medium(
        key="model",
        label="Model 属性",
        write_re=re.compile(
            r"\bmodel\s*\.\s*addAttribute\s*\(\s*\"(?P<key>[^\"]+)\"\s*,"),
        read_re=re.compile(
            r"@ModelAttribute\s*\(\s*(?:value\s*=\s*)?\"(?P<key>[^\"]+)\""),
    ),
    # 数据库持久层：写读正则相同（都用"调了哪个仓储字段的方法"作为特征），
    # 真正的写/读区分在最前面已经做完 —— 见 `_db_handles`。
    # group("key") 由 `_REPO_FIELD_RE` 提供，这里只为让 MEDIA 表保持同构。
    Medium(
        key="db",
        label="数据库持久层",
        write_re=_REPO_FIELD_RE,
        read_re=_REPO_FIELD_RE,
        symmetric=True,
    ),
)


def _keys(regex: re.Pattern[str], text: str) -> set[str]:
    """取出匹配到的所有键名（兼容命名组 key / key2 两种写法）。"""
    out: set[str] = set()
    for m in regex.finditer(text):
        gd = m.groupdict()
        v = gd.get("key") or gd.get("key2")
        if v:
            out.add(v)
    return out


# ---------------- 数据库介质：按仓储字段配对 ----------------
#
# 写/读两侧都靠 `字段.方法(...)` 识别，所以"同一个字段"是唯一判据。
# 但真值里还有一类写法根本不在 Controller 里：Controller 调的是 Service，
# Service 内部才调 Mapper（JavaSecLab 的 `xssService.insertOne(...)` →
# `XssServiceImpl.insertOne` → `xssMapper.insertAll(...)`）。
#
# 只扫入口体会让这类样本"两边都没有仓储调用"，连接自然为零。所以再加一层
# **符号解析**：把入口里调用的方法名，解析到方法定义所在的文件（含同名文件
# 的类，如 `XssServiceImpl.java` / `XssMapper.java`），把那个方法体也纳入
# 扫描范围。这与切片器的 `_resolve_cross_file_helpers` 思路一致，但只用索引，
# 不往切片里塞代码 —— 串接是"发现连接"，不是"提供证据"。

# 方法定义（含 `public int insertOne(...) {` / 接口的 `R insertOne(...) ;`）
_METHOD_DEF_RE = re.compile(
    r"(?:^|[\n;{}])\s*"
    r"(?:@[A-Za-z_][\w.]*(?:\([^)]*\))?\s*)*"
    r"(?:public|private|protected|static|final|abstract|synchronized|\s)*"
    r"[\w<>\[\],.\s?]+?\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*(?:throws[^{;]*)?[{;]",
    re.M)


def _method_bodies(text: str) -> dict[str, list[str]]:
    """{方法名: [方法体…]} —— 粗解析，够用于"找同名方法实现"。

    用花括号配平取体；接口声明（以 `;` 结尾）没有体，记为空串，仍然占位
    —— 占位是为了让调用方知道"这个方法在这里有声明"，从而继续去别处找实现。
    """
    out: dict[str, list[str]] = {}
    for m in _METHOD_DEF_RE.finditer(text):
        name = m.group(1)
        if name in {"if", "for", "while", "switch", "catch", "new", "return"}:
            continue
        tail = m.group(0).rstrip()
        if tail.endswith(";"):
            out.setdefault(name, []).append("")
            continue
        open_idx = m.end() - 1
        depth, end = 1, len(text)
        for i in range(open_idx + 1, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        out.setdefault(name, []).append(text[open_idx:end + 1])
    return out


def _repo_handles(source: str) -> set[str]:
    """本段代码里被点用过的仓储字段名（`xssMapper` / `xssService` …）。"""
    return {m.group(1) for m in _REPO_FIELD_RE.finditer(source)}


def _resolve_repo_traces(body: str, repo_root, depth: int = 1) -> str:
    """把入口调用的方法解析到定义文件，返回这些方法体的拼接（供扫仓储字段）。

    为什么必须做这一步：`xssService.insertOne(payload, ua)` 这一行里
    只有 service 字段，落库发生在 `XssServiceImpl.insertOne` 里的
    `xssMapper.insertAll(...)`。不解析就完全看不到"写进了库"。

    只跟一层（depth=1）：二跳之后命中率急剧下降，而误连的成本是切片膨胀。
    """
    if depth <= 0 or repo_root is None:
        return ""
    root = Path(repo_root)
    if not root.exists():
        return ""
    called = {m.group(1) for m in re.finditer(r"\.\s*([A-Za-z_]\w*)\s*\(", body)}
    called = {c for c in called if len(c) >= 3}
    if not called:
        return ""

    # 索引：方法名 → 定义它的文件。惰性建一次，避免每个入口都全库扫。
    idx = getattr(_resolve_repo_traces, "_idx", None)
    if idx is None or idx[0] != str(root):
        by_name: dict[str, list[Path]] = {}
        for p in root.rglob("*.java"):
            if any(seg in ("test", "target", "build") for seg in p.parts):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for name in _method_bodies(text):
                by_name.setdefault(name, []).append(p)
        idx = (str(root), by_name)
        _resolve_repo_traces._idx = idx
    by_name = idx[1]

    hits: list[str] = []
    seen_files: set[Path] = set()
    for name in sorted(called):
        for p in by_name.get(name, [])[:2]:
            if p in seen_files:
                continue
            seen_files.add(p)
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for b in _method_bodies(text).get(name, []):
                if b:
                    hits.append(b)
    return "\n".join(hits)


def writes_of(source: str) -> dict[str, set[str]]:
    """{介质: {键名}} —— 本方法向哪些介质写了哪些键。"""
    return {m.key: ks for m in MEDIA if (ks := _keys(m.write_re, source))}


def reads_of(source: str) -> dict[str, set[str]]:
    """{介质: {键名}} —— 本方法从哪些介质读了哪些键。"""
    return {m.key: ks for m in MEDIA if (ks := _keys(m.read_re, source))}


def keys_of(source: str) -> dict[str, set[str]]:
    """{介质: {键名}} —— 本段代码**接触过**的所有键（不分写读）。

    db 介质用这个：同一个仓储字段上的读和写都算"接触"，方向由配对时的
    读写两侧决定，不需要在单侧区分（`symmetric` 字段）。
    """
    out = writes_of(source)
    for k, vs in reads_of(source).items():
        out.setdefault(k, set()).update(vs)
    return out


# ---------------- 串接 ----------------

@dataclass
class Link:
    """一条跨路由连接：writer 写入的键，被 reader 读出。"""
    medium: str            # cookie / session / request / model / db
    key: str
    writer: CodeUnit
    reader: CodeUnit
    # db 介质专用：写入/读取各自经过的方法链（如 `xssService.insertOne` /
    # `xssMapper.insertAll`）。空表示"入口体里直接调的仓储字段"。
    writer_via: tuple[str, ...] = ()
    reader_via: tuple[str, ...] = ()

    def describe(self) -> str:
        m = next((x for x in MEDIA if x.key == self.medium), None)
        label = m.label if m else self.medium
        w = f"（经 {', '.join(self.writer_via)}）" if self.writer_via else ""
        r = f"（经 {', '.join(self.reader_via)}）" if self.reader_via else ""
        return (f"{label} \"{self.key}\"："
                f"{self.writer.unit_name}{w} 写入 → {self.reader.unit_name}{r} 读出")


@dataclass
class ChainResult:
    """串接结果，按写入方索引，便于切片阶段直接取用。"""
    links: list[Link] = field(default_factory=list)

    def links_of_writer(self, unit_name: str) -> list[Link]:
        return [l for l in self.links if l.writer.unit_name == unit_name]

    def links_of_reader(self, unit_name: str) -> list[Link]:
        return [l for l in self.links if l.reader.unit_name == unit_name]


def build_chains(units: list[CodeUnit],
                 entries_only: dict[str, str] | None = None,
                 repo_root: str | Path | None = None) -> ChainResult:
    """在整库切片的入口集合里找「同一介质、同一键名」的写-读配对。

    只配对**不同方法**。同一方法内既写又读是自包含的，单入口分析已覆盖，
    重复标注只会让切片变长。

    重要：判定"当前方法自己写了什么"必须用**未追加辅助方法**的入口方法体。

    切片器为每个入口拼了"同文件辅助方法"整块（污点清洗常在辅助方法里），
    副作用是**同类里的其它路由方法也被当成辅助方法拼了进来**。直接拿
    `source_code` 去扫写入点，会让每个入口都"看到"同类所有方法的 Cookie
    写入，于是 store / reflect / safe / show 四个入口互相都连上了 —— 实测
    12 条串接里 9 条是这么来的假连接。

    取值优先级：`entries_only` 显式指定 > `CodeUnit.own_body` > `source_code`。
    中间这层是关键 —— 早期版本只认 `entries_only`，忘传就静默退化到污染态
    的 `source_code`，调用方完全看不出结果已经错了。默认走 `own_body`
    让"不传也对"成为默认行为。

    `repo_root` 给出后，db 介质会额外做一层方法解析：入口里调的
    `xssService.insertOne(...)` 会被追到 `XssServiceImpl` 的方法体里去看
    有没有 `xssMapper.insertAll(...)`。不给就退化为"只看入口体",
    不会报错，只是 DB 串接只能覆盖 Controller 直接调 Mapper 的写法。
    """
    res = ChainResult()
    body_of = entries_only or {}

    # 先各自建索引，避免 O(n^2) 反复扫源码
    writers: dict[tuple[str, str], list[CodeUnit]] = {}
    readers: dict[tuple[str, str], list[CodeUnit]] = {}
    # db 介质单独记"经哪条方法链接触到该字段"，用于证据里写清楚
    via_w: dict[tuple[str, str], tuple[str, ...]] = {}
    via_r: dict[tuple[str, str], tuple[str, ...]] = {}
    # 每个入口实际"接触"到的仓储字段集合。db 配对必须用它，不能靠回查
    # `own_body`：单测里构造的 CodeUnit 往往只填了 source_code。
    handles_of: dict[str, set[str]] = {}

    for u in units:
        src = body_of.get(u.unit_name) or u.own_body or u.source_code or ""
        if not src:
            continue
        for medium, keys in writes_of(src).items():
            if medium == "db":
                continue                # db 走对称配对，见下
            for k in keys:
                writers.setdefault((medium, k), []).append(u)
        for medium, keys in reads_of(src).items():
            if medium == "db":
                continue
            for k in keys:
                readers.setdefault((medium, k), []).append(u)

    for (medium, key), wlist in writers.items():
        for r in readers.get((medium, key), []):
            for w in wlist:
                if w.unit_name == r.unit_name:
                    continue          # 同方法内读写，不算跨路由
                res.links.append(Link(medium=medium, key=key, writer=w, reader=r))

    # ---- db 介质：对称配对 ----
    #
    # 同一仓储字段上的"调用"既可能是写也可能是读，单看一侧区分不了
    # （`xssMapper.add(...)` 与 `xssMapper.list()` 长得一样）。所以这里
    # 不区分方向：同一字段被两个不同路由调用，就产出一条连接，两侧都贴证据
    # —— 真正判定"谁是写入方、读取点有没有回显"是上层的事。
    db_touch: dict[tuple[str, str], list[CodeUnit]] = {}
    for u in units:
        src = body_of.get(u.unit_name) or u.own_body or u.source_code or ""
        if not src:
            continue
        direct = _repo_handles(src)
        if direct:
            handles_of[u.unit_name] = set(direct)
            for h in direct:
                db_touch.setdefault(("db", h), []).append(u)
        elif repo_root is not None:
            trace = _resolve_repo_traces(src, repo_root)
            found = _repo_handles(trace)
            if found:
                handles_of[u.unit_name] = set(found)
                # 记录方法链，便于证据里点明"经 Service 才落库"
                chain = tuple(sorted({n for n in re.findall(
                    r"\.\s*([A-Za-z_]\w*)\s*\(", src) if len(n) >= 3}))[:3]
                for h in found:
                    db_touch.setdefault(("db", h), []).append(u)
                    via_w.setdefault(("db", h, u.unit_name), chain)

    for (_medium, handle), ulist in db_touch.items():
        uniq: list[CodeUnit] = []
        for u in ulist:
            if all(u.unit_name != x.unit_name for x in uniq):
                uniq.append(u)
        for i, a in enumerate(uniq):
            for b in uniq[i + 1:]:
                # 双向各产一条：a 写 b 读 / b 写 a 读。上层按"写入方文档里
                # 有没有读写两侧都贴证据"来判，方向不确定时两侧都该看到。
                for w, r in ((a, b), (b, a)):
                    res.links.append(Link(
                        medium="db", key=handle, writer=w, reader=r,
                        writer_via=via_w.get(("db", handle, w.unit_name), ()),
                        reader_via=via_w.get(("db", handle, r.unit_name), ())))

    # 稳定排序，保证切片文本可复现（同输入必须产出同一切片，否则又引入抖动）
    res.links.sort(key=lambda l: (l.writer.unit_name, l.reader.unit_name,
                                  l.medium, l.key))
    return res


# ---------------- 证据渲染 ----------------

_MAX_READER_BODY = 1200


def render_chain_block(links: list[Link],
                       reader_bodies: str | dict[str, str] = "") -> str:
    """把串接证据渲染成切片段落。

    格式与 `// ---- 框架装配证据 ----` 保持一致，这样 `entry_body()` 的截断
    和 `_impl_segment()` 的取段逻辑都不用改 —— 新证据天然落在"入口方法体"之后。

    关键点：**必须把读取点的方法体贴出来**。只写一句"Cookie xss 被 show 读了"
    等于让模型猜 show 做了什么；贴出 `return xss;` 它才能判断是否原样回显。

    `reader_bodies` 可以给一条字符串（老用法：所有连接共用一个读取点），
    也可以给 {读取方方法名: 方法体}。**必须支持后者**：db 介质会一次连上多个
    读取点（写入方 → 列表路由、写入方 → 删除路由），只贴第一个会让判定层
    看到"读取点没回显"而判安全 —— 而真正的回显点在第二个里。
    """
    if not links:
        return ""
    lines = ["", "// ---- 跨路由串接证据 ----"]
    for l in links:
        lines.append(f"// {l.describe()}")
    if isinstance(reader_bodies, dict):
        # 按读取方去重，保持出现顺序（稳定排序已在 build_chains 里做过）
        seen: list[str] = []
        for l in links:
            if l.reader.unit_name not in seen:
                seen.append(l.reader.unit_name)
        chunks = [reader_bodies.get(n, "") for n in seen]
    else:
        chunks = [reader_bodies]
    bodies = [c.strip() for c in chunks if c and c.strip()]
    if bodies:
        # **逐块**截断再拼接，不能先拼后截。
        # 踩过：db 一次连上 6 个读取点，总长超限后尾部被切掉，而真正回显的
        # 那个读取点恰好排在后面 —— 判定层看到的是"读取点都没有回显"，
        # 于是把存储型 XSS 判成安全。截断顺序必须与渲染顺序一致。
        per = max(200, _MAX_READER_BODY // max(len(bodies), 1))
        out: list[str] = []
        for b in bodies:
            out.append(b if len(b) <= per else b[:per] + "\n// ...（下略）")
        lines.append("// 读取点方法体：")
        for k, b in enumerate(out):
            if k:
                lines.append("//   ")
            lines.extend("//   " + ln for ln in b.splitlines())
    lines.append("")
    return "\n".join(lines)
