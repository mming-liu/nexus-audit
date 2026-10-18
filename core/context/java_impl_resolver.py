"""Java 跨文件「实现体」解析：MyBatis Mapper / 接口实现 / @Select 注解。

为什么必须做（java-sec-code 实测出来的硬坑）：
  SQLI.mybatisSec01 的方法体只有一行
      return userMapper.findByUserName(username);
  切片里的 sink 形态和真正有漏洞的 mybatisVuln01
      return userMapper.findByUserNameVuln01(username);
  完全同构 —— 差别全部藏在 UserMapper 里：
      @Select("... username = #{username}")    安全（参数绑定）
      @Select("... username = '${username}'")  有漏洞（字符串拼接）
  不做这一步，模型只能看方法名猜，整类 SQL 注入必然瞎判。

同理，Spring 里大量 service 是 interface + impl，
`UserService.findById(id)` 的真实 SQL 在 `UserServiceImpl` 里，
XML 定义的 MyBatis 语句在 `resources/mapper/*.xml` 里。

设计：只做「确定性文本索引 + 精确查找」，不做任何语义推断。
查不到就明确标注「未找到实现体」，让上层模型自带证据不足的判断，
而不是让模型对着一个光秃秃的方法名瞎猜。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# @Select("...") / @Update("...") / @Insert / @Delete —— MyBatis 注解式 SQL
MYBATIS_ANNO = re.compile(
    r"@(?:Select|Insert|Update|Delete)\s*\(\s*(?:value\s*=\s*)?\"((?:[^\"\\]|\\.)*)\"",
    re.S,
)
# `@Select("select ... " + " from t where x = ${y}")` 跨行字符串拼接：
# 上面的 MYBATIS_ANNO 只吃第一对双引号，拼接的第二段（往往正是带 `${}`
# 或关键 WHERE 条件那一段）会整段丢失，`${}` 判据就看不到 → 真漏洞判成安全。
# 这里补齐：注解参数开头到第一个不在字符串里的 `)` 之间的所有字符串字面量。
MYBATIS_ANNO_CONCAT = re.compile(
    r"@(?:Select|Insert|Update|Delete)\s*\(\s*(?:value\s*=\s*)?"
    r"((?:\"(?:[^\"\\]|\\.)*\"\s*\+?\s*)+)", re.S)
# @Select({"a", "b"}) 数组形式
MYBATIS_ANNO_ARR = re.compile(
    r"@(?:Select|Insert|Update|Delete)\s*\(\s*\{(.*?)\}\s*\)", re.S
)

# `_enclosing_method()` 跳过后续注解时，这些名字出现在注解参数里，
# 不能被当成方法名（`@Options(keyProperty = "id")` 之后紧跟的 `(` 属于注解）。
_ANNO_LIKE_NAMES = {
    "Options", "Results", "Result", "ResultMap", "Param", "MapKey",
    "Select", "Insert", "Update", "Delete", "Value", "Type", "keyProperty",
}

# 调用点：obj.method(args) —— 取尾部方法名
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(")

# mapper XML 里的语句：<select id="x" ...>SQL</select>
XML_STMT = re.compile(
    r"<(select|insert|update|delete)\b[^>]*\bid\s*=\s*\"([^\"]+)\"[^>]*>(.*?)</\1>",
    re.S | re.I,
)

# 判断 MyBatis 语句是否可注入：${} 是字符串拼接，#{} 是参数绑定
MYBATIS_BIND = re.compile(r"#\{[^}]*\}")
MYBATIS_CONCAT = re.compile(r"\$\{[^}]*\}")


@dataclass
class ImplHit:
    """一个被调用方法在别处的实现体。"""
    name: str
    kind: str                 # mybatis_anno / mybatis_xml / java_impl / java_interface
    file: str
    body: str
    note: str = ""

    def render(self) -> str:
        tag = {
            "mybatis_anno": "MyBatis 注解语句",
            "mybatis_xml": "MyBatis XML 语句",
            "java_impl": "接口实现类方法体",
            "java_interface": "接口声明（无实现体，签名如下）",
        }.get(self.kind, self.kind)
        head = f"// ---- 跨文件证据：{self.name}() 的{tag} @ {self.file} ----"
        return f"{head}\n{self.body.rstrip()}"


@dataclass
class JavaImplResolver:
    """懒索引项目内的 Java / Mapper XML，按「方法名」做精确查找。

    只为切片补充证据，不参与任何判定；查不到返回空列表。

    `source_root` 是「本次要切片的源码树」。索引范围限定在它之下，
    而不是整个 Maven 项目根：OWASP Benchmark 的切片目录就是 testcode，
    若索引项目根会把 2740 个用例全部解析一遍（实测 43s），
    而 java-sec-code 需要跨到 security/ util/ mapper/ 也必须能覆盖。
    """
    root: Path
    source_root: Path | None = None
    max_body_chars: int = 1400
    _index: dict[str, list[ImplHit]] = field(default_factory=dict, repr=False)
    _built: bool = False

    # ---------------- 索引构建 ----------------

    def build(self) -> None:
        if self._built:
            return
        self._built = True
        root = Path(self.root)
        if not root.exists():
            return
        scan_java = Path(self.source_root) if self.source_root else root
        # 相对路径要按项目根解析：调用方可能传相对路径（切片器传的就是
        # repo_path），而 `Path("src/main/java").exists()` 依赖当前工作目录，
        # 在别的 cwd 下跑就静默返回 False → 回退成扫整个 root → 或干脆扫空。
        # 实测踩过一次：`source_root` 是相对的，`exists()` 为 False，
        # 索引里一条 @Select 都没有，6 条 MyBatis 样本全部退回模型 —— 不报错。
        if not scan_java.is_absolute():
            scan_java = (root / scan_java)
        if not scan_java.exists():
            scan_java = root
        for p in scan_java.rglob("*.java"):
            if "test" in p.parts and "main" not in p.parts:
                continue
            text = _read_cached(p)
            if not text:
                continue
            self._index_java(p, text)
        # Mapper XML 在 resources 下，不在源码树里，按项目根找
        for p in root.rglob("*.xml"):
            if "mapper" not in str(p).lower():
                continue
            text = _read_cached(p)
            if text:
                self._index_mapper_xml(p, text)

    def _rel(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.root)).replace("\\", "/")
        except ValueError:
            return str(p).replace("\\", "/")

    def _index_java(self, p: Path, text: str) -> None:
        rel = self._rel(p)
        # 1) MyBatis 注解式语句
        #    先用 CONCAT 版本取**拼接后的完整 SQL**（`"a" + "b"` 跨行也吃得到），
        #    没有拼接时它与单段版本结果一致；两者都建索引会让同一条语句
        #    出现两次，所以以 CONCAT 为主、单段版只兜它匹配不到的场合
        #    （例如注解参数里有 `value = ` 之外的写法）。
        seen_anno: set[tuple[str, str]] = set()
        for m in MYBATIS_ANNO_CONCAT.finditer(text):
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
            sql = "".join(parts)
            if not sql.strip():
                continue
            name = self._enclosing_method(text, m.end())
            if not name:
                continue
            seen_anno.add((name, sql))
            note = _mybatis_risk_note(sql)
            self._add(ImplHit(name, "mybatis_anno", rel,
                              f'@Select("{sql.strip()}")\n// {note}'))
        for m in MYBATIS_ANNO.finditer(text):
            sql = m.group(1)
            name = self._enclosing_method(text, m.end())
            if not name or (name, "".join(re.findall(
                    r'"((?:[^"\\]|\\.)*)"', m.group(0)))) in seen_anno:
                continue
            note = _mybatis_risk_note(sql)
            self._add(ImplHit(name, "mybatis_anno", rel,
                              f'@Select("{sql.strip()}")\n// {note}'))
        for m in MYBATIS_ANNO_ARR.finditer(text):
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
            if not parts:
                continue
            sql = " ".join(parts)
            name = self._enclosing_method(text, m.end())
            if not name:
                continue
            self._add(ImplHit(name, "mybatis_anno", rel,
                              f'@Select({{...}}) 拼接后："{sql.strip()}"\n'
                              f"// {_mybatis_risk_note(sql)}"))

        # 2) 普通 Java 方法体（含 interface 的抽象方法声明）
        for name, body, is_iface in _iter_methods(text):
            kind = "java_interface" if is_iface else "java_impl"
            snippet = body[: self.max_body_chars]
            if len(body) > self.max_body_chars:
                snippet += f"\n// ...（省略 {len(body) - self.max_body_chars} 字符）"
            self._add(ImplHit(name, kind, rel, snippet))

    def _index_mapper_xml(self, p: Path, text: str) -> None:
        rel = self._rel(p)
        # 必须先剥掉 XML 注释：MyBatis 的写法习惯是「把安全版本注释掉、留漏洞版本」，
        # 被注释的语句不生效。不剥注释会把 `<!--<select id="x">--><!--</select>-->`
        # 当成一条真实语句索引进去，污染证据。
        text = _strip_xml_comments(text)
        for m in XML_STMT.finditer(text):
            stmt, sid, sql = m.group(1), m.group(2), m.group(3)
            sql_clean = re.sub(r"<[^>]+>", " ", sql)          # 去掉 <if> 等动态标签
            sql_clean = re.sub(r"\s+", " ", sql_clean).strip()
            if not sql_clean:
                continue
            self._add(ImplHit(sid, "mybatis_xml", rel,
                              f"<{stmt} id=\"{sid}\">{sql_clean}</{stmt}>\n"
                              f"// {_mybatis_risk_note(sql_clean)}"))

    def _add(self, hit: ImplHit) -> None:
        self._index.setdefault(hit.name, []).append(hit)

    @staticmethod
    def _enclosing_method(text: str, pos: int) -> str | None:
        """从注解位置往后找它修饰的方法名。

        不能直接找"第一个 `word(`"：注解后面往往还跟着别的注解或注解参数，
        例如

            @Select("select ...")
            @Options(useGeneratedKeys = true, keyProperty = "id")
            int insert(User u);

        `@Options(` 里的 `Options(` 会被当成方法名，把整条实现体挂到
        `Options` 这个不存在的名字上 —— 不报错，只是查不到。
        正确做法：先**跳过所有后续注解**（含其括号平衡的参数），
        再取类型/修饰符之后的名字。返回的名字还必须后面紧跟 `(` 且不是
        `Options`/`Results`/`Result` 这类已知注解名。
        """
        seg = text[pos: pos + 1200]
        i = 0
        # 逐段跳过后续注解：@Name(...) / @Name
        while True:
            while i < len(seg) and seg[i] in " \t\r\n":
                i += 1
            if i >= len(seg) or seg[i] != "@":
                break
            m = re.match(r"@\s*[A-Za-z_][\w.]*", seg[i:])
            if not m:
                break
            i += m.end()
            j = i
            while j < len(seg) and seg[j] in " \t":
                j += 1
            if j < len(seg) and seg[j] == "(":
                depth = 1
                j += 1
                while j < len(seg) and depth:
                    if seg[j] == "(":
                        depth += 1
                    elif seg[j] == ")":
                        depth -= 1
                    j += 1
                i = j
        # 现在应到「修饰符 返回类型 方法名(」
        rest = seg[i:]
        # 去掉方法体前的类型与修饰符，取最后一个紧贴 `(` 的标识符
        m = re.search(r"\b([A-Za-z_]\w*)\s*\(", rest)
        if not m:
            return None
        name = m.group(1)
        if name in _ANNO_LIKE_NAMES:
            # 还在注解参数里（`keyProperty = "id")` 之类），继续往后找
            m2 = re.search(r"\b([A-Za-z_]\w*)\s*\(", rest[m.end():])
            if not m2 or m2.group(1) in _ANNO_LIKE_NAMES:
                return None
            return m2.group(1)
        return name

    # ---------------- 查询 ----------------

    def lookup(self, name: str, limit: int = 2) -> list[ImplHit]:
        """按方法名查实现体。优先注解/XML（含 SQL 事实），其次 java impl。"""
        self.build()
        hits = self._index.get(name) or []
        if not hits:
            return []
        order = {"mybatis_anno": 0, "mybatis_xml": 1, "java_impl": 2, "java_interface": 3}
        # 抽象接口声明信息量最低；实现类优先于同名无关类
        hits = sorted(hits, key=lambda h: (order.get(h.kind, 9),
                                          0 if "Impl" in h.file else 1))
        return hits[:limit]

    def resolve_calls(self, source: str, limit: int = 3) -> list[ImplHit]:
        """从切片源码里提取被调用的方法名，按「与本次判定相关」排序后取前 limit 个。

        只补「切片里看不到方法体」的调用：入口方法 + 已注入的同文件辅助方法
        都视作可见，不再重复注入。

        排序是构造性的低成本启发，不做语义推断：
          1. 调用点必须真的出现在切片源码里（切片没调用的实现体一律不注入 ——
             早期版本按词根打分，结果把同类里其它路由的漏洞语句塞进来，
             例如审 mybatisSec01 却注入 findByUserNameVuln03 的 ${order}，
             等于用别的路由的漏洞"污染"当前样本）
          2. MyBatis 注解 / XML 语句优先（SQL 事实本身）
          3. 名字与文件名里的安全词根命中数其次
        """
        self.build()
        body = _entry_only(source)
        defined = {name for name, _body, _iface in _iter_methods(body)}
        cands: list[ImplHit] = []
        seen: set[str] = set()
        for m in CALL_RE.finditer(body):
            name = m.group(2)
            if name in seen or len(name) < 3 or name in defined:
                continue
            seen.add(name)
            for h in self.lookup(name, limit=1):
                if h.kind == "java_interface":
                    continue
                cands.append(h)
        if not cands:
            return []
        kind_rank = {"mybatis_anno": 0, "mybatis_xml": 0, "java_impl": 1}
        cands.sort(key=lambda h: (kind_rank.get(h.kind, 2), -_relevance(h)))
        return cands[:limit]


def _entry_only(source: str) -> str:
    """只保留切片开头的入口方法体，丢掉后面拼进来的同文件辅助方法。

    切片是「入口 + // ---- 同文件辅助方法 ---- + 其余方法」的结构，
    辅助方法里往往含同一类里其它路由的漏洞写法。若在这里也扫调用点，
    审 mybatisSec01 就会把 findByUserNameVuln03 的 ${order} 当成证据注入，
    等于用别的样本的漏洞污染当前判定 —— 必错。
    """
    marker = source.find("// ----")
    return source[:marker] if marker > 0 else source


# 安全词根：命中越多越可能与本次判定相关
_SEC_WORDS = (
    "vuln", "vul", "sec", "safe", "check", "filter", "sanit", "escape", "encode",
    "sql", "query", "exec", "cmd", "shell", "file", "path", "url", "uri", "host",
    "xml", "entity", "parse", "eval", "expr", "script", "deserial", "read",
    "cipher", "crypto", "hash", "digest", "random", "token", "cookie", "session",
    "redirect", "forward", "origin", "domain", "whitelist", "blacklist",
)


def _relevance(h: ImplHit) -> int:
    """方法名/文件名里安全词根命中数，兼作廉价的相关性代理。"""
    blob = f"{h.name} {h.file}".lower()
    return sum(1 for w in _SEC_WORDS if w in blob)


def _strip_xml_comments(text: str) -> str:
    """去掉 XML 注释，保留换行以维持行号可读性。"""
    return re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)


def _mybatis_risk_note(sql: str) -> str:
    if MYBATIS_CONCAT.search(sql):
        return "含 ${} 字符串拼接（传入值被直接拼入 SQL 文本，属可注入）"
    if MYBATIS_BIND.search(sql):
        return "含 #{} 参数绑定（由 JDBC 预编译占位符承载，不可注入）"
    return "无外部占位符（语句为固定文本）"


# ---------------- Java 方法体切分（供本模块与调试复用） ----------------

METHOD_HEAD = re.compile(
    r"[ \t]*(?:public|protected|private)\s+"
    r"(?:(?:static|final|synchronized|abstract|native|default)\s+)*"
    # 返回类型：不含空白（void/String/int/User/List<User>/String[]），
    # 用 `\S+?\s+` 而不是 `[\w.\<\>\[\]\,\?\s]+?\s+`，
    # 否则跳行空白后会把 "User mybatisSec01(@Req... String username) {" 里
    # 参数列表当返回类型，生生造出一个名字叫 `{` 的假方法。
    r"\S+?\s+([A-Za-z_]\w*)\s*\(",
    re.M,
)


def _match_paren(text: str, open_idx: int) -> int:
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _match_brace(text: str, open_idx: int) -> int:
    depth, i, n = 0, open_idx, len(text)
    in_str = None
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "\"'":
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _strip_annotations(text: str) -> str:
    """删掉注解，避免 `public @interface Foo {` 之流被当成方法。

    `@RequestMapping("/x")` 里带括号，`METHOD_HEAD` 会从括号开始吞掉后面的方法名，
    生成名为 `{` 的假方法 —— 这会让调用图里冒出根本不存在的调用点。

    实现用切片拼接而不是逐字符 append：OWASP 2740 个文件 × 逐个字符
    append 实测占 7s（占整体 1/3），换成 `str.find` 定位 + 片段拼接后 <0.5s。
    """
    if "@" not in text:
        return text
    parts: list[str] = []
    pos = 0
    n = len(text)
    while True:
        i = text.find("@", pos)
        while i > 0 and text[i - 1] not in " \t\n(,{":
            i = text.find("@", i + 1)   # 不是注解起始（如 email@host），跳过
        if i < 0:
            break
        parts.append(text[pos:i])
        j = i + 1
        while j < n and (text[j].isalnum() or text[j] in "_."):
            j += 1
        k = j
        while k < n and text[k] in " \t":
            k += 1
        if k < n and text[k] == "(":
            e = _match_paren(text, k)
            if e > 0:
                parts.append(" ")       # 保持原文偏移大致对齐，便于阅读行号
                pos = e + 1
                continue
        parts.append(" ")
        pos = j if j > i else i + 1
    parts.append(text[pos:])
    return "".join(parts)


_METHOD_CACHE: dict[int, list] = {}

# 文件内容缓存：同一份源码在「索引构建」和「切片侧核对」里会被读两三次，
# OWASP 2740 个文件 × 3 次 IO 实测占 4s，缓存后降到 1.4s。
_FILE_CACHE: dict[Path, str] = {}


def _read_cached(p: Path) -> str:
    key = Path(p)
    txt = _FILE_CACHE.get(key)
    if txt is None:
        try:
            txt = key.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            txt = ""
        if len(_FILE_CACHE) > 6000:
            _FILE_CACHE.clear()
        _FILE_CACHE[key] = txt
    return txt


def _iter_methods(text: str):
    """产出 (方法名, 方法体源码, 是否接口抽象声明)。

    跳过 main()：命令行入口不是业务逻辑，注入进切片只会分散模型注意力。
    结果按 `id + len` 做一次缓存：同一份源码在一次切片里会被调用两三次
    （索引构建 + 切片侧核对），重复做括号配平纯属浪费。
    """
    key = (id(text), len(text))
    cached = _METHOD_CACHE.get(key)
    if cached is not None and cached[0] is text:
        yield from cached[1]
        return

    text_stripped = _strip_annotations(text)
    out: list[tuple[str, str, bool]] = []
    n = len(text_stripped)
    for m in METHOD_HEAD.finditer(text_stripped):
        name = m.group(1)
        if name == "main" or not name.isidentifier():
            continue
        po = text_stripped.find("(", m.end() - 1)
        if po < 0:
            continue
        pc = _match_paren(text_stripped, po)
        if pc < 0:
            continue
        tail = text_stripped[pc + 1: pc + 200]
        brace = tail.find("{")
        semi = tail.find(";")
        # `throws Exception {` 里 `{` 在 `;` 之前，没问题；但 `throws A, B;`
        # 这种畸形写法或注解尾部残留会出现 `;` 在前。真正的坑是**泛型返回值**：
        #   public List<User> orderBySafe(String field) {
        # 若 `tail` 里先撞到的是别处的 `;`，这里就判成抽象声明。
        # 因此除了比较位置，还要求 `;` 之前**没有未闭合的花括号**。
        if semi >= 0 and (brace < 0 or semi < brace):
            # 再看一眼：`;` 与 `(` 之间是否夹着 `{`（跨过去了说明花括号其实在前）
            between = text_stripped[pc + 1: pc + 1 + tail.find(";")] \
                if semi < 200 else ""
            if "{" not in between:
                end = text_stripped.find(";", pc)
                if end < 0:
                    continue
                out.append((name, text_stripped[m.start(): end + 1], True))
                continue
        if brace < 0:
            continue
        bo = pc + 1 + brace
        bc = _match_brace(text_stripped, bo)
        if bc < 0:
            continue
        out.append((name, text_stripped[m.start(): bc + 1], False))

    if len(_METHOD_CACHE) > 512:      # 简单上限，避免长跑任务里无限增长
        _METHOD_CACHE.clear()
    _METHOD_CACHE[key] = (text, out)
    yield from out
