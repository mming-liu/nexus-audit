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
# @Select({"a", "b"}) 数组形式
MYBATIS_ANNO_ARR = re.compile(
    r"@(?:Select|Insert|Update|Delete)\s*\(\s*\{(.*?)\}\s*\)", re.S
)

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
    """懒索引整个项目的 Java / Mapper XML，按「方法名」做精确查找。

    只为切片补充证据，不参与任何判定；查不到返回空列表。
    """
    root: Path
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
        for p in root.rglob("*.java"):
            if "test" in p.parts and "main" not in p.parts:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            self._index_java(p, text)
        for p in root.rglob("*.xml"):
            if "mapper" not in str(p).lower():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            self._index_mapper_xml(p, text)

    def _rel(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.root)).replace("\\", "/")
        except ValueError:
            return str(p).replace("\\", "/")

    def _index_java(self, p: Path, text: str) -> None:
        rel = self._rel(p)
        # 1) MyBatis 注解式语句
        for m in MYBATIS_ANNO.finditer(text):
            sql = m.group(1)
            name = self._enclosing_method(text, m.end())
            if not name:
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
        """从注解位置往后找它修饰的方法名。"""
        seg = text[pos: pos + 600]
        m = re.search(r"\b([A-Za-z_]\w*)\s*\(", seg)
        return m.group(1) if m else None

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
    """把行首的注解整体删掉，避免 `public @interface Foo {` 之流被当成方法。

    `@RequestMapping("/x")` 里带括号，`METHOD_HEAD` 会从括号开始吞掉后面的方法名，
    生成名为 `{` 的假方法 —— 这会让调用图里冒出根本不存在的调用点。
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "@" and (i == 0 or text[i - 1] in " \t\n(,{"):
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_."):
                j += 1
            k = j
            while k < n and text[k] in " \t":
                k += 1
            if k < n and text[k] == "(":
                e = _match_paren(text, k)
                if e > 0:
                    out.append(" " * (e + 1 - i))   # 保持列位置大致不变
                    i = e + 1
                    continue
            out.append(" " * max(1, j - i))
            i = j if j > i else i + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _iter_methods(text: str):
    """产出 (方法名, 方法体源码, 是否接口抽象声明)。

    跳过 main()：命令行入口不是业务逻辑，注入进切片只会分散模型注意力。
    """
    text = _strip_annotations(text)
    n = len(text)
    for m in METHOD_HEAD.finditer(text):
        name = m.group(1)
        if name == "main" or not name.isidentifier():
            continue
        po = text.find("(", m.end() - 1)
        if po < 0:
            continue
        pc = _match_paren(text, po)
        if pc < 0:
            continue
        tail = text[pc + 1: pc + 200]
        brace = tail.find("{")
        semi = tail.find(";")
        if semi >= 0 and (brace < 0 or semi < brace):
            yield m.group(1), text[m.start(): text.find(";", pc) + 1], True
            continue
        if brace < 0:
            continue
        bo = pc + 1 + brace
        bc = _match_brace(text, bo)
        if bc < 0:
            continue
        body = text[m.start(): bc + 1]
        yield m.group(1), body, False
