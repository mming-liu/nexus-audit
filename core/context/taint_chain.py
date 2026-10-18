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
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

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


def writes_of(source: str) -> dict[str, set[str]]:
    """{介质: {键名}} —— 本方法向哪些介质写了哪些键。"""
    return {m.key: ks for m in MEDIA if (ks := _keys(m.write_re, source))}


def reads_of(source: str) -> dict[str, set[str]]:
    """{介质: {键名}} —— 本方法从哪些介质读了哪些键。"""
    return {m.key: ks for m in MEDIA if (ks := _keys(m.read_re, source))}


# ---------------- 串接 ----------------

@dataclass
class Link:
    """一条跨路由连接：writer 写入的键，被 reader 读出。"""
    medium: str            # cookie / session / request / model
    key: str
    writer: CodeUnit
    reader: CodeUnit

    def describe(self) -> str:
        m = next((x for x in MEDIA if x.key == self.medium), None)
        label = m.label if m else self.medium
        return (f"{label} \"{self.key}\"："
                f"{self.writer.unit_name} 写入 → {self.reader.unit_name} 读出")


@dataclass
class ChainResult:
    """串接结果，按写入方索引，便于切片阶段直接取用。"""
    links: list[Link] = field(default_factory=list)

    def links_of_writer(self, unit_name: str) -> list[Link]:
        return [l for l in self.links if l.writer.unit_name == unit_name]

    def links_of_reader(self, unit_name: str) -> list[Link]:
        return [l for l in self.links if l.reader.unit_name == unit_name]


def build_chains(units: list[CodeUnit],
                 entries_only: dict[str, str] | None = None) -> ChainResult:
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
    """
    res = ChainResult()
    body_of = entries_only or {}

    # 先各自建索引，避免 O(n^2) 反复扫源码
    writers: dict[tuple[str, str], list[CodeUnit]] = {}
    readers: dict[tuple[str, str], list[CodeUnit]] = {}

    for u in units:
        src = body_of.get(u.unit_name) or u.own_body or u.source_code or ""
        if not src:
            continue
        for medium, keys in writes_of(src).items():
            for k in keys:
                writers.setdefault((medium, k), []).append(u)
        for medium, keys in reads_of(src).items():
            for k in keys:
                readers.setdefault((medium, k), []).append(u)

    for (medium, key), wlist in writers.items():
        for r in readers.get((medium, key), []):
            for w in wlist:
                if w.unit_name == r.unit_name:
                    continue          # 同方法内读写，不算跨路由
                res.links.append(Link(medium=medium, key=key, writer=w, reader=r))

    # 稳定排序，保证切片文本可复现（同输入必须产出同一切片，否则又引入抖动）
    res.links.sort(key=lambda l: (l.writer.unit_name, l.reader.unit_name,
                                  l.medium, l.key))
    return res


# ---------------- 证据渲染 ----------------

_MAX_READER_BODY = 1200


def render_chain_block(links: list[Link], reader_body: str = "") -> str:
    """把串接证据渲染成切片段落。

    格式与 `// ---- 框架装配证据 ----` 保持一致，这样 `entry_body()` 的截断
    和 `_impl_segment()` 的取段逻辑都不用改 —— 新证据天然落在"入口方法体"之后。

    关键点：**必须把读取点的方法体贴出来**。只写一句"Cookie xss 被 show 读了"
    等于让模型猜 show 做了什么；贴出 `return xss;` 它才能判断是否原样回显。
    """
    if not links:
        return ""
    lines = ["", "// ---- 跨路由串接证据 ----"]
    for l in links:
        lines.append(f"// {l.describe()}")
    if reader_body:
        body = reader_body.strip()
        if len(body) > _MAX_READER_BODY:
            body = body[:_MAX_READER_BODY] + "\n// ...（下略）"
        lines.append("// 读取点方法体：")
        lines.extend("//   " + ln for ln in body.splitlines())
    lines.append("")
    return "\n".join(lines)
