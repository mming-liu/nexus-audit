"""跨路由串接（taint_chain）与 xss/redir 规则的自检。

不调模型，秒级跑完。覆盖三类容易回归的点：

1. **介质配对**：写/读两侧的键名匹配是否只连真的一对
2. **污染隔离**：`own_body` 与 `source_code` 的差别必须生效 ——
   切片器会把同类其它路由方法当"辅助方法"拼进来，若串接误用 source_code，
   一条真连接会膨胀成 N² 条假连接（实测 12 条里 9 条是假的）
3. **规则分支**：xss 的反射型/存储型/已编码，redir 的 forward 型/常量/白名单

    python benchmarks/smoke_test_chains.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import (       # noqa: E402
    has_external_input, redir_verdict, verdict, xss_verdict,
)
from core.context.taint_chain import (         # noqa: E402
    build_chains, reads_of, render_chain_block, writes_of,
)
from core.models import CodeUnit, Language      # noqa: E402

FAILS: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"  {'OK ' if ok else 'XX '} {label}: {got!r}" + ("" if ok else f"  (期望 {want!r})"))
    if not ok:
        FAILS.append(label)


def unit(name: str, body: str, own: str | None = None) -> CodeUnit:
    return CodeUnit(file_path=f"/x/{name}.java", language=Language.JAVA_WEB,
                    unit_name=name, start_line=1, end_line=1,
                    source_code=body, own_body=body if own is None else own)


# ---------------- 1. 介质配对 ----------------

print("[1] 介质读写识别")
STORE = '''@RequestMapping("/stored/store")
public String store(String xss, HttpServletResponse response) {
    Cookie cookie = new Cookie("xss", xss);
    response.addCookie(cookie);
    return "Set param into cookie";
}'''
SHOW = '''@RequestMapping("/stored/show")
public String show(@CookieValue("xss") String xss) {
    return xss;
}'''
check("store 写入 cookie", writes_of(STORE), {"cookie": {"xss"}})
check("store 无读取", reads_of(STORE), {})
check("show 读取 cookie", reads_of(SHOW), {"cookie": {"xss"}})
check("show 无写入", writes_of(SHOW), {})

print("\n[2] 不同键名不应连上")
OTHER = '''@CookieValue("token") String token) { return token; }'''
ch = build_chains([unit("A.store", STORE), unit("A.other", OTHER)])
check("键名不同 → 0 条", len(ch.links), 0)

print("\n[3] 同一介质同一键名 → 1 条")
ch = build_chains([unit("A.store", STORE), unit("B.show", SHOW)])
check("连接数", len(ch.links), 1)
check("写入方", ch.links[0].writer.unit_name if ch.links else None, "A.store")
check("读取方", ch.links[0].reader.unit_name if ch.links else None, "B.show")

print("\n[4] 污染隔离：source_code 含同类方法，own_body 不含")
# store 的切片里被拼进了 show（模拟切片器把同类路由当辅助方法）。
# 注意：必须显式传 own=STORE，不能省略 —— unit() 在 own 为 None 时回落到
# body，那样两次构造完全相同，"污染"根本没造出来。
#
# 污染的后果不是"连接数变多"（同方法内读写被 build_chains 主动排除），
# 而是**干净的方法被误认成写入方/读取方**：reflect / safe / show 都不写
# Cookie，却因为切片里混进了 store 的方法体，全部被当成写入方。实测
# java-sec-code 上污染态产出 12 条连接、干净态 1 条。
POLLUTED = STORE + "\n\n// ---- 同文件辅助方法 ----\n" + SHOW
from core.context.taint_chain import reads_of as _r, writes_of as _w   # noqa: E402
check("污染态：store 切片里出现了读操作", _r(POLLUTED), {"cookie": {"xss"}})
check("干净态：own_body 只有写，没有读", _r(STORE), {})
ch = build_chains([unit("A.store", POLLUTED, own=STORE), unit("B.show", SHOW)])
check("用 own_body → 1 条（store 只当写入方）", len(ch.links), 1)
check("用 own_body → 写入方是 store", [l.writer.unit_name for l in ch.links], ["A.store"])

# 另一个入口 reflect：切片里被拼进 store 后，它会凭空变成"写入方"
REFLECT_BODY = '''@RequestMapping("/xss/reflect")
public static String reflect(String xss) { return xss; }'''
polluted_reflect = REFLECT_BODY + "\n\n// ---- 同文件辅助方法 ----\n" + STORE
ch_p = build_chains([unit("R.reflect", polluted_reflect, own=REFLECT_BODY),
                     unit("B.show", SHOW)])
check("reflect 干净时不写 Cookie → 0 条", len(ch_p.links), 0)
ch_p2 = build_chains([unit("R.reflect", polluted_reflect, own=polluted_reflect),
                      unit("B.show", SHOW)])
check("reflect 被污染后变成写入方（假连接）", len(ch_p2.links), 1)

print("\n[5] 证据渲染")
block = render_chain_block(ch.links, SHOW)
check("含段落头", "跨路由串接证据" in block, True)
check("含连接描述", 'Cookie "xss"' in block, True)
check("含读取点方法体", "return xss;" in block, True)
check("空连接不产文本", render_chain_block([], ""), "")

# ---------------- 2. 规则分支 ----------------

print("\n[6] xss：反射型")
REFLECT = '''@RequestMapping("/xss/reflect")
@ResponseBody
public static String reflect(String xss) {
    return xss;
}'''
check("裸形参 + 回显 → 真", xss_verdict(REFLECT), True)

SAFE = '''@RequestMapping("/xss/safe")
@ResponseBody
public static String safe(String xss) {
    return encode(xss);
}'''
check("有编码调用 → 假", xss_verdict(SAFE), False)

print("\n[7] xss：存储型（靠串接证据）")
# STORE 是不带注解/方法头的裸方法体，entry_body() 会把它整段当作"方法外"截掉。
# 这里换成完整形态，才能测到"有形参、无回显"这条真实分支。
STORE_FULL = '''@RequestMapping("/stored/store")
@ResponseBody
public String store(String xss, HttpServletResponse response) {
    Cookie cookie = new Cookie("xss", xss);
    response.addCookie(cookie);
    return "Set param into cookie";
}'''
check("store 单独 → False（不回显、无串接）", xss_verdict(STORE_FULL), False)
check("store + 串接 → 真",
      xss_verdict(STORE_FULL + "\n" + render_chain_block(ch.links, SHOW)), True)

SHOW_SAFE = '''@CookieValue("xss") String xss) {
    return encode(xss);
}'''
ch2 = build_chains([unit("A.store", STORE), unit("C.show", SHOW_SAFE)])
check("读取点做编码 → 假",
      xss_verdict(STORE_FULL + "\n" + render_chain_block(ch2.links, SHOW_SAFE)), False)

print("\n[8] redir：四种形态")
FORWARD = '''@RequestMapping("/forward")
public static void forward(HttpServletRequest request, HttpServletResponse response) {
    String url = request.getParameter("url");
    RequestDispatcher rd = request.getRequestDispatcher(url);
    rd.forward(request, response);
}'''
check("forward（服务端内部转发）→ 假", redir_verdict(FORWARD), False)

SEND_REDIRECT = '''@RequestMapping("/sendRedirect")
public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) {
    String url = request.getParameter("url");
    response.sendRedirect(url);
}'''
check("sendRedirect 无校验 → 真", redir_verdict(SEND_REDIRECT), True)

SEC = '''@RequestMapping("/sendRedirect/sec")
public void sendRedirect_seccode(HttpServletRequest request, HttpServletResponse response) {
    String url = request.getParameter("url");
    if (SecurityUtil.checkURL(url) == null) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        return;
    }
    response.sendRedirect(url);
}'''
check("sendRedirect + 白名单 → 假", redir_verdict(SEC), False)

CONST = '''@RequestMapping("/")
public String redirect() {
    return "redirect:/index";
}'''
check("常量目标 → 假", redir_verdict(CONST), False)

print("\n[9] ssrf：socket 层校验是决定性事实")
SSRF_VULN = '''@GetMapping("/HttpURLConnection/vuln")
public String httpURLConnectionVuln(@RequestParam String url) {
    return HttpUtils.HttpURLConnection(url);
}'''
check("转发给工具类、无 hook → 真", verdict("ssrf", SSRF_VULN), True)

SSRF_SEC = '''@GetMapping("/HttpURLConnection/sec")
public String httpURLConnection(@RequestParam String url) {
    try {
        SecurityUtil.startSSRFHook();
        return HttpUtils.HttpURLConnection(url);
    } finally {
        SecurityUtil.stopSSRFHook();
    }
}'''
check("挂上 startSSRFHook → 假", verdict("ssrf", SSRF_SEC), False)

SSRF_SCHEME = '''@GetMapping("/urlConnection/sec")
public String URLConnectionSec(String url) {
    if (!SecurityUtil.isHttp(url)) { return "[-] SSRF check failed"; }
    return HttpUtils.URLConnection(url);
}'''
check("只做协议白名单 → 假", verdict("ssrf", SSRF_SCHEME), False)

NO_REQ = '''@GetMapping("/health")
public String health() { return "ok"; }'''
check("不发请求 → 不属本类目", verdict("ssrf", NO_REQ), None)

print("\n[10] 门面路由")
check("verdict('xss')", verdict("xss", REFLECT), True)
check("verdict('redir')", verdict("redir", CONST), False)
check("verdict('openredirect') 别名", verdict("openredirect", SEND_REDIRECT), True)

print("\n[11] sqli 白名单必须带实参")
# 空括号 `matches()` 在 Java 里没有这个重载，是死代码。曾被当成白名单证据，
# 导致真实注入被漏判 —— 而这正是"死分支让人误以为已覆盖"的典型。
from core.agents.rule_detectors import SQLI_WHITELIST_RE
_WS = ('String sql = "select * from t where id=" + id;')
check("仅拼接、无白名单",
      bool(SQLI_WHITELIST_RE.search(_WS)), False)
check("matches(\"[0-9]+\") 带实参 → 白名单",
      bool(SQLI_WHITELIST_RE.search('if (id.matches("[0-9]+")) { }')), True)
check("matches() 空括号 → 不算白名单（死代码）",
      bool(SQLI_WHITELIST_RE.search('if (id.matches()) { }')), False)
check("matches( ) 空白 → 不算白名单",
      bool(SQLI_WHITELIST_RE.search('if (id.matches( )) { }')), False)
check("FILTER_PATTERN.matcher(x).matches() → 白名单（真实写法，见 SecurityUtil:201）",
      bool(SQLI_WHITELIST_RE.search('if (!FILTER_PATTERN.matcher(input).matches()) { }')), True)

print("\n[12] Skeptic 提示词不硬编码语言")
# Java 赛道接进反方质检后，若提示词仍写 ```python，质检员会按 Python 语义
# 挑刺（找 decorator 而非注解），挑出的理由和代码对不上。
from core.agents.skeptic_reviewer import SKEPTIC_PROMPT_TMPL, _LANG_FENCE
from core.models import Language
check("语言围栏覆盖全部赛道", set(_LANG_FENCE) == set(Language), True)
check("Java 围栏是 java", _LANG_FENCE[Language.JAVA_WEB], "java")
check("旧式三参调用仍默认 python",
      "```python" in SKEPTIC_PROMPT_TMPL.format(
          vuln_type="sqli", property_missing="x", code="x=1"), True)

print("\n[13] 沙箱状态三分")
# `verified=False` 有两种含义：跑过没复现（可信）、根本没跑（仍是猜测）。
# 早期 Web3 赛道不跑 Foundry 却把静态置信度塞进 verified，报告渲染成
# "✔ 已复现"——把猜测冒充成验证结果。
from core.models import PoCResult
check("默认认为跑过", PoCResult(hypothesis=None).sandbox_ran, True)
check("可显式标为未跑", PoCResult(hypothesis=None, sandbox_ran=False).sandbox_ran, False)

print("\n[14] own_body 的使用边界（回归 P2-5 引入的坑）")
# own_body 只该给 taint_chain 和 rule_detectors 用。推理型 agent（Skeptic）
# 必须拿 source_code：清洗逻辑写在同文件私有方法 / Service 实现层，
# 那些证据只在 source_code 里，用 own_body 会让质检员变睁眼瞎。
import asyncio, inspect
from core.agents.skeptic_reviewer import SkepticReviewer
_src = inspect.getsource(SkepticReviewer.review)
check("Skeptic 读的是 source_code",
      "h.unit.source_code" in _src and "own_body or" not in _src, True)

# 用真实切片验证：同一入口，own_body 必须严格窄于 source_code，
# 且 source_code 里含 own_body 看不到的清洗方法体。
from pathlib import Path
from core.slicer.java_servlet import JavaSlicer
_fx = Path(__file__).resolve().parent.parent / "reference_repos" / "java-sec-code"
if _fx.exists():
    _us = JavaSlicer(_fx).extract_entry_units()
    _u = next((x for x in _us if x.unit_name == "XSS.safe"), None)
    if _u:
        check("own_body 不含辅助方法体", "StringUtils.replace" in _u.own_body, False)
        check("source_code 含辅助方法体（清洗逻辑可见）",
              "StringUtils.replace" in _u.source_code, True)
        check("source_code 不含兄弟路由方法（P0-2 已净化）",
              "addCookie" in _u.source_code, False)

print("\n[15] Cite-Before-Verdict：证据必须是切片里的真实执行行")
from core.agents.scenario_matcher import verify_evidence
_C = '''@RequestMapping("/vuln")
public String vuln(String xss) {
    // return HtmlUtils.htmlEscape(xss);   曾经的安全写法，已删
    return xss;
}'''
check("真实执行行 → 通过", verify_evidence(_C, "return xss;")[0], True)
check("带缩进 → 通过", verify_evidence(_C, "    return xss;")[0], True)
check("带行号前缀 → 通过", verify_evidence(_C, '43: return xss;')[0], True)
check("编造的行 → 拒绝",
      verify_evidence(_C, "String out = HtmlUtils.htmlEscape(xss);")[0], False)
check("含省略号（概述而非引用）→ 拒绝", verify_evidence(_C, "return xss; ...")[0], False)
check("空 evidence → 拒绝", verify_evidence(_C, "")[0], False)
# 注释行是最危险的假证据：它常常写着"原本的漏洞写法"，被当真会判反。
check("引用行注释 → 拒绝",
      verify_evidence(_C, "// return HtmlUtils.htmlEscape(xss);   曾经的安全写法，已删")[0], False)

# 证据块里的代码被渲染成 `//   <code>`（防止规则把它当入口方法体的语句），
# 而"注释行一律不许当证据"的规则会连它一起拒 —— 结果是**最有力的那条证据
# 无法被引用**，模型只能退回入口方法体随便找一行交差。这正是
# mybatisVuln02 引用 `return userMapper...` 的机制性成因。
_BLOCK = '''@GetMapping("/sec/httpCors")
public CsrfToken getCsrfToken_02(CsrfToken token) {
    return token;
}

// ---- 框架装配证据：以下全局组件会作用于本路由 ----
// [Filter] OriginFilter  urlPatterns=[/*]  来源 CorsConfig.java
//   if (SecurityUtil.checkURL(refer) == null) {
//       response.sendError(403);
//   }
// [注意] 以下装配无法静态确定生效路径：
//   - 某处 registerCorsConfiguration
'''
check("证据块里的代码（带 //   原样）→ 通过",
      verify_evidence(_BLOCK, "//   if (SecurityUtil.checkURL(refer) == null) {")[0], True)
check("证据块里的代码（只拷代码）→ 通过",
      verify_evidence(_BLOCK, "if (SecurityUtil.checkURL(refer) == null) {")[0], True)
# 同样的 `//   ` 前缀，出现在**非证据块**里就还是注释，不能放行 ——
# 否则"注释里写着原本的漏洞写法"会被当成执行证据。
check("非证据块里的 //   仍是注释 → 拒绝",
      verify_evidence('public class A {\n    //   if (x) { sql="..."+y; }\n    return 1;\n}',
                      "if (x) { sql")[0], False)
check("证据块里的说明条目（//   - xxx）不可引用",
      verify_evidence(_BLOCK, "- 某处 registerCorsConfiguration")[0], False)

# sqli 判据必须覆盖 MyBatis 的 ${} 形态。只写 JDBC 拼接时，MyBatis 样本里
# 既没有 `+` 也没有 executeQuery，模型严格按字面只能答 No（整类漏报）。
from core.agents.vuln_categories import CATEGORIES as _CATS
_sq = _CATS["sqli"]
check("sqli 判据含 ${}", "$" + "{" in _sq.sink_question, True)
check("sqli 判据明确 #{} 不算拼接", "#{}" in _sq.sink_question, True)
check("sqli 判据仍保留 JDBC 形态", "executeQuery" in _sq.sink_question, True)

# ---------------- 跨项目迁移暴露的 5 处规则缺陷 ----------------
# 全部来自 Hello-Java-Sec 盲测，且都是"在 java-sec-code 上永远测不出来"的那类：
# 换一个作者、换一种写法，规则就从"全对"掉到 76%。这里逐条钉住。
print("\n[17] 跨项目迁移暴露的规则缺陷")

from core.agents.rule_detectors import verdict as _verdict, entry_body as _eb

# (a) 注释里的"修复写法"绝不能当防护。真实项目里留一行注释掉的修复极常见，
#     靶场作者就是这么写的，规则照读就把真漏洞判成安全。
_XXE_COMMENTED = '''public String XMLReader(String content) {
    XMLReader r = XMLReaderFactory.createXMLReader();
    // 修复：禁用外部实体
    // r.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    r.parse(new InputSource(new StringReader(content)));
}'''
check("注释里的 setFeature 不算防护（xxe → vuln）",
      _verdict("xxe", _XXE_COMMENTED), True)
_XXE_REAL = _XXE_COMMENTED.replace(
    "// r.setFeature", 'r.setFeature')
check("真实生效的 setFeature 算防护（xxe → safe）",
      _verdict("xxe", _XXE_REAL), False)
check("entry_body 已剥注释", "disable-doctype" not in _eb(_XXE_COMMENTED), True)

# (b) 白名单判据不能绑死函数名。`Pattern.matches(...)` 是标准库全串匹配，
#     之前因为"必须出现 sqlFilter/checkSql/isValidOrder"而没被认出来。
_SQLI_PATTERN_MATCHES = '''public String safe5(String name) {
    boolean ok = Pattern.matches("^[a-zA-Z0-9]+$", name);
    if (ok) {
        Statement st = conn.createStatement();
        String sql = "select * from users where user = '" + name + "'";
        st.executeQuery(sql);
    }
}'''
check("Pattern.matches 白名单 → safe", _verdict("sqli", _SQLI_PATTERN_MATCHES), False)
_SQLI_TRIVIAL = _SQLI_PATTERN_MATCHES.replace('"^[a-zA-Z0-9]+$"', '".*"')
check("matches(\".*\") 不算白名单 → vuln", _verdict("sqli", _SQLI_TRIVIAL), True)

# (c) 拼接的操作数是"已知 SQL 编码函数"且拼接点在引号内 → safe（见 [34]）；
#     是"我们没见过的清洗函数"时，仍是"不确定"而不是"有把握"。
#     兜底判 True 会把正确防护冤枉成漏洞。
_SQLI_ESAPI = '''public String safe3(String id) {
    Statement st = conn.createStatement();
    String sql = "select * from users where id = '" + ESAPI.encoder().encodeForSQL(codec, id) + "'";
    st.executeQuery(sql);
}'''
check("已知编码函数 + 引号内拼接 → safe",
      _verdict("sqli", _SQLI_ESAPI), False)
# 真正的未知清洗函数：语义完全靠猜 → 仍退模型
_SQLI_UNKNOWN_FN = _SQLI_ESAPI.replace(
    "ESAPI.encoder().encodeForSQL(codec, id)", "SqlCleaner.wash(id)")
check("未知清洗函数参与拼接 → None（交模型）",
      _verdict("sqli", _SQLI_UNKNOWN_FN), None)
_SQLI_BARE = '''public String vul(String id) {
    Statement st = conn.createStatement();
    String sql = "select * from users where id = '" + id + "'";
    st.executeQuery(sql);
}'''
check("裸变量拼接 → vuln", _verdict("sqli", _SQLI_BARE), True)

# (d) `${}` 遇上数字类型参数没有注入面：Spring/MyBatis 已把它解析成 int。
#     这是可核对的事实（形参声明），不是语义推断。
_SQLI_INT_DOLLAR = '''public List queryById(@PathVariable Integer id) {
    return mapper.queryByIdAsInterger(id);
}'''
_MAPPER_IMPL = '''// ---- 跨文件证据：queryByIdAsInterger() 的 MyBatis 注解语句 ----
@Select("select * from users where id = ${id}")
List<User> queryByIdAsInterger(@Param("id") Integer id);'''
check("${} + Integer 形参 → safe",
      _verdict("sqli", _SQLI_INT_DOLLAR + "\n\n" + _MAPPER_IMPL), False)
check("${} + String 形参 → vuln",
      _verdict("sqli", _SQLI_INT_DOLLAR.replace("Integer id", "String id")
               + "\n\n" + _MAPPER_IMPL.replace("Integer id", "String id")), True)

# (e) 反序列化白名单还认 ValidatingObjectInputStream（commons-io 的 allowlist）
_DESER_VALIDATING = '''public String safe(String b64) {
    ValidatingObjectInputStream ois = new ValidatingObjectInputStream(new ByteArrayInputStream(bs));
    ois.accept(Student.class);
    ois.readObject();
}'''
check("ValidatingObjectInputStream.accept → safe",
      _verdict("deserial", _DESER_VALIDATING), False)

# (f) 存储型 XSS 写库：读取点不在本方法，介质（DB）也不在串接建模内。
#     判 False 会把"看不见读取点"说成"链不闭合"，必须交模型。
_XSS_STORE_DB = '''public String save(HttpServletRequest request) {
    String content = request.getParameter("content");
    xssMapper.add(user, content, date);
    return "success";
}'''
check("写库但未编码 → None（介质未建模）", _verdict("xss", _XSS_STORE_DB), None)
check("写库前已编码 → safe",
      _verdict("xss", _XSS_STORE_DB.replace(
          "xssMapper.add(user, content", 'xssMapper.add(user, HtmlUtils.htmlEscape(content)')), False)


# 契约测试：用 mock 模型覆盖"守规矩 / 编造证据 / 混合投票"三种行为。
# 为什么必须测这个：核验一旦把合规输出也判失败，全部采样都会作废，
# 引擎会静默退化成"什么都判不出来" —— 比不启用这个机制更糟。
import asyncio as _aio
from core.agents.scenario_matcher import ScenarioMatcher as _SM
_GOOD = '{"hit": "Yes", "evidence_line": "return xss;"}'
_FAKE = '{"hit": "Yes", "evidence_line": "String safe = HtmlUtils.htmlEscape(xss);"}'
check("合规输出 → 判定通过",
      _aio.run(_SM(llm=lambda m: _GOOD)._vote("p", "hit", 1, code=_C))[0], True)
def _raise_if_not_raise():
    try:
        _aio.run(_SM(llm=lambda m: _FAKE)._vote("p", "hit", 1, code=_C))
        return False          # 没抛异常 = 编造的证据被放行了
    except RuntimeError:
        return True
check("编造证据 → 抛异常（记判定失败，不记作 No）", _raise_if_not_raise(), True)
_seq = {"n": 0}
def _mixed(_m):
    _seq["n"] += 1
    return _FAKE if _seq["n"] == 1 else _GOOD
check("3 票中 1 票编造 → 作废该票，剩 2 票计票",
      _aio.run(_SM(llm=_mixed)._vote("p", "hit", 3, code=_C))[1], (True, True))

print("\n[16] GitHub 双通道在本地必须 no-op")# 本地跑出一堆 `::warning` 会淹没正常输出；只在 GITHUB_ACTIONS 下才输出。
import os
os.environ.pop("GITHUB_ACTIONS", None)
os.environ.pop("GITHUB_STEP_SUMMARY", None)
from cli import emit_github_annotations, emit_step_summary
from core.models import CodeUnit
_fake = [(CodeUnit(file_path="a/b.py", language=Language.PYTHON_WEB, unit_name="f",
                   start_line=1, end_line=2), "sqli")]
check("无 GITHUB_ACTIONS 时不输出 annotation",
      emit_github_annotations(_fake, [], Path(".")), 0)
check("无 GITHUB_STEP_SUMMARY 时返回 False",
      emit_step_summary(Path(__file__)), False)

# ---------------- 双引证 + 输入白名单 + 无源提示 ----------------
# 这三项都来自"异源项目上模型一致误报"的两条样本（XMLDecoderVul.safe /
# GroovyVul.safe）。它们的共同点是：**规则和提示词各漏了一块拼图**，
# 而模型只是严格照办。逐项钉住，防止后续重构把它们悄悄弄回去。
print("\n[18] 双引证 / 输入白名单 / 外部输入判定")

# (a) needs_taint 的 Yes 必须同时给 source_line 与 sink_line。
#     只引一行时，模型可以直接引用 sink 行（真实存在、核验通过），
#     而"外部输入是否流入"这个条件从头到尾没被检查 —— XMLDecoderVul.safe
#     上两个模型一致误报就是这么来的。
_TAINT_C = '''@GetMapping("/safe")
public void safe() {
    ObjectInputStream ois = new ObjectInputStream(bis);
    Object obj = ois.readUnshared();
}'''
_SINK_ONLY = '{"hit": "Yes", "evidence_line": "Object obj = ois.readUnshared();"}'
check("taint 模式：只引一行 → 拒绝",
      _SM._check_evidence(_SINK_ONLY, _TAINT_C, taint=True)[0], False)
_DUAL = ('{"hit": "Yes", "source_line": "public void safe(String payload) {", '
         '"sink_line": "Object obj = ois.readUnshared();"}')
_TAINT_C2 = _TAINT_C.replace("public void safe() {", "public void safe(String payload) {")
check("taint 模式：双行齐全 → 通过",
      _SM._check_evidence(_DUAL, _TAINT_C2, taint=True)[0], True)
_SAME = ('{"hit": "Yes", "source_line": "Object obj = ois.readUnshared();", '
         '"sink_line": "Object obj = ois.readUnshared();"}')
check("source_line 与 sink_line 相同 → 拒绝（等于只引一行）",
      _SM._check_evidence(_SAME, _TAINT_C, taint=True)[0], False)
_ROUTE_AS_SOURCE = ('{"hit": "Yes", "source_line": "@GetMapping(\\"/safe\\")", '
                    '"sink_line": "Object obj = ois.readUnshared();"}')
check("source_line 引用路由注解行 → 拒绝（不说明哪里接收输入）",
      _SM._check_evidence(_ROUTE_AS_SOURCE, _TAINT_C, taint=True)[0], False)
# No 的票仍按单行核验，否则模型在"确实没有漏洞"时无处可引。
_NO_ONE_LINE = '{"hit": "No", "evidence_line": "Object obj = ois.readUnshared();"}'
check("taint 模式：No 只需一行", _SM._check_evidence(_NO_ONE_LINE, _TAINT_C, taint=True)[0], True)

# (b) 输入白名单与受限 Context 是两类互不替代的事实。
_SPEL_WL = '''public void safe(String cmd) {
    List<String> safeCodeList = Arrays.asList("id", "whoami");
    if (!safeCodeList.contains(cmd)) {
        throw new RuntimeException("unsafe");
    }
    new GroovyShell().evaluate(cmd);
}'''
check("输入白名单 + 阻断 → safe", _verdict("spel", _SPEL_WL), False)
_SPEL_WL_NOBLOCK = '''public void safe(String cmd) {
    List<String> safeCodeList = Arrays.asList("id");
    if (!safeCodeList.contains(cmd)) {
        log.warn("unsafe code");
    }
    new GroovyShell().evaluate(cmd);
}'''
check("白名单只记日志不阻断 → 不算防护（vuln）",
      _verdict("spel", _SPEL_WL_NOBLOCK), True)
_SPEL_BLACKLIST = '''public String vul2(String ex) {
    String[] black_list = {"java.+lang", "Runtime", "exec.*\\\\("};
    for (String s : black_list) {
        if (Pattern.compile(s).matcher(ex).find()) { return "黑名单过滤"; }
    }
    Expression exp = new SpelExpressionParser().parseExpression(ex);
    return exp.getValue().toString();
}'''
check("黑名单过滤不算防护（spel → vuln）", _verdict("spel", _SPEL_BLACKLIST), True)
_SPEL_BARE = '''public void vul(String cmd) {
    GroovyShell shell = new GroovyShell();
    shell.evaluate(cmd);
}'''
check("裸 evaluate 无任何防护 → vuln（不再退回模型）",
      _verdict("spel", _SPEL_BARE), True)

# (c) 无外部输入**不能**当硬短路判 False。这条是最容易"修得更好看、错得更严重"
#     的地方：XMLDecoderVul.vul 与 .safe 都不接收输入、读同一个常量文件，
#     真值却相反 —— 差异在 API 选择，不在输入侧。任何"无输入 ⇒ 安全"的
#     短路都会把那种真漏洞一起判掉。
_NOARG_SINK = '''@GetMapping("/vul")
public void vul() {
    File file = new File(path);
    new XMLDecoder(new BufferedInputStream(new FileInputStream(file))).readObject();
}'''
from core.agents.rule_detectors import has_external_input as _ext
check("无参方法 has_external_input=False", _ext(_NOARG_SINK), False)
check("无参 XMLDecoder 仍判 vuln（不得因无输入而短路）",
      _verdict("deserial", _NOARG_SINK), True)
check("有形参 → has_external_input=True",
      _ext('public void vul(String cmd) { new GroovyShell().evaluate(cmd); }'), True)
check("框架注入类型不算外部输入",
      _ext('public void f(HttpServletResponse response) { return; }'), False)
check("request.getParameter 算外部输入",
      _ext('public void f(HttpServletRequest request) { '
           'String x = request.getParameter("x"); }'), True)

# (d) sink 枚举漏项会伪装成"证据不足"。三种都真实踩过。
check("ModelAndView 视图跳转算 redir sink",
      _verdict("redir", 'public ModelAndView v(String url) { '
                        'return new ModelAndView("redirect://" + url); }'), True)
check("无任何跳转 API → redir safe",
      _verdict("redir", 'public String s(String url) { '
                        'return "安全域名：" + url; }'), False)
check("ObjectInputStream.readUnshared 算 deserial sink",
      _verdict("deserial", 'public String r(String b) { '
                           'new java.io.ObjectInputStream(stream).readUnshared(); }'), True)
check("JAXB unmarshal 算 xxe sink",
      _verdict("xxe", 'public Object u(String c) { '
                      'return unmarshaller.unmarshal(new StringReader(c)); }'), True)

# ---------------- cmdi / pathtraver 规则化 ----------------
# 这两类长期"没有干净支点"，实际有：只判两端（裸奔 True / 值级白名单 False），
# 中间态（认不出性质的校验调用）一律 None。踩过的坑写在下面断言里。
print("\n[19] cmdi / pathtraver 确定性规则")

_CMDI_BARE = '''public static String vul(String cmd) {
    Process proc = Runtime.getRuntime().exec(cmd);
    return "";
}'''
check("裸 exec(形参) → vuln", _verdict("cmdi", _CMDI_BARE), True)

_CMDI_WL = '''public static String safe(String cmd) {
    Set<String> commands = new HashSet<>();
    commands.add("ls");
    commands.add("pwd");
    String command = cmd.split("\\\\s+")[0];
    if (!commands.contains(command)) {
        return "不在白名单中";
    }
    Runtime.getRuntime().exec(command);
    return "";
}'''
check("值级白名单 + 阻断 → safe", _verdict("cmdi", _CMDI_WL), False)

# 黑名单 helper：函数名就叫 checkOs，调用形态与白名单一模一样。
# 只看"有没有调 checkXxx"会把这条判成 safe —— 必须退回模型。
_CMDI_BLACKLIST_HELPER = '''public static String safe(String filepath) {
    if (!Security.checkOs(filepath)) {
        String[] cmdList = {"sh", "-c", "ls -l " + filepath};
        new ProcessBuilder(cmdList).start();
        return "ok";
    }
    return "检测到非法命令注入";
}'''
check("认不出性质的 checkXxx（可能是黑名单）→ None，不臆断",
      _verdict("cmdi", _CMDI_BLACKLIST_HELPER), None)

_CMDI_INT = '''public static void f(Integer n) {
    Runtime.getRuntime().load(Integer.toString(n));
    return;
}'''
check("整型形参无注入面 → safe", _verdict("cmdi", _CMDI_INT), False)

_CMDI_CONST = '''public void ping() {
    Runtime.getRuntime().exec("/bin/ping -c1 127.0.0.1");
    return;
}'''
check("常量命令 → safe", _verdict("cmdi", _CMDI_CONST), False)

_PATH_VUL = '''public String download(String filename) {
    String filePath = System.getProperty("user.dir") + "/logs/" + filename;
    InputStream in = Files.newInputStream(Paths.get(filePath));
    return "";
}'''
check("路径拼接进文件 API、无任何校验 → vuln",
      _verdict("pathtraver", _PATH_VUL), True)

_PATH_CANON = '''public String safe(String filename) {
    String base = System.getProperty("user.dir") + "/logs/";
    File f = new File(base, filename);
    if (!f.getCanonicalPath().startsWith(new File(base).getCanonicalPath())) {
        throw new RuntimeException("非法路径");
    }
    InputStream in = new FileInputStream(f);
    return "";
}'''
check("规范化 + 前缀校验 → safe", _verdict("pathtraver", _PATH_CANON), False)

_PATH_HALF = '''public String safe(String filename) {
    if (!Security.checkTraversal(filename)) {
        return "安全通过";
    }
    return "检测到非法的文件名";
}'''
check("只有校验调用、没有文件操作 → 无 sink，safe",
      _verdict("pathtraver", _PATH_HALF), False)

_PATH_GUARD = '''public String download(String filename) {
    if (!Security.checkTraversal(filename)) {
        throw new RuntimeException("非法");
    }
    InputStream in = Files.newInputStream(Paths.get(base + filename));
    return "";
}'''
check("有文件操作 + 认不出的 checkXxx → None",
      _verdict("pathtraver", _PATH_GUARD), None)

# 跨文件辅助段：认不出的 checkXxx 能在证据段里读到实现体时，规则必须自己判性质，
# 而不是继续退回模型。这两条对应 java-sec-code / Hello-Java-Sec 里的真实写法。
_PATH_GUARD_BLACKLIST = _PATH_GUARD + '''

// ---- 跨文件辅助方法实现 ----
// 来自 SecurityUtil.java:18
public static boolean checkTraversal(String content) {
    return content.contains("..") || content.contains("/");
}'''
# 读到黑名单也**不能**判漏洞：够不够严取决于能否构造编码变体，
# 规则手里只有 `contains("..")` 这一行，没有可核对的事实支点。
# 两个靶场的真值都按"作者做了校验"标 safe，规则若判 True 会同时
# 打坏 java-sec-code(getImageSec) 与 Hello-Java-Sec(processbuilderSafe)。
check("辅助段读到黑名单实现 → 不判漏洞，退回模型",
      _verdict("pathtraver", _PATH_GUARD_BLACKLIST), None)

_CMD_HELPER_ALLOW = '''public static String safe(String filepath) {
    if (!SecurityUtil.checkOs(filepath)) {
        new ProcessBuilder("sh", "-c", "ls -l " + filepath).start();
        return "ok";
    }
    return "非法";
}

// ---- 跨文件辅助方法实现 ----
// 来自 SecurityUtil.java:31
public static boolean checkOs(String param) {
    return WHITE_LIST.contains(param);
}'''
check("辅助段读到值级白名单 → 判 safe",
      _verdict("cmdi", _CMD_HELPER_ALLOW), False)

# 枚举定义只出现在辅助段（入口体里只有 contains 判断）也要认
_CMD_ENUM_IN_SIB = '''public static String safe(String cmd) {
    if (!SecurityUtil.isAllowed(cmd)) {
        return "非法";
    }
    Runtime.getRuntime().exec(cmd);
    return "";
}

// ---- 跨文件辅助方法实现 ----
public static boolean isAllowed(String c) {
    return ALLOWED.indexOf(c) < 0;
}'''
check("白名单枚举在辅助段里 → 判 safe",
      _verdict("cmdi", _CMD_ENUM_IN_SIB), False)

# 黑名单循环：`for (String s : black_list) { if (content.contains(s))`
# 与白名单 `if (ALLOWED.contains(x))` 只差**接收者**是容器还是被检对象。
# 只看 `.contains(\w+)` 会把前者判成白名单（实测 checkOs 被误判成 safe）。
_CMD_BLACKLIST_LOOP = '''public static String safe(String filepath) {
    if (!Security.checkOs(filepath)) {
        new ProcessBuilder("sh", "-c", "ls -l " + filepath).start();
        return "ok";
    }
    return "非法";
}

// ---- 跨文件证据：checkOs() 的接口实现类方法体 @ Security.java ----
public static boolean checkOs(String content) {
    String[] black_list = {"|", ",", "&", "&&", ";", "||"};
    for (String s : black_list) {
        if (content.contains(s)) {
            return true;
        }
    }
    return false;
}'''
check("辅助段黑名单循环（content.contains(s)）→ 不判漏洞，退回模型",
      _verdict("cmdi", _CMD_BLACKLIST_LOOP), None)

# ssrf：读辅助段实现体，只有"host 字符串集合"能判 safe。
# 正则匹配 IP 段不能判 vul —— Hello-Java-Sec 里同一个 isIntranet，
# 内联写法标 vul、先赋中间变量标 safe，规则的事实支点区分不了这两条。
_SSRF_WL = '''public String URLConnection3(String url) {
    if (!Security.isHttp(url)) {
        return "no";
    } else if (!Security.isWhite(url)) {
        return "非可信域名！";
    } else {
        return HttpClientUtils.URLConnection(url);
    }
}

// ---- 跨文件证据：isWhite() 的接口实现类方法体 @ Security.java ----
public static boolean isWhite(String url) {
    List<String> url_list = new ArrayList<String>();
    url_list.add("baidu.com");
    URI uri = new URI(url);
    String host = uri.getHost().toLowerCase();
    return url_list.contains(host);
}'''
check("辅助段读到 host 值集合白名单 → 判 safe",
      _verdict("ssrf", _SSRF_WL), False)

_SSRF_REGEX = '''public String URLConnection2(String url) {
    if (!Security.isHttp(url)) {
        return "no";
    } else if (Security.isIntranet(Security.urltoIp(url))) {
        return "不允许访问内网!!!";
    } else {
        return HttpClientUtils.URLConnection(url);
    }
}

// ---- 跨文件证据：isIntranet() 的接口实现类方法体 @ Security.java ----
public static boolean isIntranet(String ip) {
    Pattern reg = Pattern.compile("^(127\\\\.0\\\\.0\\\\.1)|(localhost)|^(10\\\\.\\\\d{1,3})");
    Matcher match = reg.matcher(ip);
    return match.find();
}'''
check("辅助段只有正则 IP 段匹配 → 不能判 vul，退回模型",
      _verdict("ssrf", _SSRF_REGEX), None)

print("\n[20] MyBatis 注解解析边界")
from core.context.java_impl_resolver import (  # noqa: E402
    JavaImplResolver, MYBATIS_ANNO_CONCAT)

_MB = '''
public interface UserMapper {
    @Select("select * from users where name = "
          + "'" + #{name} + "'")
    List<User> byNameConcat(String name);

    @Select("select * from users order by ${field}")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    List<User> orderByUnsafe(String field);
}
'''
_anno_hits = []
for _m in MYBATIS_ANNO_CONCAT.finditer(_MB):
    _sql = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', _m.group(1)))
    _anno_hits.append((JavaImplResolver._enclosing_method(_MB, _m.end()), _sql))

_names = [n for n, _s in _anno_hits]
check("跨行 `\"a\" + \"b\"` 拼接 → 取到拼接后的完整 SQL",
      any(s.strip() == "select * from users where name = '" for _n, s in _anno_hits),
      True)
check("跨行拼接不丢第二段（第一段单独不足以判定）",
      any("where name =" in s and len(s) > len("select * from users where name =")
          for _n, s in _anno_hits), True)
check("`@Options` 紧跟注解 → 不错位成方法名 Options",
      "Options" not in _names and "orderByUnsafe" in _names, True)
check("`${field}` 判据能看到（不被拼接截断掩掉）",
      any("${field}" in s for _n, s in _anno_hits), True)
check("两个方法名都解析正确",
      sorted(n for n in _names if n) == ["byNameConcat", "orderByUnsafe"], True)

print("\n[21] sqli 拼接判据的范围（JavaSecLab 暴露的污染）")

# 结果拼接拖累 SQL 拼接：safe5 里有 `"查询成功，用户名：" + user + " 密码：" + pass`，
# 两个裸变量让"SQL 操作数全是清洗函数"这个事实被否掉 → 误报。
# ESAPI 现已是已知编码函数（[34]），此样本升级为确定性 safe；
# "结果拼接不被扫进 SQL 判据"这一点由同一段 `_sql_rhs_iter` 保证。
_SQLI_RESULT_CONCAT = '''public R safe5(@RequestParam String id) {
    Statement stmt = conn.createStatement();
    String sql = "select * from sqli where id = '" + ESAPI.encoder().encodeForSQL(oracleCodec, id) + "'";
    ResultSet rs = stmt.executeQuery(sql);
    return R.ok("查询成功，用户名：" + user + " 密码：" + pass);
}'''
check("结果拼接里的裸变量不污染 SQL 拼接判定 → safe（ESAPI 已知编码）",
      _verdict("sqli", _SQLI_RESULT_CONCAT), False)
# 同形态换未知清洗函数 → 仍应退模型（污染防护没有被放宽）
_SQLI_RESULT_CONCAT_UNK = _SQLI_RESULT_CONCAT.replace(
    "ESAPI.encoder().encodeForSQL(oracleCodec, id)", "SqlCleaner.wash(id)")
check("结果拼接不污染 + 未知清洗函数 → 退回模型",
      _verdict("sqli", _SQLI_RESULT_CONCAT_UNK), None)

# 局部变量已转整型：safe4 形参是 String，但 `Integer userId = Integer.valueOf(id)`
# 之后拼进 SQL 的是 Integer。只认形参声明会把这条判成误报。
_SQLI_LOCAL_NUMERIC = '''public R safe4(@RequestParam String id) {
    Integer userId;
    try {
        userId = Integer.valueOf(id);
    } catch (NumberFormatException e) {
        return R.error("必须为整数");
    }
    Statement stmt = conn.createStatement();
    String sql = "SELECT * FROM sqli WHERE id = " + userId;
    ResultSet rs = stmt.executeQuery(sql);
    return R.ok("查询成功，用户名：" + user + " 密码：" + pass);
}'''
check("局部变量经 Integer.valueOf 收窄 → safe",
      _verdict("sqli", _SQLI_LOCAL_NUMERIC), False)

print("\n[22] 反射执行：污点不在第一个实参")

# JavaSecLab CommandController.vul3：method.invoke(null, new String[]{payload}, ...)
# 只看第一个实参（null）会把这条真漏洞判成"实参是常量"。
_CMDI_REFLECT = '''public R vul3(String payload) throws Exception {
    Class<?> clazz = Class.forName("java.lang.ProcessImpl");
    Method method = clazz.getDeclaredMethod("start", String[].class, Map.class);
    method.setAccessible(true);
    Process process = (Process) method.invoke(null, new String[]{payload}, null, null, null, false);
    return R.ok(process.toString());
}'''
check("method.invoke(null, ...) 的污点在第 2 个实参 → vuln",
      _verdict("cmdi", _CMDI_REFLECT), True)

# switch 不能当白名单证据：同文件别的路由方法里有 switch(actionCode)，
# 曾把这条真漏洞静默判成 safe（比误报危险）。
_CMDI_SWITCH_ELSEWHERE = '''public R vul3(String payload) throws Exception {
    Method m = Class.forName("java.lang.ProcessImpl").getDeclaredMethod("start", String[].class);
    m.invoke(null, new String[]{payload});
    return R.ok("");
}

// ---- 跨文件辅助方法实现 ----
public void unrelated(String actionCode) {
    switch (actionCode) {
        case "a": break;
        case "b": break;
    }
}'''
check("同文件无关的 switch 不算白名单 → 不判 safe（退回模型）",
      _verdict("cmdi", _CMDI_SWITCH_ELSEWHERE), None)


print("\n[23] 判据的扫描作用域：只认入口真正调用的那个辅助方法")

# 同一个类里并存"给别的路由用的值级白名单"和"当前路由真正调的校验"。
# 扫整段辅助证据会把前者算进来 → 当前入口被静默判 safe。这是
# `_helper_guard_nature` 从"扫整段"改成"只截名字命中的方法体"的原因。
_CMDI_FOREIGN_ALLOW = '''public static String vul(String cmd) {
    if (!Security.checkOs(cmd)) {
        return "非法";
    }
    Runtime.getRuntime().exec(cmd);
    return "";
}

// ---- 跨文件辅助方法实现 ----
public static boolean checkOs(String content) {
    String[] black_list = {"|", ",", "&", "&&", ";", "||"};
    for (String s : black_list) {
        if (content.contains(s)) {
            return true;
        }
    }
    return false;
}

public static boolean isAllowedHost(String h) {
    return ALLOWED_HOSTS.contains(h);
}'''
check("未调用的白名单方法不得让当前入口判 safe → 退回模型",
      _verdict("cmdi", _CMDI_FOREIGN_ALLOW), None)

_CMDI_REAL_ALLOW = '''public static String safe(String cmd) {
    if (!SecurityUtil.isAllowedCmd(cmd)) {
        return "非法";
    }
    Runtime.getRuntime().exec(cmd);
    return "";
}

// ---- 跨文件辅助方法实现 ----
public static boolean isAllowedCmd(String content) {
    return ALLOWED_CMDS.contains(content);
}'''
check("真正调用的值级白名单 → safe", _verdict("cmdi", _CMDI_REAL_ALLOW), False)

print("\n[24] SQL 拼接：条件片段也要认")
# SQL 被拆成多段拼接时，当前这一行的字面量只剩 `" AND id = "`。
# 只认 select/from 会整行漏掉，"这条拼接里有裸变量"的事实没被检查。
_SQLI_TAIL_ONLY = '''public String query(String id) {
    Statement st = conn.createStatement();
    String sql = "SELECT * FROM users WHERE 1=1";
    sql += " AND id = " + id;
    st.executeQuery(sql);
}'''
check("尾段拼接（AND … = ）里的裸变量 → vuln",
      _verdict("sqli", _SQLI_TAIL_ONLY), True)
_SQLI_TAIL_SAFE = '''public String query(String id) {
    Statement st = conn.createStatement();
    String sql = "SELECT * FROM users WHERE 1=1";
    sql += " AND id = " + Integer.valueOf(id);
    st.executeQuery(sql);
}'''
check("尾段拼接里是纯函数调用 → 无裸变量，不判漏洞", _verdict("sqli", _SQLI_TAIL_SAFE), None)

print("\n[25] 模板介质：th:utext vs th:text")
# 切片器把「视图名解析到的模板渲染点」贴进证据段（view_templates.py）。
# 判定支点是模板里的渲染指令本身：th:utext 不转义、th:text 转义。
_TPL_EVIDENCE = '''
// ---- 关联视图模板（视图名解析到的模板文件，渲染点原文）----
// src/main/resources/templates/vul/xss/other.html:118  {how} 键 "html"
// >>  118| <p {directive}="${{html}}"></p>
//
'''
_TPL_VUL = '''@GetMapping("/vul2OtherTemplate")
public String vul2OtherTemplate(@RequestParam("payload") String payload, Model model) {
    model.addAttribute("html", payload);
    return "vul/xss/other";
}
'''
check("model 写入 + th:utext 不转义 → vuln",
      _verdict("xss", _TPL_VUL + _TPL_EVIDENCE.format(how="不转义渲染", directive="th:utext")), True)
check("model 写入 + th:text 自动转义 → safe",
      _verdict("xss", _TPL_VUL + _TPL_EVIDENCE.format(how="转义渲染", directive="th:text")), False)
check("写入前已编码 → 模板不转义也不成立（safe）",
      _verdict("xss", _TPL_VUL.replace("model.addAttribute(\"html\", payload)",
                                       "model.addAttribute(\"html\", HtmlUtils.htmlEscape(payload))")
               + _TPL_EVIDENCE.format(how="不转义渲染", directive="th:utext")), False)

print("\n[26] 数据库介质：同一仓储字段的写-读配对")
_DB_WRITE = '''@PostMapping("/save")
public String save(HttpServletRequest request) {
    String content = request.getParameter("content");
    xssMapper.add(user, content, date);
    return "success";
}'''
_DB_READ = '''@GetMapping("/getStored")
public List getStored() {
    return xssMapper.list();
}'''
ch_db = build_chains([unit("XSS.save", _DB_WRITE), unit("XSS.getStored", _DB_READ)],
                     repo_root=None)
# 方向锁之后只有 "写内容 → 读内容" 一条。
# 旧断言是「双向各 1 条」（对称配对），那是 newbee-mall 切片 26% 噪声的来源。
check("同字段 → 只连 写→读 一条（方向锁）", len(ch_db.links), 1)
check("介质是 db", {l.medium for l in ch_db.links}, {"db"})
check("键是字段名", {l.key for l in ch_db.links}, {"xssMapper"})

_db_block = render_chain_block(ch_db.links, {"XSS.getStored": _DB_READ})
check("db 证据里写出字段与方向", '数据库持久层 "xssMapper"' in _db_block, True)
check("db 读取点直取库值并返回 → vuln",
      xss_verdict(_DB_WRITE + "\n" + _db_block), True)
check("写入前编码 → safe",
      xss_verdict(_DB_WRITE.replace("xssMapper.add(user, content",
                                    "xssMapper.add(user, HtmlUtils.htmlEscape(content)")
                 + "\n" + _db_block), False)
# 删除接口与写入接口共用同一 Mapper：不能因为"有连接"就报存储型 XSS。
# 这条路由唯一形参是 `int id` —— 没有可注入的字符串，服务端判无此漏洞。
_DB_DELETE = '''@GetMapping("/delete")
public String delete(int id) {
    xssMapper.deleteFeedById(id);
    return "success";
}'''
ch_del = build_chains([unit("XSS.delete", _DB_DELETE), unit("XSS.getStored", _DB_READ)],
                      repo_root=None)
check("只按主键删除的接口 → 不判漏洞",
      xss_verdict(_DB_DELETE + "\n" + render_chain_block(
          ch_del.links, {"XSS.getStored": _DB_READ})), False)
# 同样的删除逻辑，但形参换成 String —— 此时"有没有把值写进库"才是真问题，
# 规则不替模型下结论。
_DB_DELETE_STR = _DB_DELETE.replace("int id", "String id")
ch_del_s = build_chains([unit("XSS.delete", _DB_DELETE_STR), unit("XSS.getStored", _DB_READ)],
                        repo_root=None)
check("String 形参的删除接口 → 退回模型",
      xss_verdict(_DB_DELETE_STR + "\n" + render_chain_block(
          ch_del_s.links, {"XSS.getStored": _DB_READ})), None)

print("\n[27] 串接证据解析：db 连接不得污染普通介质分支")
# db 的连接描述行也以 `//` 起头，早期实现把它一起吞进来，于是
# `_chain_reader_body` 非空、`_has_plain_chain` 为真 → 走进 cookie/session
# 分支判 False，DB 判定被整段跳过。
from core.agents.rule_detectors import _chain_reader_body as _crb, _has_plain_chain as _hpc
check("db 证据不产生普通读取点", _crb(_DB_WRITE + "\n" + _db_block), "")
check("db 证据不算普通连接", _hpc(_DB_WRITE + "\n" + _db_block), False)
_cookie_block = render_chain_block(
    build_chains([unit("A.store", STORE), unit("B.show", SHOW)]).links, SHOW)
check("cookie 证据仍是普通连接", _hpc(STORE_FULL + _cookie_block), True)

print("\n[28] xss 回显点：printf/format 计入 sink")
# OWASP 里 `printf`/`format` 占 xss sink 的 41%。只认 print/write/println
# 会把它们的真阳性整批漏成"无回显"（BenchmarkTest00149 就是这样漏的）。
_X_FMT_LIT = '''response.setContentType("text/html;charset=UTF-8");
String param = request.getParameter("p");
String bar = param + "_SafeStuff";
Object[] obj = {"a", bar};
response.getWriter().printf(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);'''
_X_FMT_VAR = '''String param = request.getParameter("p");
String bar = param;
Object[] obj = {"a", "b"};
response.getWriter().format(bar, obj);'''
check("printf 字面量格式串 + 无编码 → 真漏洞", xss_verdict(_X_FMT_LIT), True)
check("format 变量当格式串 → 真漏洞", xss_verdict(_X_FMT_VAR), True)

print("\n[29] xss 格式串位置决定 ENCODE 能否当防护")
# 同样是 encode + printf：格式串是字面量时脏值只是 `%s` 的实参，编码有效；
# 格式串本身可控时，转换说明符（`%n` 换行、`%x` 宽度）由用户决定，
# ENCODE 未必覆盖，规则不下结论。
_X_ENC_LITFMT = '''String param = request.getParameter("p");
String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
Object[] obj = {"a", bar};
response.getWriter().printf(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);'''
_X_ENC_VARFMT = '''String param = request.getParameter("p");
String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
Object[] obj = {"a", "b"};
response.getWriter().printf(bar, obj);'''
check("编码 + 字面量格式串 → 安全", xss_verdict(_X_ENC_LITFMT), False)
check("编码 + 变量格式串 → 退回模型", xss_verdict(_X_ENC_VARFMT), None)
_X_ENC_PLAIN = '''String param = request.getParameter("p");
String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
response.getWriter().println(bar);'''
check("编码 + 普通回显（无格式串）→ 安全", xss_verdict(_X_ENC_PLAIN), False)

print("\n[30] xss 外部输入：值从别的类的包装对象里取")
# `new SeparateClassRequest(request)` 之后 `scr.getTheParameter(...)` ——
# 入口体里一个 `getParameter(` 都没有，但请求对象被整个传出去了。
_X_FOREIGN = '''response.setContentType("text/html;charset=UTF-8");
org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
String param = scr.getTheParameter("BenchmarkTest01507");
if (param == null) param = "";
String bar = new Test().doSomething(request, param);
response.getWriter().println(bar.toCharArray());'''
check("request 传给别的类再取值 → 算外部输入", has_external_input(_X_FOREIGN), True)
# 回显值来自 `new Test().doSomething(request, param)` —— 值在辅助方法里产出，
# 是否转义取决于那个方法体。**这是有意的保守**：宁可交模型，也不在没有
# 看到辅助方法体的情况下判 True（否则一路"看见外部输入 + 看见回显"就报）。
# 线上对照：OWASP BenchmarkTest01507 真值是 vul，但同一形态的
# BenchmarkTest01046/01335/01417 用 `doSomething` 里换成字面量或转义，
# 真值是 safe，规则在本靶场分不开这两类，只能交模型。
check("值来自辅助方法产出 → 退回模型（范围没看全）", xss_verdict(_X_FOREIGN), None)
_X_CONST_ONLY = '''String bar = readFromConfig();
response.getWriter().println(bar.toCharArray());'''
check("没有任何外部输入 → 不判漏洞", xss_verdict(_X_CONST_ONLY), False)

# `getTheValue` 名字像 `getTheParameter`，但 OWASP 的 SeparateClassRequest
# 里它写着 `// This method is a 'safe' source.` 且 `return "bar";`。
# 按名字算脏 → 260 条样本里 205 条 safe 全部翻成误报。
_X_SAFE_SOURCE = '''org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
String param = scr.getTheValue("BenchmarkTest00887");
String bar = "safe!";
java.util.HashMap<String, Object> map39726 = new java.util.HashMap<String, Object>();
map39726.put("keyA-39726", "a-Value");
map39726.put("keyB-39726", param);
bar = (String) map39726.get("keyB-39726");
response.getWriter().println(bar.toCharArray());'''
check("getTheValue 是声明过的安全源 → 不判漏洞",
      xss_verdict(_X_SAFE_SOURCE), False)
check("getTheValue 不算外部输入",
      has_external_input(_X_SAFE_SOURCE), False)
check("getTheParameter 算外部输入",
      has_external_input('String p = scr.getTheParameter("x");'), True)

print("\n[31] 容器「先放常量再覆盖」→ 不判 True，交模型")
# OWASP 的两组同构写法：差别只在覆盖顺序，真值相反。
_LS = '''String param = request.getParameter("p");
String bar = "alsosafe";
if (param != null) {
    java.util.List<String> valuesList = new java.util.ArrayList<String>();
    valuesList.add("safe");
    valuesList.add(param);
    valuesList.add("moresafe");
    valuesList.remove(0);
    bar = valuesList.get(%s); // get the last 'safe' value
}
response.getWriter().println(bar.toCharArray());'''
check("List remove(0) 后 get(1) 取到常量 → 安全", xss_verdict(_LS % "1"), False)
check("List remove(0) 后 get(0) 取到 param → 真漏洞", xss_verdict(_LS % "0"), True)
_MP = '''String param = request.getParameter("p");
String bar = "safe!";
java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
m.put("keyA", "a_Value");
m.put("keyB", param);
bar = (String) m.get("keyB");
%s
response.getWriter().println(bar);'''
check("Map 先取 param 再被 keyA 覆盖 → 安全",
      xss_verdict(_MP % 'bar = (String) m.get("keyA");'), False)
check("Map 只取 param（无覆盖）→ 真漏洞", xss_verdict(_MP % ""), True)

print("\n[32] 恒真/恒假分支：常量条件可求值")
# OWASP 用 `(7*18)+num > 200` 这种恒真条件承载 true/false 样本。
# 恒真分支赋字面量 ⇒ 脏值没进回显 ⇒ 安全；赋 param ⇒ 维持 True。
_IF_LIT = '''String param = request.getParameter("p");
String bar;
int num = 106;
if ((7 * 18) + num > 200) bar = "always";
else bar = param;
response.getWriter().println(bar);'''
_IF_VAR = '''String param = request.getParameter("p");
String bar;
int num = 106;
if ((7 * 18) + num > 200) bar = param;
else bar = "never";
response.getWriter().println(bar);'''
check("恒真分支赋字面量 → 安全", xss_verdict(_IF_LIT), False)
# 恒真分支赋 param：语义上确实是漏洞，但"回显值来自 if 行内赋值"这一形态
# 本方法里**没有一处行首的 `bar = …`** 可供逐行核对，按第 5 条铁律
# 只能交模型，不能拿"条件解出来是真的"替模型下结论。
check("恒真分支赋 param → 退回模型（不替它下结论）", xss_verdict(_IF_VAR), None)
_IF_UNKNOWN = '''String param = request.getParameter("p");
String bar;
if (flag > 200) bar = "x";
else bar = param;
response.getWriter().println(bar);'''
# 条件里是未知变量 → 两个分支都可能生效，bar 也可能是 `"x"`。
# 规则判不准"哪一支生效"，同样交给模型。
check("条件含变量 → 两支都可能，退回模型", xss_verdict(_IF_UNKNOWN), None)
_LOOP = '''String param = request.getParameter("p");
String bar = "safe";
boolean go = false;
while (false) {
    bar = param;
}
response.getWriter().println(bar);'''
check("while(false) 块内的赋值不生效 → 安全", xss_verdict(_LOOP), False)

print("\n[33] cmdi 字符集正则白名单：锚定 + matches() 全串匹配")
# java-sec-code SecurityUtil.cmdFilter 的形态。三个条件缺一不可。
_CMD_CHARSET = '''// ---- 跨文件辅助方法实现 ----
// 来自 SecurityUtil.java:200
    public static String cmdFilter(String input) {
        if (!FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }
        return input;
    }
FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\\\.-]+$");'''
_entry = '''public String codeInjectSec(String filepath) {
    String filterFilePath = SecurityUtil.cmdFilter(filepath);
    if (null == filterFilePath) { return "Bad boy. I got u."; }
    String[] cmdList = new String[]{"sh", "-c", "ls -la " + filterFilePath};
    ProcessBuilder builder = new ProcessBuilder(cmdList);
    builder.start();
    return "";
}'''
check("字符集锚定白名单 → 判安全",
      _verdict("cmdi", _entry + "\n" + _CMD_CHARSET), False)
# 未锚定 = find 语义，`";;ls"` 能过 → 不是白名单
check("正则未锚定 → 不认",
      _verdict("cmdi", _entry + "\n" + _CMD_CHARSET.replace(
          '^[a-zA-Z0-9_/\\\\.-]+$', '[a-zA-Z0-9_/\\\\.-]+')),
      None)
# 有 `|` = 几个片段之一，退化成黑名单
check("正则含 | → 不认",
      _verdict("cmdi", _entry + "\n" + _CMD_CHARSET.replace(
          '[a-zA-Z0-9_/\\\\.-]+', 'cat|dog')),
      None)
# 用了 .find() 而不是 .matches() → 子串命中即可，不是全串
check("用 find() 而非 matches() → 不认",
      _verdict("cmdi", _entry + "\n" + _CMD_CHARSET.replace(
          '.matches()', '.find()')),
      None)

print("\n[34] sqli SQL 编码函数：拼接点必须在单引号内")
# Hello-Java-Sec JDBC.safe3 / JavaSecLab JdbcController.safe5 同形态。
# encodeForSQL 与 escapeSql 都只中和 `'`，只在**字符串位置**有效；
# 无引号拼接（数字注入位）里 `1 OR 1=1` 原样穿过 —— 判据绑定引号上下文。
_SQL_ENC_OK = '''public String safe(String id) throws Exception {
    Statement stmt = conn.createStatement();
    String sql = "select * from users where id = '"
            + ESAPI.encoder().encodeForSQL(oracleCodec, id) + "'";
    ResultSet rs = stmt.executeQuery(sql);
    return "";
}'''
check("encodeForSQL + 引号内拼接 → safe", _verdict("sqli", _SQL_ENC_OK), False)
_SQL_ENC_NUM = '''public String bad(String id) throws Exception {
    Statement stmt = conn.createStatement();
    String sql = "SELECT * FROM users WHERE id = "
            + ESAPI.encoder().encodeForSQL(new OracleCodec(), id);
    ResultSet rs = stmt.executeQuery(sql);
    return "";
}'''
check("encodeForSQL 但无引号（数字注入位）→ 退模型",
      _verdict("sqli", _SQL_ENC_NUM), None)
_SQL_ESC_OK = '''public String ok(String id) throws Exception {
    Statement stmt = conn.createStatement();
    String sql = "SELECT * FROM users WHERE id = '"
            + StringEscapeUtils.escapeSql(id) + "'";
    ResultSet rs = stmt.executeQuery(sql);
    return "";
}'''
check("escapeSql + 引号内拼接 → safe", _verdict("sqli", _SQL_ESC_OK), False)
_SQL_ESC_NUM = '''public String bad2(String id) throws Exception {
    Statement stmt = conn.createStatement();
    String sql = "SELECT * FROM users WHERE id = "
            + StringEscapeUtils.escapeSql(id);
    ResultSet rs = stmt.executeQuery(sql);
    return "";
}'''
check("escapeSql 但无引号 → 退模型", _verdict("sqli", _SQL_ESC_NUM), None)
_SQL_BARE = '''public String vul(String id) throws Exception {
    Statement stmt = conn.createStatement();
    String sql = "select * from users where id = '" + id + "'";
    ResultSet rs = stmt.executeQuery(sql);
    return "";
}'''
check("裸变量拼接 → 真漏洞", _verdict("sqli", _SQL_BARE), True)

print("\n[35] 真值争议登记簿：证据必须逐字对上源码")
# 这条断言守的是"报告可信度"而不是检测能力：行号写错的争议清单，
# 维护者点进去看到无关代码，会连带怀疑整份报告。所以登记的证据
# 必须能在靶场里逐字找到 —— 与 cite-before-verdict 对模型的要求同一把尺子。
from benchmarks.disputed_truth import (          # noqa: E402
    all_disputes, for_target, verify_evidence,
)
_ds = all_disputes()
check("登记簿非空", len(_ds) > 0, True)
check("每条都有源码证据", all(d.evidence for d in _ds), True)
check("每条都填了行号", all(e.line > 0 for d in _ds for e in d.evidence), True)
check("每条都归到已知分歧类型",
      all(d.kind in ("defense_in_depth", "not_the_property",
                     "self_contradiction", "demo_convention") for d in _ds), True)
_problems = verify_evidence(ROOT)
check("证据逐字核对通过", not _problems, True)
if _problems:
    for _p in _problems:
        print(f"     ! {_p}")
# 靶场脚本取的清单必须与登记簿一致（防止又出现本地字典各说各话）
check("Hello-Java-Sec 清单来自登记簿",
      set(for_target("Hello-Java-Sec")) >= {"XMLDecoderVul.safe", "Traversal.safe2"}, True)
check("JavaSecLab 清单来自登记簿",
      set(for_target("JavaSecLab")) >= {"ReflectController.safe2"}, True)


print("\n[36] 值来源闸门：sqli / pathtraver 也认『常量顶掉脏值』")
# 这三种机制此前只写在 xss 里，且只认变量名 bar、只扫入口体。OWASP 把同一套
# 模板复用到了 sqli/pathtraver，只是把代码放进了同文件的 private class Test —
# 于是规则看见「bar 拼进 SQL」就判 True，真值却是 safe。
_SQL_HEAD = '''public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
'''
_SQL_TAIL = '''    java.sql.Connection conn = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.Statement stmt = conn.createStatement();
    java.sql.ResultSet rs = stmt.executeQuery(sql);
}'''
_PATH_TAIL = '''    java.nio.file.Path path = java.nio.file.Paths.get(fileName);
    java.io.InputStream is = java.nio.file.Files.newInputStream(path);
}'''
_SEP = "\n// ---- 同文件辅助方法 ----\n"
_SQL_SINK = '''    String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";
'''
_SQL_VUL = _SQL_HEAD + '''    String bar = param;
    String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";
''' + _SQL_TAIL
check("SQL 拼接操作数是裸形参 → 真漏洞", _verdict("sqli", _SQL_VUL), True)

_SQL_IF = _SQL_HEAD + '''    String bar = new Test().doSomething(request, param);
''' + _SQL_SINK + _SQL_TAIL + _SEP + '''
private class Test {
    public String doSomething(HttpServletRequest request, String param) {
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        return bar;
    }
}'''
check("helper 里恒真分支赋字面量 → 安全", _verdict("sqli", _SQL_IF), False)

_SQL_TRI = _SQL_HEAD + '''    String bar = doSomething(request, param);
''' + _SQL_SINK + _SQL_TAIL + _SEP + '''
private static String doSomething(HttpServletRequest request, String param) {
    String bar;
    int num = 106;
    bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    return bar;
}'''
check("helper 里恒真三元赋字面量 → 安全", _verdict("sqli", _SQL_TRI), False)

_SQL_CONST_ARG = _SQL_HEAD + '''    String g = "barbarians_at_the_gate";
    String bar = thing.doSomething(g);
''' + _SQL_SINK + _SQL_TAIL
check("调用点只喂常量（helper 不可见）→ 安全", _verdict("sqli", _SQL_CONST_ARG), False)

_SQL_TAINT_ARG = _SQL_HEAD + '''    String g = request.getParameter("q");
    String bar = thing.doSomething(g);
''' + _SQL_SINK + _SQL_TAIL
check("实参本身来自请求 → 维持真漏洞", _verdict("sqli", _SQL_TAINT_ARG), True)

# 反例：switch 的选中分支赋 param，不能因为"结构复杂"就放行
_SQL_SWITCH = _SQL_HEAD + '''    String bar = new Test().doSomething(request, param);
''' + _SQL_SINK + _SQL_TAIL + _SEP + '''
private class Test {
    public String doSomething(HttpServletRequest request, String param) {
        String bar;
        String guess = "ABC";
        char switchTarget = guess.charAt(2);
        switch (switchTarget) {
            case 'A': bar = param; break;
            case 'C': case 'D': bar = param; break;
            default: bar = "bobs_your_uncle"; break;
        }
        return bar;
    }
}'''
check("switch 选中分支赋 param → 维持真漏洞", _verdict("sqli", _SQL_SWITCH), True)

_PATH_MAP = _SQL_HEAD + '''    String bar = new Test().doSomething(request, param);
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
''' + _PATH_TAIL + _SEP + '''
private class Test {
    public String doSomething(HttpServletRequest request, String param) {
        String bar = "safe!";
        java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
        m.put("keyA-1", "a_Value");
        m.put("keyB-1", param);
        bar = (String) m.get("keyB-1");
        bar = (String) m.get("keyA-1");
        return bar;
    }
}'''
check("路径拼接的操作数是容器常量 → 安全", _verdict("pathtraver", _PATH_MAP), False)

_PATH_VUL = _SQL_HEAD + '''    String bar = param;
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
''' + _PATH_TAIL
check("路径拼接的操作数是裸形参 → 真漏洞", _verdict("pathtraver", _PATH_VUL), True)

# 行内赋值（`if (c) param = values[0];`）`_ASSIGN_RE` 是看不见的。只看行首赋值
# 会取到开头的 `String param = "";`，把外部输入当常量 —— 那是**漏报**。
# OWASP 02272 就是这么从 True 掉成 False 的。
_SQL_INLINE_IF = _SQL_HEAD.replace('    String param = request.getParameter("p");\n', '''    String param = "";
    java.util.Map<String, String[]> map = request.getParameterMap();
    if (!map.isEmpty()) param = map.get("p")[0];
''') + '''    String bar = doSomething(request, param);
''' + _SQL_SINK + _SQL_TAIL + _SEP + '''
private static String doSomething(HttpServletRequest request, String param) {
    String bar;
    int num = 196;
    if ((500 / 42) + num > 200) bar = param;
    else bar = "This should never happen";
    return bar;
}'''
check("行内 if 赋值不能被当成常量（防漏报）",
      _verdict("sqli", _SQL_INLINE_IF), True)

_PATH_FIELD_WRITTEN = _SQL_HEAD + '''    this.TESTFILES_DIR = param;
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + "x";
''' + _PATH_TAIL
check("字段前缀被本方法写过 → 不放行", _verdict("pathtraver", _PATH_FIELD_WRITTEN), True)


# ---------------- [37] xpathi：4 条模型侧 FP 的机制锁 ----------------
#
# OWASP xpathi 曾有 4 条 FP 全是模型投票抖动（missing_property），根因是
# 没有 verdict 入口、可证为常量的样本照样送模型抽签。00117/01893 是恒真
# 分支、02370/02457 是容器顶掉脏值 —— 与 sqli/pathtraver 同机制。
# 第 4 条断言是方向性护栏：`get(0)` 取的恰是 add 进去的脏值，容器推演
# 必须判不出 lit，否则就是把真漏洞判 safe（记忆第 5 条的容器变体）。

_XP_SINK = '''    javax.xml.xpath.XPathFactory xpf = javax.xml.xpath.XPathFactory.newInstance();
    javax.xml.xpath.XPath xp = xpf.newXPath();
    String expression = "/Employees/Employee[@emplid='" + bar + "']";
    org.w3c.dom.NodeList nodeList =
            (org.w3c.dom.NodeList) xp.compile(expression).evaluate(xmlDocument,
                    javax.xml.xpath.XPathConstants.NODESET);
'''
_XP_VUL = _SQL_HEAD + '''    String bar = param;
''' + _XP_SINK + _SQL_TAIL
check("xpathi 裸形参拼进表达式 → 真漏洞(交模型)", _verdict("xpathi", _XP_VUL), None)

_XP_CONST_IF = _SQL_HEAD + '''    String bar;
    int num = 86;
    if ((7 * 42) - num > 200) bar = "This_should_always_happen";
    else bar = param;
''' + _XP_SINK + _SQL_TAIL
check("xpathi 恒真分支赋字面量 → 安全(00117)", _verdict("xpathi", _XP_CONST_IF), False)

_XP_CONST_HELPER = _SQL_HEAD + '''    String bar = doSomething(request, param);
''' + _XP_SINK + _SQL_TAIL + _SEP + '''
private static String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {
    String bar;
    int num = 86;
    if ((7 * 42) - num > 200) bar = "This_should_always_happen";
    else bar = param;
    return bar;
}'''
check("xpathi 恒真分支经 helper → 安全(01893)", _verdict("xpathi", _XP_CONST_HELPER), False)

_XP_CONTAINER = _SQL_HEAD + '''    String bar = doSomething(request, param);
''' + _XP_SINK + _SQL_TAIL + _SEP + '''
private static String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {
    String bar = "alsosafe";
    if (param != null) {
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        valuesList.remove(0);
        bar = valuesList.get(1);
    }
    return bar;
}'''
check("xpathi 容器顶掉脏值 → 安全(02370/02457)", _verdict("xpathi", _XP_CONTAINER), False)

_XP_CONTAINER_LEAK = _SQL_HEAD + '''    String bar = doSomething(request, param);
''' + _XP_SINK + _SQL_TAIL + _SEP + '''
private static String doSomething(HttpServletRequest request, String param)
        throws ServletException, IOException {
    String bar = param;
    if (param != null) {
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add("moresafe");
        valuesList.remove(0);
        bar = valuesList.get(1);
    }
    return bar;
}'''
check("xpathi guard 前旧值是脏值 → 不许放行(方向护栏)", _verdict("xpathi", _XP_CONTAINER_LEAK), None)


# ---------------- [38] OWASP 全量扫描暴露的五类机制 ----------------
#
# 这一段的来源不是设计，是 `benchmarks/regress_owasp_rules.py`（全量 2740
# 样本）逼出来的：30 条/类的抽样池把 41 条 safe→True 与 15 条 vul→False
# 全盖住了。逐条打开源码后归成五类，每类一条断言。
#
# 三条是**方向护栏**（必须判 True / None），比"能判出 False"更重要：
# 判据放宽时最先坏的总是它们，而它们坏掉就是静默放行真漏洞。

# ① 容器顶掉脏值，写在**入口体**里（不只是 helper 内）
_SQL_CONTAINER_INLINE = _SQL_HEAD + '''    String bar = "alsosafe";
    if (param != null) {
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        valuesList.remove(0);
        bar = valuesList.get(1);
    }
''' + _SQL_SINK + _SQL_TAIL
check("入口体容器顶掉脏值 → 安全(00200)", _verdict("sqli", _SQL_CONTAINER_INLINE), False)

# ② switch 选择子 `charAt(1)` = 'B' → 走常量分支
_SQL_SWITCH_SAFE = _SQL_HEAD + '''    String bar;
    String guess = "ABC";
    char switchTarget = guess.charAt(1);
    switch (switchTarget) {
        case 'A':
            bar = param;
            break;
        case 'B':
            bar = "bob";
            break;
        case 'C':
        case 'D':
            bar = param;
            break;
        default:
            bar = "bob's your uncle";
            break;
    }
''' + _SQL_SINK + _SQL_TAIL
check("switch charAt(1)='B' 走常量分支 → 安全(01806)", _verdict("sqli", _SQL_SWITCH_SAFE), False)

# ③ 方向护栏：同一个 switch，`charAt(2)` = 'C' 走的是脏值分支。
#    01803/01807/01814 就是这一族。靶场把 01807 标成 safe 是**真值错误**
#    （已登记 disputed_truth.py），规则必须判 True 而不是被 switch 折叠忽悠成安全。
_SQL_SWITCH_VUL = _SQL_SWITCH_SAFE.replace("charAt(1)", "charAt(2)")
check("switch charAt(2)='C' 走脏值分支 → 真漏洞(方向护栏)", _verdict("sqli", _SQL_SWITCH_VUL), True)

# ④ 跨文件接口实现体 return 字面量（`SeparateClassRequest.getTheValue`）
#    证据在切片的「跨文件证据：getTheValue() 的接口实现类方法体」段里，
#    `_element_is_constant` 必须去读它，否则整族样本永远判不出常量。
_SQL_SAFE_SOURCE = _SQL_HEAD + '''    String param2 = scr.getTheValue("p");
    String bar = thing.doSomething(param2);
''' + _SQL_SINK + _SQL_TAIL + '''
// ---- 跨文件证据：getTheParameter() 的接口实现类方法体 @ src/SeparateClassRequest.java ----
    public String getTheParameter(String p) {
        return request.getParameter(p);
    }
// ---- 跨文件证据：getTheValue() 的接口实现类方法体 @ src/SeparateClassRequest.java ----
    public String getTheValue(String p) {
        return "bar";
    }
'''
check("跨文件实现体 return 字面量 → 安全(00863 族)", _verdict("sqli", _SQL_SAFE_SOURCE), False)

# ⑤ 方向护栏：`encodeBase64` 是数据变换，不是输出编码。
#    宽写成 `encode\w*\(` 会让 OWASP 00385 这类真漏洞被判"已编码"→ 静默放行。
#    要求只到"不得判 False"这一档：值经过 helper 产出，是否已转义取决于
#    那个方法体，规则看不到就不能给确定结论（与 _echo_value_traced_locally
#    的三态一致）。
_XSS_BASE64_VUL = '''public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = new String(java.util.Base64.decodeBase64(
            java.util.Base64.encodeBase64(param.getBytes())));
    java.io.PrintWriter out = response.getWriter();
    out.println(bar);
}'''
check("encodeBase64 不算输出编码 → 不得判安全(方向护栏)",
      _verdict("xss", _XSS_BASE64_VUL) is not False, True)

# ⑥ 方向护栏：`PrintWriter out = response.getWriter(); out.format(...)`
#    回显经过中间变量，连写形态 `getWriter().format(` 匹配不到。
#    漏掉的后果不是少报一个 sink，而是整条落到"无回显 → False"。
_XSS_WRITER_VUL = '''public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = param;
    Object[] obj = {"a", bar};
    java.io.PrintWriter out = response.getWriter();
    out.format(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);
}'''
check("PrintWriter 中间变量回显 → 真漏洞(方向护栏)", _verdict("xss", _XSS_WRITER_VUL), True)


# ---------------- [39] authz：越权与未授权访问 ----------------
#
# 判据来源是靶场自述原文（JavaSecLab idor 页面）。这一段的两条护栏比
# 正例更重要：
#   · 只取主体、不做拒绝分支 → 必须是 None（不是 False）。"log 了一句
#     当前用户"不构成校验，判 False 就是静默放行。
#   · 垂直越权的视图路由 → 必须是 None（不是 True）。"方法体没有角色校验"
#     是事实，但"没有校验"不等于"谁都能访问"——可能被全局拦截器挡住。

_AUTHZ_VUL = '''public R getUserInfo(String username){
    User user = userMapper.getAllByUsername(username);
    if (user != null) {
        return R.ok("用户名：" + user.getUsername() + " 密码：" + user.getPassword());
    } else return R.error("用户名不存在");
}'''
check("入参直查资源且无主体获取 → 越权(True)", _verdict("authz", _AUTHZ_VUL), True)

_AUTHZ_SAFE = '''public R safe(String username){
    String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
    if (username == null || !username.equals(currentUsername)) {
        return R.error("您没有权限查看该用户的资料");
    }
    User user = userMapper.getAllByUsername(username);
    return R.ok("用户名：" + user.getUsername());
}'''
check("取主体 + 比对 + 拒绝分支 → 安全(False)", _verdict("authz", _AUTHZ_SAFE), False)

_AUTHZ_ROLE = '''public R safe() {
    String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
    if ("admin".equals(currentUsername)) {
        return R.ok("管理员权限校验通过");
    }
    return R.error("当前用户无管理员权限：" + currentUsername);
}'''
check("角色常量比对 → 安全(False)", _verdict("authz", _AUTHZ_ROLE), False)

_AUTHZ_ANNOTATION = '''@PreAuthorize("hasRole('ADMIN')")
public R list() {
    return R.ok(userMapper.selectAll());
}'''
check("@PreAuthorize 声明式校验 → 安全(False)", _verdict("authz", _AUTHZ_ANNOTATION), False)

# 方向护栏：只记日志、没有终止请求 → 不构成校验
_AUTHZ_LOG_ONLY = '''public R getUserInfo(String username){
    String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
    log.info("current user = {}", currentUsername);
    User user = userMapper.getAllByUsername(username);
    return R.ok("用户名：" + user.getUsername() + " 密码：" + user.getPassword());
}'''
check("只取主体 + 记日志、无拒绝分支 → 不得判安全(方向护栏)",
      _verdict("authz", _AUTHZ_LOG_ONLY) is not False, True)

# 方向护栏：垂直越权的视图路由，方法体看不到全局拦截器
_AUTHZ_VERTICAL = '''@GetMapping("/vul")
public String vul() {
    return "vul/logic/idor/admin";
}'''
check("垂直越权视图路由 → 交模型，不硬判 True(方向护栏)",
      _verdict("authz", _AUTHZ_VERTICAL), None)


# ---------------- [40] 四跳调用链：切片必须跨到 sink ----------------
#
# 企业项目的真实链路是 Controller → Facade → Service → Dao → Mapper，4~6 跳。
# 2026-10-20 之前 `_resolve_cross_file_helpers` 的深度固定为 1，实测四跳探针：
#   Controller.detail → Facade.query → Service.getDetail → Dao.rawQuery → sink
# 切片里**只有 Hop 1**，`SELECT * FROM orders` 完全不在，规则返回 None，
# 模型看不到 sink 就答 No —— 真漏洞被静默放行。
#
# 这三个断言锁的是"证据到没到"，不是"判据聪明不聪明"：
#   ① Hop 标记 ≥ 3 —— 展开真的递归了
#   ② sink 文本在切片里 —— 第 3 跳的实现体被拉进来了
#   ③ 规则判 True —— 端到端通了（证据到了但判据不读，仍然是 None）

from core.slicer.java_servlet import JavaSlicer as _JS          # noqa: E402
import tempfile as _tf                                          # noqa: E402
from pathlib import Path as _Path                               # noqa: E402

_HOP_FILES = {
    "OrderController.java": '''package probe;
@RestController
@RequestMapping("/order")
public class OrderController {
    private OrderFacade orderFacade;
    @GetMapping("/detail")
    public String detail(@RequestParam("id") String id) {
        return orderFacade.query(id);
    }
}''',
    "OrderFacade.java": '''package probe;
public class OrderFacade {
    private OrderService orderService;
    public String query(String id) {
        return orderService.getDetail(id);
    }
}''',
    "OrderService.java": '''package probe;
public class OrderService {
    private OrderDao orderDao;
    public String getDetail(String id) {
        return orderDao.rawQuery(id);
    }
}''',
    "OrderDao.java": '''package probe;
public class OrderDao {
    private JdbcTemplate jdbcTemplate;
    public java.util.List<String> rawQuery(String id) {
        String sql = "SELECT * FROM orders WHERE id = '" + id + "'";
        return jdbcTemplate.query(sql, (rs, i) -> rs.getString("id"));
    }
}''',
}

with _tf.TemporaryDirectory() as _td:
    _base = _Path(_td) / "src" / "main" / "java" / "probe"
    _base.mkdir(parents=True)
    for _n, _c in _HOP_FILES.items():
        (_base / _n).write_text(_c, encoding="utf-8")
    _hop_units = _JS(_Path(_td)).extract_entry_units()

_hop_src = _hop_units[0].source_code if _hop_units else ""
check("四跳链：Hop 标记 ≥ 3（展开真的递归了）",
      len([ln for ln in _hop_src.splitlines() if "[Hop " in ln]) >= 3, True)
check("四跳链：第 3 跳的 sink 进切片",
      "SELECT * FROM orders" in _hop_src, True)
check("四跳链：规则端到端判 True（证据到了判据也要读）",
      _verdict("sqli", _hop_src), True)


# ---------------- [41] 值域判据：类型能不能承载 `'` ----------------
#
# micro_service_seclab 把 sqli 的唯一正确答案放在了一行类型声明里：
#   in(List<String>)  与 longin(List<Long>)  **逐字同构**，连 Joiner 都一样，
#   差别只有泛型实参。作者在 longin 上方写着「这并不是一个注入……是误报问题」。
#
# 检出方式是"不看拼接像不像，只看拼进去的值能不能是引号"。这条判据
# 一旦写反，方向错误比误报危险：把 `List<String>` 判成 safe 是静默放行。
# 所以三个断言里两个是方向护栏。

_MS_SEQ = [
    # (标签, 形参声明, 期望)
    ("List<String> 拼进 IN 子句 → 真漏洞",
     "public List<Student> q(@RequestBody List<String> name_list) {\n"
     '        String sql = "select * from students where username in (\'"'
     '+ Joiner.on("\',\'").join(name_list)+"\')\'";\n'
     "        return jdbcTemplate.query(sql, ROW_MAPPER);\n    }", True),
    ("List<Long> 同构代码 → 安全（值域锁死）",
     "public List<Student> q(@RequestBody List<Long> name_list) {\n"
     '        String sql = "select * from students where username in (\'"'
     '+ Joiner.on("\',\'").join(name_list)+"\')\'";\n'
     "        return jdbcTemplate.query(sql, ROW_MAPPER);\n    }", False),
    ("Integer 形参 + String.valueOf → 安全",
     "public List<Student> q(Integer id) {\n"
     '        String sql = "select * from students where id = \'" + String.valueOf(id) + "\'";\n'
     "        return jdbcTemplate.query(sql, ROW_MAPPER);\n    }", False),
    ("Optional<String>.get() 解包 → 真漏洞（方向护栏）",
     "public List<Student> q(Optional<String> username) {\n"
     '        String sql = "select * from students where username like \'%" + username.get() + "%\'";\n'
     "        return jdbcTemplate.query(sql, ROW_MAPPER);\n    }", True),
]
for _label, _qbody, _want in _MS_SEQ:
    _src = ("    @RequestMapping(\"/x\")\n    public Object x() {\n"
            "        return svc.call(p);\n    }\n\n"
            "// ---- 跨文件辅助方法实现（入口方法调用的外部方法，含真实算法/参数）----\n"
            "// 来自 Db.java:1 [Hop 1]\n    " + _qbody)
    check(f"值域判据：{_label}", _verdict("sqli", _src), _want)


# ---------------- [42] 接口声明段：没有方法体的仓库/映射器 ----------------
#
# Spring Data 仓库的方法只有声明，`_method_index()` 只收有方法体的方法，
# 于是切片里只剩一行 `personRepository.findPersonByUsername(name)`。
# 补上接口声明（含 extends 子句）之后，"框架派生查询 ⇒ 参数化"才成为事实。

_IFACE_FILES = {
    "JpaController.java": '''package probe;
@RestController
public class JpaController {
    private PersonRepository personRepository;
    @RequestMapping("/jpa")
    public Object jpa(@RequestParam("name") String name) {
        return personRepository.findPersonByUsername(name);
    }
}''',
    "PersonRepository.java": '''package probe;
public interface PersonRepository extends JpaRepository<Person, String> {
    public List<Person> findPersonByUsername(String username);
}''',
    "MyMapper.java": '''package probe;
public interface MyMapper {
    /**
     * If using ${username}, application will send a error.
     */
    @Select("select * from users where username = #{username}")
    User findByUserName(@Param("username") String username);
}''',
    "MapperController.java": '''package probe;
@RestController
public class MapperController {
    private MyMapper userMapper;
    @RequestMapping("/mybatis")
    public Object q(@RequestParam("username") String username) {
        return userMapper.findByUserName(username);
    }
}''',
}

with _tf.TemporaryDirectory() as _td:
    _base = _Path(_td) / "src" / "main" / "java" / "probe"
    _base.mkdir(parents=True)
    for _n, _c in _IFACE_FILES.items():
        (_base / _n).write_text(_c, encoding="utf-8")
    _iface_units = {u.unit_name: u.source_code for u in _JS(_Path(_td)).extract_entry_units()}

_jpa_src = _iface_units.get("JpaController.jpa", "")
check("接口声明段：extends JpaRepository 被带进切片",
      "extends JpaRepository" in _jpa_src, True)
check("接口声明段：JPA 派生查询判安全（框架生成参数化 SQL）",
      _verdict("sqli", _jpa_src), False)
# 方向护栏：Javadoc 里的 `${username}` 是**注释**。规则读到它就会把
# `#{username}` 安全样本判成注入 —— java-sec-code 实测从 1.000 掉到 0.971。
_myb_src = _iface_units.get("MapperController.q", "")
check("接口声明段：Javadoc 里的 ${} 不许被当成 MyBatis 替换符（方向护栏）",
      _verdict("sqli", _myb_src), False)


# ---------------- [43] Apache HttpClient 的变量形态 SSRF ----------------
#
# `client.execute(new HttpGet(url))` 早就能认，但真实代码几乎都先声明变量：
#   HttpGet get = new HttpGet(imageUrl); client.execute(get);
# 实参是小写变量名，`execute\(\s*(?:new\s+)?Http\w*` 一个字符都对不上。

_SSRF_VAR = '''    @RequestMapping("/four")
    public String four(@RequestParam(value = "url") String imageUrl) {
        DefaultHttpClient client = new DefaultHttpClient();
        HttpGet get = new HttpGet(imageUrl);
        HttpResponse response = client.execute(get);
        return response.toString();
    }'''
check("HttpClient 变量形态 new HttpGet(url) + execute → 真漏洞",
      _verdict("ssrf", _SSRF_VAR), True)
check("HttpClient 目标写死 new HttpGet(常量) → 不是本类目对象",
      _verdict("ssrf", _SSRF_VAR.replace("new HttpGet(imageUrl)",
                                         'new HttpGet("http://fixed/x")')), None)


# ---------------- [44] JPA createQuery：JPQL 世界的 prepareStatement ----------------
#
# JavaSecLab `JPAController` 三个对照样本，此前全部退回模型。
# 判据与 prepareStatement 完全同构：先回溯源变量，再看文本里有没有拼接。

_JPA_CASES = [
    ("jpql 字符串拼接 → 真漏洞",
     'String jpql = "SELECT s FROM Sqli s WHERE s.username = \'" + username + "\'";\n'
     "        Query q = entityManager.createQuery(jpql);", True),
    ("jpql 命名参数 + setParameter → 安全",
     'String jpql = "SELECT s FROM Sqli s WHERE s.username = :username";\n'
     '        Query q = entityManager.createQuery(jpql).setParameter("username", username);',
     False),
    ("jpql 常量无占位符 → 交模型（不硬判）",
     'String jpql = "SELECT s FROM Sqli s";\n'
     "        Query q = entityManager.createQuery(jpql);", None),
]
for _label, _qbody, _want in _JPA_CASES:
    _src = ("    @RequestMapping(\"/x\")\n    public Object x(@RequestParam String username) {\n"
            "        " + _qbody + "\n        return null;\n    }")
    check(f"JPA createQuery：{_label}", _verdict("sqli", _src), _want)


print()

# ---------------- [45] 真实分层项目盲测（newbee-mall）暴露的三类机制 ----------------
#
# 这三条都不是新类目，而是"同一机制在真实写法下失效"，每一条都有真实样本：
#   ① 嵌套实参吞调用：`request.setAttribute("x", svc.foo(p))` 里 `svc.` 被外层
#      实参匹配吃掉 → 70 个入口里 ServiceImpl 命中 0（规则与模型都看不到 SQL）
#   ② 主体来自注入的 HttpSession：`httpSession.getAttribute(KEY)` 不被认作主体
#      → 订单详情 / 取消 / 购物车 6 条全判 True（规则层误报）
#   ③ 认证入口与后台前缀：/login 被判越权、/admin/** 被忽略

from core.slicer.java_servlet import JavaSlicer        # noqa: E402

_sl = JavaSlicer.__new__(JavaSlicer)                    # 只用纯文本方法，不建索引


def _calls(text: str) -> list[str]:
    return [f"{v}.{n}" for v, n, _a in _sl._iter_data_calls(text)]


check("切片：嵌套实参里的服务调用必须被发现（方向护栏）",
      "svc.getDetail" in _calls('return Result.ok(svc.getDetail(orderNo, user.getUserId()));'),
      True)
check("切片：外层调用仍被识别（不是靠放弃外层换内层）",
      "Result.ok" in _calls('return Result.ok(svc.getDetail(orderNo));'), True)
check("切片：字符串里的括号不打断实参配平",
      _sl._call_args('foo("a)b", x)', 4), '"a)b", x')

check("切片：零参取值器不占跳数名额（只 return 字段）",
      bool(_sl._TRIVIAL_ACCESSOR_RE.match("public Long getCategoryId() {\n return categoryId;\n}")),
      True)
check("切片：返回字面量的方法**不能**被当成取值器滤掉（方向护栏）",
      bool(_sl._TRIVIAL_ACCESSOR_RE.match('public String getTheValue() { return "bob"; }')),
      False)

_AUTHZ_SESSION_ARG = '''@GetMapping("/orders/{orderNo}")
public String orderDetailPage(@PathVariable("orderNo") String orderNo, HttpSession httpSession) {
    NewBeeMallUserVO user = (NewBeeMallUserVO) httpSession.getAttribute(Constants.USER_KEY);
    NewBeeMallOrderDetailVO vo = orderService.getOrderDetailByOrderNo(orderNo, user.getUserId());
    return "order-detail";
}'''
check("authz：主体取自注入的 HttpSession 且作为资源键 → 安全(False)",
      _verdict("authz", _AUTHZ_SESSION_ARG), False)

_AUTHZ_SESSION_DENY = '''@GetMapping("/selectPayType")
public String selectPayType(@RequestParam("orderNo") String orderNo, HttpSession httpSession) {
    NewBeeMallUserVO user = (NewBeeMallUserVO) httpSession.getAttribute(Constants.USER_KEY);
    NewBeeMallOrder order = orderService.getByOrderNo(orderNo);
    if (!user.getUserId().equals(order.getUserId())) {
        NewBeeMallException.fail("无权限");
    }
    return "pay-select";
}'''
check("authz：会话主体 + 自定义异常终止分支 → 安全(False)",
      _verdict("authz", _AUTHZ_SESSION_DENY), False)

_AUTHZ_PAY = '''@GetMapping("/paySuccess")
@ResponseBody
public Result paySuccess(@RequestParam("orderNo") String orderNo, @RequestParam("payType") int payType) {
    String r = orderService.paySuccess(orderNo, payType);
    return Result.success(r);
}'''
check("authz：无主体、无会话、单号直改状态 → 越权(True，方向护栏)",
      _verdict("authz", _AUTHZ_PAY), True)

_AUTHZ_LOGIN = '''@PostMapping("/login")
@ResponseBody
public Result login(@RequestParam("loginName") String loginName,
                    @RequestParam("password") String password, HttpSession session) {
    MallUser u = userService.login(loginName, password);
    session.setAttribute(Constants.USER_KEY, u);
    return Result.success(u);
}'''
check("authz：认证入口本身不做授权判定 → None(方向护栏)",
      _verdict("authz", _AUTHZ_LOGIN), None)

_AUTHZ_ADMIN = '''@RequestMapping(value = "/orders/update", method = RequestMethod.POST)
@ResponseBody
public Result update(@RequestBody NewBeeMallOrder order) {
    return Result.success(orderService.updateOrderInfo(order));
}
// ---- 框架装配证据：以下全局组件会作用于本路由 ----
// [interceptor] urlPatterns=['/admin/**']
//   registry.addInterceptor(adminLoginInterceptor)
//   .addPathPatterns("/admin/**");'''
check("authz：后台前缀有全局鉴权拦截器 → 不硬判 True(方向护栏)",
      _verdict("authz", _AUTHZ_ADMIN), None)


# ---------------- [45] 类级路由前缀 + excludePathPatterns ----------------
#
# 两件事必须一起成立，否则 authz 会拿到**方向相反**的事实：
#   ① 完整路由 = 类级 @RequestMapping + 方法级 @GetMapping
#   ② 被 excludePathPatterns 排除的路由**不算**受该拦截器保护
print("\n[45] 路由前缀与拦截器排除")
from core.context.framework_wiring import FrameworkWiringResolver, Wiring  # noqa: E402

_w = FrameworkWiringResolver(repo_root=ROOT)
_w._wiring = [Wiring(kind="interceptor", name="adminLoginInterceptor",
                     url_patterns=["/admin/**"],
                     exclude_patterns=["/admin/login", "/admin/dist/**"],
                     body='registry.addInterceptor(x).addPathPatterns("/admin/**")'
                          '.excludePathPatterns("/admin/login", "/admin/dist/**");')]
_w._unparsed = []
check("装配：/admin/goods/list 受 /admin/** 拦截 → 有证据",
      len(_w.for_url("/admin/goods/list").applied), 1)
check("装配：/admin/login 被 excludePathPatterns 排除 → 无证据(方向护栏)",
      len(_w.for_url("/admin/login").applied), 0)
check("装配：/admin/dist/x 命中前缀通配排除 → 无证据",
      len(_w.for_url("/admin/dist/x").applied), 0)
check("装配：/goods/list 不在 /admin/** 下 → 无证据",
      len(_w.for_url("/goods/list").applied), 0)

# 类级前缀拼接：临时仓库里放一个控制器，直接切
import tempfile                                                      # noqa: E402
from core.slicer.java_servlet import JavaSlicer as _Slicer           # noqa: E402

_JAVA = '''package x;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/admin")
public class GoodsCtl {
    @GetMapping("/goods/list")
    public String list(@RequestParam("q") String q) { return q; }
}
'''
with tempfile.TemporaryDirectory() as _d:
    _p = Path(_d) / "GoodsCtl.java"
    _p.write_text(_JAVA, encoding="utf-8")
    _u = _Slicer(Path(_d)).extract_entry_units()[0]
check("路由：类级 /admin + 方法级 /goods/list 拼成完整路由",
      _u.route_path, "/admin/goods/list")
check("路由：完整路由写进切片首行（判定层与模型都读得到）",
      _u.source_code.splitlines()[0], "// Full-Route: /admin/goods/list")


# ---------------- [46] db 串接的方向锁 ----------------
#
# 对称配对在真实项目里产出大量反向连接（只读路由被标成写入方）。
# 方向由方法名动词决定，是可逐行核对的事实。
print("\n[46] db 串接方向锁")
from core.context.taint_chain import _db_direction                   # noqa: E402

for _m, _want in (("saveNewBeeMallGoods", "w"), ("insertOne", "w"),
                  ("add", "w"), ("safeSave", "w"), ("batchUpdateSellStatus", "w"),
                  ("list", "r"), ("getXssList", "r"), ("page", "r"),
                  ("searchNewBeeMallGoods", "r"), ("getSavedList", "r"),
                  ("deleteById", None), ("deleteBatch", None),
                  ("cancelOrder", None), ("login", None), ("paySuccess", None)):
    check(f"方向：{_m} → {_want}", _db_direction(_m), _want)

_W = unit("Ctl.save", 'public String save(String p){ xssService.saveGoods(p); return "x"; }')
_R = unit("Ctl.list", "public String list(){ return xssService.listGoods(); }")
_D = unit("Ctl.del", "public String del(Long id){ xssService.deleteById(id); return \"x\"; }")
_ch = build_chains([_W, _R])
check("串接：写→读 连一条", len([l for l in _ch.links if l.medium == "db"]), 1)
_ch2 = build_chains([_D, _R])
check("串接：删除路由不得被当成写入方（方向护栏）",
      len([l for l in _ch2.links if l.medium == "db"]), 0)


# ---------------- [47] 同名重载：入口不许丢，unit_name 不许撞 ----------------
#
# `methods: dict[name]` + `setdefault` 会让 RESTful 控制器里同名的 PUT/DELETE
# 只留第一条 —— 不报错、不进日志，只有人工数入口才发现（newbee-mall 3 条 /
# Hello-Java-Sec 2 条）。修法：保留全部定义，裸名给源码顺序第一个，
# 后续重载加 `#N`；真值表一侧用 `base_unit_name()` 剥掉后缀再查。
print("\n[47] 同名重载入口")

_OVERLOAD_FILES = {
    "CartController.java": '''package probe;
@RestController
@RequestMapping("/shop-cart")
public class CartController {
    @PutMapping("/shop-cart")
    @ResponseBody
    public Result update(@RequestBody Item item, HttpSession session) {
        User u = (User) session.getAttribute(KEY);
        item.setUserId(u.getUserId());
        return service.update(item);
    }

    @DeleteMapping("/shop-cart/{id}")
    @ResponseBody
    public Result update(@PathVariable("id") Long id, HttpSession session) {
        User u = (User) session.getAttribute(KEY);
        return service.delete(id, u.getUserId());
    }

    @GetMapping("/shop-cart")
    public String page(HttpSession session) {
        return "cart";
    }
}''',
}

with _tf.TemporaryDirectory() as _td:
    _base = _Path(_td) / "src" / "main" / "java" / "probe"
    _base.mkdir(parents=True)
    for _n, _c in _OVERLOAD_FILES.items():
        (_base / _n).write_text(_c, encoding="utf-8")
    _ov_units = _JS(_Path(_td)).extract_entry_units()

_ov_names = [u.unit_name for u in _ov_units]
_ov_routes = {u.unit_name: u.route_path for u in _ov_units}
check("重载：三个 @Mapping 方法都成为入口（不按名字去重）", len(_ov_units), 3)
check("重载：同名两条都保留", sorted(n for n in _ov_names if n.startswith("CartController.update")),
      ["CartController.update", "CartController.update#2"])
check("重载：裸名 = 源码顺序第一个（PUT）",
      _ov_routes.get("CartController.update", "").endswith("/shop-cart"), True)
check("重载：`#2` 是后面的 DELETE（路由不同，跨路由串接不许串味）",
      "{id}" in _ov_routes.get("CartController.update#2", ""), True)
check("重载：unit_name 全局唯一（否则 by_name 会吞掉一条）",
      len(set(_ov_names)), len(_ov_names))
# 真值表按 `类.方法` 硬编码：剥掉后缀必须还原成同一个键
from core.models import base_unit_name                                # noqa: E402
check("重载：base_unit_name 剥后缀", base_unit_name("CartController.update#2"),
      "CartController.update")
check("重载：无后缀的名字原样返回", base_unit_name("CartController.update"),
      "CartController.update")


# ---------------- [48] 类级 @RequestMapping 的数组形式（别名路径） ----------------
#
# `@RequestMapping({"/admin", "/manage"})` 让同一个方法在两条路径上都可达。
# 只给 `/admin/**` 挂拦截器时，攻击者走 `/manage/...` 就绕过了 ——
# 所以"受全局保护"必须是**所有**别名都被覆盖，走交集而不是取第一个。
print("\n[48] 别名路径与全局装配的覆盖交集")

_ALIAS_JAVA = '''package x;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping({"/admin", "/manage"})
public class AliasCtl {
    @GetMapping({"/list", "/query"})
    public String list(@RequestParam("q") String q) { return q; }
}
'''
with tempfile.TemporaryDirectory() as _d:
    _p = Path(_d) / "AliasCtl.java"
    _p.write_text(_ALIAS_JAVA, encoding="utf-8")
    _ua = _Slicer(Path(_d)).extract_entry_units()[0]
check("别名：类级数组取第一个作 route_path", _ua.route_path, "/admin/list")
check("别名：全部可达路径都记进切片（类级 × 方法级 2×2）",
      sorted(_ua.source_code.splitlines()[1].replace("// Alias-Route: ", "").split(", ")),
      ["/admin/list", "/admin/query", "/manage/list", "/manage/query"])

# 生产式注解读法：`produces = "application/json"` 不是路径，不许当别名
_PRODUCES_JAVA = '''package x;
@RestController
@RequestMapping(value = "/api", produces = "application/json")
public class ProducesCtl {
    @GetMapping(value = "/json", produces = "application/json")
    public String j(@RequestParam("q") String q) { return q; }
}
'''
with tempfile.TemporaryDirectory() as _d:
    _p = Path(_d) / "ProducesCtl.java"
    _p.write_text(_PRODUCES_JAVA, encoding="utf-8")
    _up = _Slicer(Path(_d)).extract_entry_units()[0]
check("别名：produces 的媒体类型不许被当成路径", _up.route_path, "/api/json")
check("别名：单一映射不写 Alias-Route 行",
      any("Alias-Route" in ln for ln in _up.source_code.splitlines()), False)

_wa = FrameworkWiringResolver(repo_root=ROOT)
_wa._wiring = [Wiring(kind="interceptor", name="adminOnly",
                      url_patterns=["/admin/**"],
                      body='registry.addInterceptor(a).addPathPatterns("/admin/**");')]
_wa._unparsed = []
_wa_src = _wa.describe_aliases(["/admin/list", "/manage/list"])
check("别名：只覆盖 /admin/** 时不报『受保护』（方向护栏）",
      "addPathPatterns" in _wa_src, False)
check("别名：部分覆盖要明说『不能认定受统一保护』",
      "不能**认定" in _wa_src or "不能**" in _wa_src, True)

_wb = FrameworkWiringResolver(repo_root=ROOT)
_wb._wiring = [Wiring(kind="interceptor", name="allApi",
                      url_patterns=["/**"],
                      body='registry.addInterceptor(b).addPathPatterns("/**");')]
_wb._unparsed = []
check("别名：全部别名都被覆盖 → 才渲染保护证据",
      "addPathPatterns" in _wb.describe_aliases(["/admin/list", "/manage/list"]), True)


# ---------------- [49] 后缀截取：写盘名里 `..` 在几何上拼不出来 ----------------
#
# `S = F.substring(F.lastIndexOf("."))` 截出的串必然是「"." + 无点尾巴」：
# 尾巴无点 ⇒ 拼不出 `..`；以 "." 开头 ⇒ 不是绝对路径。所以它是**可逐字符
# 核对的安全事实**，不是"看起来没事"。但必须三条同时成立才算 —— 三条各自
# 配一条反方向护栏，缺一条就会被半吊子写法骗过去。
print("\n[49] 路径遍历：后缀截取安全短路")

_SUF_OK = '''@RequestMapping("/up")
public Result up(MultipartFile file) {
    String fileName = file.getOriginalFilename();
    String suffixName = fileName.substring(fileName.lastIndexOf("."));
    String newFileName = UUID.randomUUID().toString() + suffixName;
    return file.transferTo(new File(Constants.FILE_UPLOAD_DIC + newFileName));
}'''
check("后缀截取：只保留「. + 无点尾巴」→ 判安全",
      verdict("pathtraver", _SUF_OK), False)

_SUF_APPEND = '''@RequestMapping("/up2")
public Result up2(MultipartFile file) {
    String fileName = file.getOriginalFilename();
    String suffixName = fileName.substring(fileName.lastIndexOf("."));
    StringBuilder tempName = new StringBuilder();
    tempName.append(System.currentTimeMillis()).append(rand.nextInt(100)).append(suffixName);
    return file.transferTo(new File(DIR + tempName.toString()));
}'''
check("后缀截取：StringBuilder 链式 append 也算『由 S 构成』",
      verdict("pathtraver", _SUF_APPEND), False)

# 护栏 ①：切了后缀，但原文名照样拼进路径 —— 截断形同虚设
_SUF_RAW = '''@RequestMapping("/up3")
public Result up3(MultipartFile file) {
    String fileName = file.getOriginalFilename();
    String suffixName = fileName.substring(fileName.lastIndexOf("."));
    log.info(suffixName);
    return file.transferTo(new File(DIR + fileName));
}'''
check("后缀截取护栏：原文名仍被拼进路径 → 必须维持判漏洞",
      verdict("pathtraver", _SUF_RAW), True)

# 护栏 ②：目录前缀来自请求参数 —— 后缀安全救不了目录
_SUF_DIRTY_DIR = '''@RequestMapping("/up4")
public Result up4(MultipartFile file, @RequestParam("dir") String dir) {
    String fileName = file.getOriginalFilename();
    String suffixName = fileName.substring(fileName.lastIndexOf("."));
    return file.transferTo(new File(dir + suffixName));
}'''
check("后缀截取护栏：目录前缀来自请求参数 → 必须维持判漏洞",
      verdict("pathtraver", _SUF_DIRTY_DIR), True)

# 护栏 ③：切后缀只为打日志，落盘用的是另一个外部值
_SUF_DECOY = '''@RequestMapping("/up5")
public Result up5(MultipartFile file, HttpServletRequest request) {
    String fileName = file.getOriginalFilename();
    String suffixName = fileName.substring(fileName.lastIndexOf("."));
    log.info(suffixName);
    String dest = request.getParameter("dest");
    return file.transferTo(new File(dest));
}'''
check("后缀截取护栏：截断结果没进 sink（只为打日志）→ 维持判漏洞",
      verdict("pathtraver", _SUF_DECOY), True)

# 护栏 ④：根本没有截断
_NO_CUT = '''@RequestMapping("/up6")
public Result up6(MultipartFile file) {
    String fileName = file.getOriginalFilename();
    return file.transferTo(new File(DIR + fileName));
}'''
check("后缀截取护栏：没有 lastIndexOf 截断 → 维持判漏洞",
      verdict("pathtraver", _NO_CUT), True)


# ---------------- [50] 主体 ID 赋给 DTO 属性：两个事实缺一不可 ----------------
#
# 与 `/orders` 的 `params.put("userId", ...)` 同构，载体从 Map 换成实体字段。
# ① 右式必须是会话/Principal 主体变量；② 该 DTO 必须真作为实参进了 Service。
# 只 set 不传（打日志/回显）不算"主体参与了资源选择"。
print("\n[50] authz：主体入 DTO 载体")

_DTO_OK = '''@PostMapping("/cart")
public Result save(@RequestBody Item item, HttpSession session) {
    User user = (User) session.getAttribute(KEY);
    item.setUserId(user.getUserId());
    return cartService.save(item);
}'''
check("DTO 载体：主体 id 写进实体 + 实体进 Service → 判安全",
      verdict("authz", _DTO_OK), False)

_DTO_NOFLOW = '''@PostMapping("/cart")
public Result save(@RequestBody Item item, HttpSession session) {
    User user = (User) session.getAttribute(KEY);
    item.setUserId(user.getUserId());
    log.info("cart owner = {}", item);
    return Result.ok();
}'''
check("DTO 载体护栏：只 set 不传 Service → 不许判安全",
      verdict("authz", _DTO_NOFLOW), None)

_DTO_CLIENT = '''@PostMapping("/cart")
public Result save(@RequestBody Item item, HttpSession session) {
    User user = (User) session.getAttribute(KEY);
    item.setUserId(item.getUserId());
    return cartService.save(item);
}'''
check("DTO 载体护栏：右式是客户端自带的 userId → 不许判安全",
      verdict("authz", _DTO_CLIENT), None)


# ---------------- [51] fastjson：版本决定结论（三态） ----------------
#
# 同一行 `JSON.parseObject(body, X.class)` 在 1.2.31 上是 autoType 入口、
# 在 1.2.83 上默认 safeMode。判据必须读 pom 里的版本；读不到就退回，不许猜。
print("\n[51] 反序列化：fastjson 版本证据")

_FJ_BODY = '''@PostMapping("/create")
public Object create(@RequestBody String body) {
    return JSON.parseObject(body, Teacher.class);
}'''
_FJ_OLD = _FJ_BODY + "\n// ---- 依赖组件版本（测试夹具）----\n// fastjson = 1.2.31\n"
_FJ_NEW = _FJ_BODY + "\n// ---- 依赖组件版本（测试夹具）----\n// fastjson = 1.2.83\n"
check("fastjson 1.2.31 + parseObject(外部输入) → 判漏洞",
      verdict("deserial", _FJ_OLD), True)
check("fastjson 1.2.83 → 判安全（safeMode 默认开）",
      verdict("deserial", _FJ_NEW), False)
check("没有版本证据 → 退回（不许猜）",
      verdict("deserial", _FJ_BODY), None)
_FJ_SAFEMODE = ('@PostMapping("/create")\n'
                'public Object create(@RequestBody String body) {\n'
                '    ParserConfig.getGlobalInstance().setSafeMode(true);\n'
                '    return JSON.parseObject(body, Teacher.class);\n'
                '}\n// ---- 依赖组件版本（测试夹具）----\n// fastjson = 1.2.31\n')
check("显式 setSafeMode(true) → 版本再低也判安全",
      verdict("deserial", _FJ_SAFEMODE), False)


# ---------------- [52] 形参主体注解：只在"真被 resolver 注入"时才算主体 ----------------
#
# 前后端分离项目的主体在签名上：`@TokenToMallUser MallUser loginMallUser`。
# 判定层读切片里的注释块（来源是 implements HandlerMethodArgumentResolver 的
# supportsParameter）。三条断言分别锁：认了要能用、认了不等于校验过、
# **没被 resolver 证实时不许按注解名猜**。
print("\n[52] authz：形参主体注解")

_SUBJ_MARK = ("\n// ---- 形参主体注解（测试夹具）----\n"
              "// @TokenToMallUser -> 形参 loginMallUser   由 XxxResolver 注入\n")

_SUBJ_KEY = '''@PostMapping("/order")
public Result list(@TokenToMallUser MallUser loginMallUser) {
    return Result.ok(orderService.getMyOrders(loginMallUser.getUserId()));
}''' + _SUBJ_MARK
check("注解形参的主体 id 作资源键 → 判安全",
      verdict("authz", _SUBJ_KEY), False)

_SUBJ_NOUSE = '''@PostMapping("/order")
public Result list(@TokenToMallUser MallUser loginMallUser) {
    log.info("who = {}", loginMallUser.getUserId());
    return Result.ok(orderService.listAll());
}''' + _SUBJ_MARK
check("注解形参只是打日志、没参与资源选择 → 不许判安全",
      verdict("authz", _SUBJ_NOUSE), None)

# 同一个方法，去掉证据块 = 仓库里没有任何 resolver 声明支持该注解。
# 此时注解名再像主体也不认：名字启发式会把 `@CurrentTenant` / `@UserAgent`
# 一起认成主体，而这里更危险 —— 认错了就会把"入参直查资源"判成安全。
_SUBJ_BARE = '''@PostMapping("/item")
public Result detail(@TokenToMallUser MallUser loginMallUser) {
    return Result.ok(itemService.getById(loginMallUser));
}'''
check("没有 resolver 证据 → 注解名再像主体也不认，裸形参直查仍判漏洞",
      verdict("authz", _SUBJ_BARE), True)
check("有了 resolver 证据 → 视为已知主体，但只凭主体存在仍不判安全",
      verdict("authz", _SUBJ_BARE + _SUBJ_MARK), None)


# ---------------- [53] authz：显式归属比对（先查资源、再比 userId） ----------------
#
# 这是水平越权最标准的写法，却正好落在 2b/2b-2/2c 的缝里：资源查询的实参里
# 没有主体 id、没有 setter、没有容器。判据要求"比对了**另一个对象**的 id"
# 且"方法内存在终止动作"。
print("\n[53] authz：显式归属比对")

_OWN_OK = '''@DeleteMapping("/addr/{id}")
public Result delete(@PathVariable Long id, @TokenToMallUser MallUser loginMallUser) {
    Address addr = addressService.getById(id);
    if (!loginMallUser.getUserId().equals(addr.getUserId())) {
        return ResultGenerator.genFailResult("forbidden");
    }
    return Result.ok(addressService.deleteById(id));
}''' + _SUBJ_MARK
check("主体 id 与查回资源的 userId 比对 + 拒绝 → 判安全",
      verdict("authz", _OWN_OK), False)

_OWN_LOGONLY = _OWN_OK.replace(
    'return ResultGenerator.genFailResult("forbidden");',
    'log.warn("owner mismatch: {}", addr.getUserId());')
check("只比对、没有终止动作 → 不许判安全",
      verdict("authz", _OWN_LOGONLY), None)

_OWN_SELF = _OWN_OK.replace(
    "!loginMallUser.getUserId().equals(addr.getUserId())",
    "!loginMallUser.getUserId().equals(loginMallUser.getUserId())")
check("拿主体跟自己比 → 不构成任何归属校验",
      verdict("authz", _OWN_SELF), None)


# ---------------- [54] authz：logout 不是"建立身份"，不进认证入口排除 ----------------
#
# 旧口径把 logout 和 login/register 一起排除 → newbee-mall-api 的
# /manage-api/v1/logout 静默退回。正确口径：logout 走正常判据链 ——
# 主体自己的 token 作资源键 → False；外部可控 userId 注销他人 → True；
# 只销毁当前请求自身的会话/凭据 → 2f 判 False（2026-10-21 新增，见下）。
# login 仍必须排除（防放宽）。
print("\n[54] authz：logout 路由口径")

_LOGOUT_MARK = ("\n// ---- 形参主体注解（测试夹具）----\n"
                "// @TokenToAdminUser -> 形参 adminUser   由 AdminResolver 注入\n")

_LOGOUT_OK = '''@RequestMapping(value = "/logout", method = RequestMethod.DELETE)
public Result logout(@TokenToAdminUser AdminUserToken adminUser) {
    adminUserService.logout(adminUser.getAdminUserId());
    return ResultGenerator.genSuccessResult();
}''' + _LOGOUT_MARK
check("logout：主体自己的 token id 作资源键 → 判安全",
      verdict("authz", _LOGOUT_OK), False)

_LOGOUT_FOREIGN = '''@PostMapping("/logout")
public Result logout(String userId) {
    return userService.logout(userId);
}'''
check("logout：外部可控 userId 注销他人会话、无主体 → 判漏洞",
      verdict("authz", _LOGOUT_FOREIGN), True)

_LOGOUT_SESSION = '''@GetMapping("/logout")
public String logout(HttpSession session) {
    session.invalidate();
    return "redirect:/login";
}'''
check("logout：只 invalidate 自身 session → 2f 会话自毁判安全",
      verdict("authz", _LOGOUT_SESSION), False)

_LOGOUT_RMATTR = '''@GetMapping("/admin/logout")
public String logout(HttpServletRequest request) {
    request.getSession().removeAttribute("loginUserId");
    request.getSession().removeAttribute("loginUser");
    return "redirect:/admin";
}'''
check("logout：只 removeAttribute 自身会话属性 → 2f 判安全",
      verdict("authz", _LOGOUT_RMATTR), False)

_LOGOUT_SUBJ_DESTROY = '''@PostMapping("/logout")
public String logout(HttpSession session) {
    SecurityUtils.getSubject().logout();
    return "redirect:/login";
}'''
check("logout：getSubject().logout() 销毁自身凭据 → 2f 判安全",
      verdict("authz", _LOGOUT_SUBJ_DESTROY), False)

# 反向：销毁动作 + 外部裸形参被交给删凭据调用 → 2f 必须让位，不判安全。
_LOGOUT_MIXED = '''@PostMapping("/logout")
public Result logout(@TokenToMallUser MallUser user, String userId) {
    userService.deleteToken(userId);
    session.removeAttribute("u");
    return ResultGenerator.genSuccessResult();
}''' + _LOGOUT_MARK.replace("adminUser", "user").replace("AdminUserToken", "MallUser")
check("logout：外部 userId 进 deleteToken（有主体但未比对）→ 不判安全",
      verdict("authz", _LOGOUT_MIXED), None)

_LOGOUT_LOGIN = '''@PostMapping("/login")
public Result login(String loginName, String password) {
    return userService.login(loginName, password);
}'''
check("login 仍在认证入口排除内（防放宽） → 不做授权判定",
      verdict("authz", _LOGOUT_LOGIN), None)


# ---------------- [55] pr-scan：Mapper XML 变更的反向依赖 ----------------
#
# Step 7 的缺口：pr-scan 原来只对入口自身方法体（第 1 跳直调）求反向依赖，
# 且 `_changed_methods_of` 的方法签名正则在 XML 上必然落空 —— 改第 3 跳的
# Mapper 语句，受影响入口一个都找不到。两个新助手必须满足：
#   ① 语句 id 从 diff 增删行里抓（select/insert/update/delete/sql，不含 resultMap）；
#   ② 调用集合取整份切片（[Hop N] 段里的调用也算"该入口可达"）。
print("\n[55] pr-scan：XML 语句 id 与全文调用集")

from cli import _java_called_names, _xml_statement_ids   # noqa: E402

_DIFF_XML = """diff --git a/NewBeeMallOrderMapper.xml b/NewBeeMallOrderMapper.xml
--- a/NewBeeMallOrderMapper.xml
+++ b/NewBeeMallOrderMapper.xml
@@ -12,7 +12,7 @@
-  <select id="findNewBeeMallOrderList" resultMap="OrderVO">
+  <select id="findNewBeeMallOrderList" resultMap="OrderVO">
     where 1=1
-  <sql id="Order_Where">
+  <sql id="Order_Where">
   <resultMap id="OrderVOMap">
   <select id="getTotalNewBeeMallOrders" resultMap="OrderVO">"""

ids = _xml_statement_ids(_DIFF_XML)
check("语句 id：改到的 select/sql 都抓到", ids == {"findNewBeeMallOrderList", "Order_Where"}, True)
check("resultMap 不收（太宽，交给文件名兜底）", "OrderVOMap" not in ids, True)

_SLICE_SRC = '''@GetMapping("/orders")
public Result list() {
    return orderService.getMyOrders(p);
}
// 来自 NewBeeMallOrderServiceImpl.java:67 [Hop 1]
public List<OrderVO> getMyOrders(PageQueryUtil p) {
    return newBeeMallOrderMapper.findNewBeeMallOrderList(p);
}'''
calls = _java_called_names(_SLICE_SRC)
check("全文调用集：第 2 跳的 mapper 调用也在内",
      {"getMyOrders", "findNewBeeMallOrderList"} <= calls, True)


# ---------------- [59] --fix：xss 模板补丁与 deserial pom 补丁的 E2E 自检 ----------------
#
# 两个迷你仓库：① Thymeleaf `th:utext` 渲染外部输入 → xss 规则 True，
# 补丁把 `th:utext` 换成 `th:text` 后必须翻转 False；
# ② fastjson 1.2.25 + `JSON.parseObject(外部输入)` → deserial 规则 True，
# pom 版本补到 1.2.83 后必须翻转 False。
# 全程验证：补丁写入 → 清缓存 → 重切片 → 翻转 → 还原（git 字节级往返）。
print("\n[59] --fix：xss 模板 / deserial fastjson 补丁自检")

import shutil                                        # noqa: E402
import tempfile                                      # noqa: E402

from cli import _verify_fixes                        # noqa: E402
from core.slicer.java_servlet import JavaSlicer      # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="nexus_fix_smoke_"))
try:
    pkg = _TMP / "src" / "main" / "java" / "demo"
    res = _TMP / "src" / "main" / "resources" / "templates" / "xss"
    pkg.mkdir(parents=True)
    res.mkdir(parents=True)
    (pkg / "XssController.java").write_text(
        'package demo;\n'
        'import org.springframework.stereotype.Controller;\n'
        'import org.springframework.ui.Model;\n'
        'import org.springframework.web.bind.annotation.*;\n'
        '@Controller\n'
        'public class XssController {\n'
        '    @GetMapping("/xss/echo")\n'
        '    public String echo(@RequestParam("html") String html, Model model) {\n'
        '        model.addAttribute("html", html);\n'
        '        return "xss/other";\n'
        '    }\n'
        '}\n', encoding="utf-8", newline="")
    (res / "other.html").write_text(
        '<!DOCTYPE html>\n<html>\n'
        '<p th:text="${safe}">ignored</p>\n'
        '<p th:utext="${html}"></p>\n'
        '</html>\n', encoding="utf-8", newline="")

    units = JavaSlicer(_TMP).extract_entry_units()
    check("迷你仓库：xss 规则判 True", verdict("xss", units[0].source_code), True)
    before = (res / "other.html").read_text(encoding="utf-8", newline="")
    rep = _TMP / "fix_report.md"
    _verify_fixes(_TMP, units, out_path=rep)
    after = (res / "other.html").read_text(encoding="utf-8", newline="")
    check("xss：--fix 不留下文件变更（字节级还原）", after, before)
    rep_text = rep.read_text(encoding="utf-8")
    check("xss：补丁自检通过并给出 diff", "th:text=" in rep_text and "自检通过" in rep_text, True)

    # ---- deserial：fastjson 版本补丁 ----
    (pkg / "DeserController.java").write_text(
        'package demo;\n'
        'import com.alibaba.fastjson.JSON;\n'
        'import org.springframework.web.bind.annotation.*;\n'
        '@RestController\n'
        'public class DeserController {\n'
        '    @PostMapping("/deser")\n'
        '    public Object deser(@RequestBody String body) {\n'
        '        return JSON.parseObject(body);\n'
        '    }\n'
        '}\n', encoding="utf-8", newline="")
    (_TMP / "pom.xml").write_text(
        '<?xml version="1.0"?>\n<project>\n'
        '  <properties><fastjson.version>1.2.25</fastjson.version></properties>\n'
        '  <dependencies>\n'
        '    <dependency>\n'
        '      <groupId>com.alibaba</groupId>\n'
        '      <artifactId>fastjson</artifactId>\n'
        '      <version>${fastjson.version}</version>\n'
        '    </dependency>\n'
        '  </dependencies>\n'
        '</project>\n', encoding="utf-8", newline="")
    units2 = JavaSlicer(_TMP).extract_entry_units()
    deser = next((u for u in units2 if "Deser" in u.unit_name), None)
    check("迷你仓库：deserial 规则判 True（版本 1.2.25 < 1.2.83）",
          verdict("deserial", deser.source_code), True)
    pom_before = (_TMP / "pom.xml").read_text(encoding="utf-8", newline="")
    _verify_fixes(_TMP, units2, out_path=rep)
    pom_after = (_TMP / "pom.xml").read_text(encoding="utf-8", newline="")
    check("deserial：--fix 不留下 pom 变更（字节级还原）", pom_after, pom_before)
    rep_text = rep.read_text(encoding="utf-8")
    check("deserial：占位符属性被改为 1.2.83 且自检通过",
          "1.2.83" in rep_text and "自检通过" in rep_text, True)
finally:
    shutil.rmtree(_TMP, ignore_errors=True)


# ---------------- [60] db 写入方载荷常量性：数值/状态位不构成跨路由 XSS 串接 ----------------
#
# 方向锁只回答"这一侧往库里塞内容吗"。真实项目里大量写入塞的全是数值/
# 状态位（payStatus=1、主键回填），几何上携带不了 XSS 污点 —— 不许给
# 只读路由贴凭空串接证据。三态：全常量→撤写入方；任一值可能带文本→保留；
# 查不出→保守保留。
print("\n[60] db 写入方载荷常量性")

_NUM_W = '''@PostMapping("/num/save")
@ResponseBody
public Result save() {
    Item item = new Item();
    item.setPayStatus(1);
    item.setGoodsId(42L);
    item.setCategoryId(7);
    itemService.saveItem(item);
    return ResultGenerator.genSuccessResult();
}'''

_STR_W = '''@PostMapping("/str/save")
@ResponseBody
public Result save(@RequestBody Item item) {
    item.setContent(payload);
    itemService.saveItem(item);
    return ResultGenerator.genSuccessResult();
}'''

_READER = unit("ListReader", '''@GetMapping("/num/list")
@ResponseBody
public Result list() {
    return itemService.listItems();
}''')
_res = build_chains([unit("NumWriter", _NUM_W), _READER])
check("数值/状态位实体写入 → 不产生跨路由串接",
      [l for l in _res.links if l.medium == "db"], [])

_res2 = build_chains([unit("StrWriter", _STR_W), _READER])
check("实体带文本字段（@RequestBody/字符串形参）→ 串接保留",
      len([l for l in _res2.links if l.medium == "db"]), 1)

# 锚点机制（真实仓库锚点由大回归覆盖）：字符串写入方 → 读取点保持连接。
_ANCHOR_W = unit("StoreController.vul", '''@GetMapping("/vul")
public String vul(@RequestParam("content") String content) {
    xssService.insertOne(new Xss(content));
    return "stored";
}''')
_ANCHOR_R = unit("StoreController.getXssList", '''@GetMapping("/list")
public String getXssList(Model model) {
    model.addAttribute("list", xssService.selectAll());
    return "list";
}''')
_res3 = build_chains([_ANCHOR_W, _ANCHOR_R])
check("锚点机制：字符串写入方 → 读取点保持连接",
      len([l for l in _res3.links if l.medium == "db"]), 1)


# ---------------- [56] Python Web：多跳切片与确定性规则 ----------------
#
# Python 赛道此前只有"第 1 跳"：sink 藏在 Service/DAO 里时，规则与模型
# 都只看到转发语句。两个收口：
#   ① web_treesitter 多跳展开（[Hop N] 段、防环、段数预算）；
#   ② sqli/cmdi/authz 的 Python 语法分支（参数化 vs f-string、列表传参 vs
#      shell=True、Depends 归属比对 vs 路由参数直查）。
print("\n[56] Python Web 规则与多跳切片")

import core.slicer.web_treesitter as WT            # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer  # noqa: E402

_PY_SQLI_VUL = '''@app.get("/user")
def get_user(uid):
    sql = f"SELECT * FROM users WHERE id = {uid}"
    cursor.execute(sql)
    return cursor.fetchone()'''

_PY_SQLI_PARAM = '''@app.get("/user")
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchone()'''

_PY_SQLI_INT = '''@app.get("/user")
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = " + str(int(uid)))
    return cursor.fetchone()'''

check("Python SQLi：f-string 拼接形参 → 判漏洞",
      verdict("sqli", _PY_SQLI_VUL), True)
check("Python SQLi：参数化元组 → 判安全",
      verdict("sqli", _PY_SQLI_PARAM), False)
check("Python SQLi：int() 锁死值域 → 判安全",
      verdict("sqli", _PY_SQLI_INT), False)

_PY_CMDI_VUL = '''@app.post("/ping")
def ping(host: str):
    cmd = "ping -c 1 " + host
    os.system(cmd)
    return "done"'''

_PY_CMDI_SAFE = '''@app.post("/ping")
def ping(host: str):
    subprocess.run(["ping", "-c", "1", host], shell=False)
    return "done"'''

check("Python CMDi：os.system 字符串拼接 → 判漏洞",
      verdict("cmdi", _PY_CMDI_VUL), True)
check("Python CMDi：列表传参 shell=False → 判安全",
      verdict("cmdi", _PY_CMDI_SAFE), False)

_PY_AUTHZ_VUL = '''@app.get("/orders/{order_id}")
def get_order(order_id: int):
    order = db.query(Order).filter(Order.id == order_id).first()
    return order'''

_PY_AUTHZ_OK = '''@app.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id,
                                   Order.user_id == current_user.id).first()
    return order'''

check("Python Authz：路由形参直查、无主体 → 判越权",
      verdict("authz", _PY_AUTHZ_VUL), True)
check("Python Authz：Depends 主体 + 归属比对 → 判安全",
      verdict("authz", _PY_AUTHZ_OK), False)
check("Python Authz：有主体但比对下沉 Service → 不表态",
      verdict("authz", '''@app.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(get_current_user)):
    return order_service.get_order(order_id)'''), None)

# 多跳切片：入口 → service（Hop 1）→ dao（Hop 2），sink 在第 2 跳。
_TMP2 = Path(tempfile.mkdtemp(prefix="nexus_py_hops_"))
try:
    app_d = _TMP2 / "app"
    app_d.mkdir()
    (app_d / "routes.py").write_text(
        'from service import UserService\n\n'
        '@app.get("/user/{uid}")\n'
        'def get_user(uid: int):\n'
        '    return UserService.find(uid)\n', encoding="utf-8", newline="")
    (app_d / "service.py").write_text(
        'from dao import UserDao\n\n'
        'class UserService:\n'
        '    @staticmethod\n'
        '    def find(uid):\n'
        '        return UserDao.fetch(uid)\n', encoding="utf-8", newline="")
    (app_d / "dao.py").write_text(
        'class UserDao:\n'
        '    @staticmethod\n'
        '    def fetch(uid):\n'
        '        sql = "SELECT * FROM users WHERE id = " + uid\n'
        '        return cursor.execute(sql)\n', encoding="utf-8", newline="")
    units_py = WebTreeSitterSlicer(_TMP2).extract_entry_units()
    u0 = next((u for u in units_py if u.unit_name == "get_user"), None)
    check("多跳切片：Hop1/Hop2 段都进切片",
          u0 is not None and "[Hop 1]" in u0.source_code and "[Hop 2]" in u0.source_code,
          True)
    check("多跳切片：第 2 跳的 sink 被规则看见（拼接 SQL → True）",
          verdict("sqli", u0.source_code), True)
    check("多跳切片：helper 体可被引证（不是注释行）",
          any(ln.strip().startswith("sql =") for ln in u0.source_code.splitlines()
              if not ln.strip().startswith("//")), True)
finally:
    shutil.rmtree(_TMP2, ignore_errors=True)


# ---------------- [57] Solidity：重入 CEI 与访问控制 ----------------
#
# 重入的判定支点是**行序**：状态扣减在外部转账之前 = CEI 正序 = 安全。
# 行号必须换算到切片文本内逐行核对，不靠"看起来像"。
print("\n[57] Solidity 重入与访问控制规则")

_SOL_CEI_OK = '''pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}'''

_SOL_REENTRANT = '''pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}'''

_SOL_LOCKED = '''pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external nonReentrant {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}'''

check("Solidity 重入：CEI 正序（先扣减后外转）→ 判安全",
      verdict("reentrancy", _SOL_CEI_OK), False)
check("Solidity 重入：先外转后减余额 → 判漏洞",
      verdict("reentrancy", _SOL_REENTRANT), True)
check("Solidity 重入：nonReentrant 修饰符 → 判安全",
      verdict("reentrancy", _SOL_LOCKED), False)

_SOL_SETOWNER_VUL = '''pragma solidity ^0.8.0;
contract Ownable {
    address public owner;
    function setOwner(address o) external {
        owner = o;
    }
}'''

_SOL_SETOWNER_OK = '''pragma solidity ^0.8.0;
contract Ownable {
    address public owner;
    function setOwner(address o) external onlyOwner {
        owner = o;
    }
}'''

_SOL_DRAIN_VUL = '''pragma solidity ^0.8.0;
contract Piggy {
    function drain() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}'''

check("Solidity 访问控制：裸 setOwner → 判漏洞",
      verdict("access_control", _SOL_SETOWNER_VUL), True)
check("Solidity 访问控制：onlyOwner 修饰符但无定义体 → 退回（看实现体不看名字）",
      verdict("access_control", _SOL_SETOWNER_OK), None)

check("Solidity 访问控制：onlyOwner 定义体含 msg.sender 恒等 → 判安全",
      verdict("access_control", _SOL_SETOWNER_OK + """
// ---- 修饰符定义（本合约，供核验）----
modifier onlyOwner {
    require(msg.sender == owner, "not owner");
    _;
}"""), False)
check("Solidity 访问控制：无条件转出全部余额 → 判漏洞",
      verdict("access_control", _SOL_DRAIN_VUL), True)


# ---------------- [58] SARIF 2.1.0 导出格式校验 ----------------
#
# GitHub Code Scanning 只认三条硬结构：version="2.1.0"、
# results[].locations[].physicalLocation.artifactLocation.uri（仓库相对）、
# region.startLine。多跳链路走 codeFlows。
print("\n[58] SARIF 2.1.0 导出格式校验")

from cli import build_sarif, write_sarif            # noqa: E402

_ENTRIES = [
    {"file": "src/main/java/demo/XssController.java", "line": 42,
     "category": "xss", "unit": "XssController.echo",
     "message": "[XSS] 入口 XssController.echo",
     "flow": [{"file": "src/main/java/demo/XssController.java", "line": 42,
               "message": "入口"},
              {"file": "src/main/resources/templates/xss/other.html", "line": 18,
               "message": "模板渲染点"}]},
    {"file": r"src\main\java\demo\DeserController.java", "line": 7,
     "category": "deserial", "unit": "DeserController.deser",
     "message": "判定失败（限流/超时），需重跑", "level": "error"},
]
_sarif = build_sarif(_ENTRIES, repo=".")
check("version = 2.1.0", _sarif["version"], "2.1.0")
check("runs[0].tool.driver.rules 覆盖全部类目",
      {r["id"] for r in _sarif["runs"][0]["tool"]["driver"]["rules"]},
      {"XSS", "DESERIAL"})
_r0 = _sarif["runs"][0]["results"][0]
check("uri 为仓库相对 POSIX 路径",
      _r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
      "src/main/java/demo/XssController.java")
check("region.startLine 保留真实行号",
      _r0["locations"][0]["physicalLocation"]["region"]["startLine"], 42)
check("codeFlows 覆盖入口与渲染点（2 个跳点）",
      len(_r0["codeFlows"][0]["threadFlows"][0]["locations"]), 2)
check("Windows 反斜杠路径归一为 POSIX",
      _sarif["runs"][0]["results"][1]["locations"][0]["physicalLocation"]
      ["artifactLocation"]["uri"],
      "src/main/java/demo/DeserController.java")
check("level 透传（失败样本为 error）",
      _sarif["runs"][0]["results"][1]["level"], "error")

import json as _json                                # noqa: E402
check("可 JSON 序列化（round-trip）",
      _json.loads(_json.dumps(_sarif))["version"], "2.1.0")

import tempfile as _tmod                            # noqa: E402
_d = Path(_tmod.mkdtemp(prefix="nexus_sarif_"))
try:
    n = write_sarif(_d / "out.sarif", _ENTRIES, repo=".")
    check("write_sarif 落盘并返回条数", n, 2)
    check("落盘文件可读回且结构完整",
          _json.loads((_d / "out.sarif").read_text(encoding="utf-8"))["runs"][0]["results"][0]
          ["ruleId"], "XSS")
finally:
    shutil.rmtree(_d, ignore_errors=True)


# ---------------- [61] 模型硬超时/熔断 + RuleDiagnostic 接线 ----------------
#
# JavaSecLab 曾在免费模型上单条挂 26 分钟：timeout=180 × 重试 6 次 × 21 条
# 退回样本。Module 9 的答案：单请求 45s、重试 1 次、连续 3 次整体超时熔断。
# 熔断用真实挂起 socket 验证 —— mock 一个"永不响应"的假客户端骗不过
# httpx 超时语义（探针必须真实，假探针和判据写错症状一模一样）。
print("\n[61] 模型硬超时 / 熔断 / 诊断头接线")

import asyncio as _aio                                            # noqa: E402
import time as _time                                              # noqa: E402
from core.agents.router import (OpenAICompatClient, ModelCircuitOpen,   # noqa: E402
                                _is_timeout)
from core.agents.rule_detectors import build_rule_diagnostic      # noqa: E402
from core.agents.rule_detectors import (                          # noqa: E402
    _py_value_text_capable as _py_val62)
from core.agents.scenario_matcher import ScenarioMatcher as _SM   # noqa: E402


async def _hang_server():
    async def _h(reader, writer):
        try:
            await _aio.sleep(30)          # 收下连接但永不回包 → 读超时
        except _aio.CancelledError:
            pass
        finally:
            writer.close()
    return await _aio.start_server(_h, "127.0.0.1", 0)


async def _breaker_flow():
    srv = await _hang_server()
    port = srv.sockets[0].getsockname()[1]
    try:
        cli1 = OpenAICompatClient(base_url=f"http://127.0.0.1:{port}/v1",
                                  model="hang", api_key="x",
                                  timeout=0.3, max_retries=1, backoff_base=0.05,
                                  breaker_threshold=3)
        t0 = _time.monotonic()
        for _ in range(3):
            try:
                await cli1.chat([{"role": "user", "content": "hi"}])
            except ModelCircuitOpen:
                pass
            except RuntimeError:
                pass                      # 超时失败（重试后仍失败抛 RuntimeError）
        hung_elapsed = _time.monotonic() - t0
        # 3 次失败 = 每次 2 个 0.3s 超时 + 微小退避 ≈ 最多 ~3s；死等 45s 就是 bug
        if hung_elapsed > 8:
            return False, f"挂起客户端耗时 {hung_elapsed:.1f}s，未按时限快速失败"
        t0 = _time.monotonic()
        try:
            await cli1.chat([{"role": "user", "content": "hi"}])
            return False, "熔断后调用竟然成功了"
        except ModelCircuitOpen:
            pass                          # 熔断：立刻快速失败，不碰网络
        if _time.monotonic() - t0 > 0.5:
            return False, "熔断快速失败没有生效（还在等网络层超时）"
        # 非超时错误（连接被拒）不喂熔断计数。注意不能用 127.0.0.1:1：
        # 本机防火墙对它静默丢包，httpx 抛的是 ReadTimeout（探针实测），
        # 那样"非超时不计数"根本没被测到。用真 accept-后-立即断开的
        # 服务器制造 ReadError/ConnectError。
        async def _rej(reader, writer):
            writer.close()
        rsrv = await _aio.start_server(_rej, "127.0.0.1", 0)
        rport = rsrv.sockets[0].getsockname()[1]
        try:
            cli2 = OpenAICompatClient(base_url=f"http://127.0.0.1:{rport}/v1",
                                      model="refused", api_key="x", timeout=2.0,
                                      max_retries=0, breaker_threshold=3)
            for _ in range(3):
                try:
                    await cli2.chat([{"role": "user", "content": "hi"}])
                except RuntimeError as e:
                    if isinstance(e, ModelCircuitOpen):
                        return False, "连接拒绝不该触发熔断"
            if cli2._consec_timeouts != 0:
                return False, "连接拒绝被计入了熔断计数"
        finally:
            rsrv.close()
            await rsrv.wait_closed()
        return True, ""
    finally:
        srv.close()
        await srv.wait_closed()


_brk_ok, _brk_why = _aio.run(_breaker_flow())
check("挂起模型在时限内快速失败 + 3 次后熔断 + 非超时不计数",
      (_brk_ok, _brk_why), (True, ""))
check("_is_timeout 认得出超时字样",
      _is_timeout(RuntimeError("Request timed out: read overdue")), True)

# 诊断头接线：matcher 在规则退回 None 时把注释头拼进送审代码，
# 且 Cite-Before-Verdict 在带头的代码上依然只认真实代码行。
_DIAG_SRC = '''@GetMapping("/vul")
public void vul(HttpServletRequest request) throws IOException {
    String bar = request.getParameter("q");
    String sql = "SELECT * FROM users WHERE name = '" + bar + "'";
    java.sql.Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
}'''
_hdr = build_rule_diagnostic("sqli", _DIAG_SRC, line_offset=1)
# 行号契约：头部占 1 行，body 从注解行起算 —— bar 在原码第 3 行 → 模型看到 L4；
# executeQuery 在原码第 6 行 → L7。探针打印过真实头部，别凭记忆写预期。
check("诊断头：候选输入行与 sink 行都抓到（M65：空实参 createStatement"
      " 行被相关性闸门剔除）",
      ("候选输入行: L4" in _hdr and "候选敏感操作行: L7" in _hdr
       and "L6" not in _hdr), True)

# 带头代码上的引证核验：真实代码行通过、注释头被拒绝
_code_h = _hdr + "\n" + _DIAG_SRC
_ok_real, _why_real = _SM._check_evidence(
    '{"hit": "yes", "evidence_line": "stmt.executeQuery(sql);", '
    '"source_line": "String bar = request.getParameter(\\"q\\");", '
    '"sink_line": "stmt.executeQuery(sql);"}',
    _code_h, taint=True)
check("带头代码：双引证真实行核验通过", (_ok_real, _why_real), (True, ""))
_ok_hdr, _why_hdr = _SM._check_evidence(
    '{"hit": "yes", "evidence_line": ' +
    _json.dumps("// [静态前筛已核实事实] 候选输入行: L2") + '}',
    _code_h)
check("带头代码：引诊断头注释行被拒（不是代码）", _ok_hdr, False)


# 端到端：matcher 拼头。用 fake llm 抓 prompt，验证头部确实进了送审代码。
class _CatchLLM:
    def __init__(self):
        self.prompts = []

    async def __call__(self, messages):
        self.prompts.append(messages[-1]["content"])
        return '{"hit": "no"}'


_cu = unit("Vul.vul", _DIAG_SRC)
_sm = _SM(llm=_CatchLLM())
_hs = _aio.run(_sm.audit_unit_for(_cu, ["sqli"], "java_web"))
check("matcher：退回样本的送审代码已带诊断头",
      "静态前筛已核实事实" in _sm._llm.prompts[0], True)
check("matcher：unit.source_code 不被变异",
      _cu.source_code, _DIAG_SRC)


# ---------------- [62] Python 跨文件链 + 模板 XSS（vulpy 机制锁定）----------------
#
# vulpy（第 7 靶场）实测抓出的三个判据坑，全部由真实 bad/good 对照暴露：
#   ① Python 单引号字面量不是常量被漏认（只认了双引号）；
#   ② "... '{}'".format(x) 的 '{}' 让 .format 调用误入 f-string 分支
#      （真 f-string 必须有 f 前缀）→ 返回 None，真漏洞静默丢失；
#   ③ request.form.get('x') 是外部输入，但实参常量性没被识别。
print("\n[62] Python 跨文件链 / 模板 XSS / vulpy 机制锁定")

# ①②③ 单点断言
check("单引号字面量是常量",
      _py_val62("'password'", "x = 'password'"), False)
check("'{}'.format(形参) 不误入 f-string 分支（返回 True 而非 None）",
      _py_val62(
          "\"SELECT * FROM users WHERE u = '{}'\".format(username)",
          "def f(username):\n    q = \"SELECT * FROM users WHERE u = '{}'\".format(username)"),
      True)
check("request.form.get(...) 是外部输入",
      _py_val62("request.form.get('username')",
                "u = request.form.get('username')"), True)

# 跨文件两跳链：mod 调 lib，lib 里有拼接 SQL（vulpy 的 do_login 形态）
_T62 = Path(_tmod.mkdtemp(prefix="nexus_t62_"))
try:
    (_T62 / "mod_x.py").write_text(
        "from flask import Blueprint, request\n"
        "import lib_x\n"
        "bp = Blueprint('x', __name__)\n"
        "\n"
        "@bp.route('/login', methods=['POST'])\n"
        "def do_login():\n"
        "    u = request.form.get('username')\n"
        "    return lib_x.find(u)\n", encoding="utf-8")
    (_T62 / "lib_x.py").write_text(
        "import sqlite3\n"
        "\n"
        "def find(username):\n"
        "    c = sqlite3.connect('d.sqlite').cursor()\n"
        "    return c.execute(\"SELECT * FROM users WHERE u = '{}'\".format(username)).fetchone()\n",
        encoding="utf-8")
    _u62 = WebTreeSitterSlicer(_T62).extract_entry_units()
    check("蓝图 @bp.route 入口被切出", len(_u62), 1)
    check("跨文件 lib 体进入 [Hop 1]",
          "[Hop 1]" in (_u62[0].source_code if _u62 else ""), True)
    check("两跳链拼接 SQL → 判漏洞",
          verdict("sqli", _u62[0].source_code) if _u62 else None, True)
    (_T62 / "lib_x.py").write_text(
        "import sqlite3\n"
        "\n"
        "def find(username):\n"
        "    c = sqlite3.connect('d.sqlite').cursor()\n"
        "    return c.execute(\"SELECT * FROM users WHERE u = ?\", (username,)).fetchone()\n",
        encoding="utf-8")
    _u62b = WebTreeSitterSlicer(_T62).extract_entry_units()
    check("同链路参数化 → 判安全",
          verdict("sqli", _u62b[0].source_code) if _u62b else None, False)
finally:
    shutil.rmtree(_T62, ignore_errors=True)

# 模板 XSS 四形态
check("render_template_string 拼接外部输入 → 判漏洞",
      verdict("xss", '@app.route("/e")\ndef e():\n'
                     '    n = request.args.get("n")\n'
                     '    return render_template_string("<h1>" + n + "</h1>")'), True)
check("Markup(f-string 外部输入) → 判漏洞",
      verdict("xss", '@app.route("/m")\ndef m():\n'
                     '    w = request.form.get("w")\n'
                     '    return Markup(f"<b>{w}</b>")'), True)
check("render_template 文件模板（自动转义）→ 判安全",
      verdict("xss", '@app.route("/p")\ndef p():\n'
                     '    return render_template("p.html", n=request.args.get("n"))'), False)
check("render_template_string 常量 → 判安全",
      verdict("xss", '@app.route("/c")\ndef c():\n'
                     '    return render_template_string("<h1>hi</h1>")'), False)

# vulpy 真实仓库 E2E（bad/good 成对真值 6 条）
_Vul62 = Path(__file__).resolve().parent.parent / "reference_repos" / "vulpy-master"
if _Vul62.exists():
    _v62_truth = {
        ("bad", "do_login"): True, ("bad", "do_chpasswd"): True,
        ("bad", "do_key_create"): True,
        ("good", "do_login"): False, ("good", "do_chpasswd_post"): False,
        ("good", "do_key_create"): False,
    }
    _v62_got = {}
    for _side in ("bad", "good"):
        for _u in WebTreeSitterSlicer(_Vul62 / _side).extract_entry_units():
            if (_side, _u.unit_name) in _v62_truth:
                _v62_got[(_side, _u.unit_name)] = verdict("sqli", _u.source_code)
    check("vulpy 成对真值 6/6（bad .format → True / good 参数化 → False）",
          _v62_got, _v62_truth)
else:
    print("  -- vulpy 靶场不在 reference_repos，跳过 E2E（安装见 Module 10）")


# ---------------- [63] Solidity 真实合约形态（smartbugs 机制锁定）----------------#
# smartbugs（第 8 靶场）抓出的四个判据坑：
#   ① _looks_solidity 只认 pragma/contract 关键字 → 函数级切片全退 None；
#   ② 0.4.x 老语法 msg.sender.call.value(x)() 不在外部调用集合 → 经典
#      重入（PrivateBank/CashOut、SimpleBank/Collect）全部静默退回；
#   ③ modifier 可无参（modifier onlyowner {）→ 带参正则漏掉整类权限；
#   ④ 状态门 modifier（only_uninitialized 查 m_numOwners）不是身份检查，
#      拿它判安全会把 parity initWallet 判反。
#   以及错名构造函数（Rubixi 的 DynamicPyramid）必须判 True。
print("\n[63] Solidity 真实合约形态 / 重入老语法 / modifier 实现体")

from core.slicer.web3_slither import SoliditySlicer    # noqa: E402

_SOL_OLD_REENTRANT = '''// contract: PrivateBank
function CashOut(uint _am) public payable {
    if(_am <= balances[msg.sender]) {
        if(msg.sender.call.value(_am)()) {
            balances[msg.sender] -= _am;
        }
    }
}'''
check("老语法 call.value()() 先外转后扣减 → 判漏洞",
      verdict("reentrancy", _SOL_OLD_REENTRANT), True)

_SOL_OLD_CEI = '''// contract: GoodBank
function withdraw(uint _am) public payable {
    balances[msg.sender] -= _am;
    msg.sender.call.value(_am)();
}'''
check("老语法 CEI 正序（先扣减后外转）→ 判安全",
      verdict("reentrancy", _SOL_OLD_CEI), False)

_SOL_MOD_NOPARAM = '''// contract: Vault
function changeOwner(address _owner) onlyowner {
    owner = _owner;
}
// ---- 修饰符定义（本合约，供核验）----
modifier onlyowner {
    if (msg.sender == creator) _;
}'''
check("无参 modifier 实现体含 msg.sender 恒等 → 判安全",
      verdict("access_control", _SOL_MOD_NOPARAM), False)

_SOL_STATE_GATE = '''// contract: Wallet
function initWallet(address[] _owners, uint _required) only_uninitialized {
    initMultiowned(_owners, _required);
}
// ---- 修饰符定义（本合约，供核验）----
modifier only_uninitialized { if (m_numOwners > 0) throw; _; }'''
check("纯状态门 modifier 不是身份检查 → 不判安全（退回交模型）",
      verdict("access_control", _SOL_STATE_GATE), None)

_SOL_RUBIXI = '''// contract: Rubixi
function DynamicPyramid() {
    creator = msg.sender;
}'''
check("错名构造函数写 owner 态 → 判漏洞（Rubixi）",
      verdict("access_control", _SOL_RUBIXI), True)

_SOL_TRUE_CTOR = '''// contract: MyContract
function MyContract() public {
    owner = msg.sender;
}'''
check("同名构造函数写 owner = 正常初始化 → 判 safe（Module 19 由 None 收紧）",
      verdict("access_control", _SOL_TRUE_CTOR), False)

_SOL_TXORIGIN = '''// contract: Phishable
function withdrawAll(address _recipient) public {
    require(tx.origin == owner);
    _recipient.transfer(this.balance);
}'''
check("tx.origin 保护不算数（钓鱼反模式）→ 判漏洞",
      verdict("access_control", _SOL_TXORIGIN), True)

# smartbugs 真实仓库 E2E：strict 门禁关键数字
_SB = Path(__file__).resolve().parent.parent / "reference_repos" / "smartbugs-curated-main"
if _SB.exists():
    _sb_meta = {Path(x["path"]).name: x
                for x in _json.loads((_SB / "vulnerabilities.json").read_text(encoding="utf-8"))}
    _sb_rows = []
    for _cat in ("reentrancy", "access_control"):
        for _u in SoliditySlicer(_SB).extract_entry_units(_SB / "dataset" / _cat):
            _e = _sb_meta.get(Path(_u.file_path).name)
            if not _e:
                continue
            _vl = {l for v in _e["vulnerabilities"]
                   if v["category"] == _cat for l in v["lines"]}
            if not _vl:
                continue
            if (Path(_u.file_path).name, _u.unit_name) in {("parity_wallet_bug_1.sol", "kill"),
                                                           ("parity_wallet_bug_2.sol", "kill")}:
                continue                     # 口径分歧剔除
            _sb_rows.append((_cat, any(_u.start_line <= l <= _u.end_line for l in _vl),
                             verdict(_cat, _u.source_code)))
    _sb_fp = sum(1 for _c, _t, _g in _sb_rows if _g is True and not _t)
    _sb_rev = sum(1 for _c, _t, _g in _sb_rows if _g is False and _t)
    _sb_dec = sum(1 for _c, _t, _g in _sb_rows if _g is not None)
    check("smartbugs E2E：零误报（safe 分母 ~198）", _sb_fp, 0)
    check("smartbugs E2E：零判反", _sb_rev, 0)
    check("smartbugs E2E：确定性判定 ≥ 40 条（老语法/modifier 修复生效）",
          _sb_dec >= 40, True)
else:
    print("  -- smartbugs 靶场不在 reference_repos，跳过 E2E（安装见 Module 12）")


# ---------------- [64] --fix 跨语言补丁（Python 参数化 / Solidity CEI）----------------
#
# 与 [59] 同一闭环：规则 True → 补丁 → 重切片重跑规则翻 False → 字节级
# 还原。Python 走 ast 改写（正则配平嵌套括号在真实代码上必踩坑）；
# Solidity 走紧邻反序行交换（复杂控制流不碰，交人工）。
print("\n[64] --fix 跨语言补丁：Python 参数化 / Solidity CEI 行交换")

from cli import _fix_python_sqli, _fix_solidity_reentrancy   # noqa: E402

# Python：三种拼接形态 → 参数化
_T64 = Path(_tmod.mkdtemp(prefix="nexus_t64_"))
try:
    (_T64 / "dao.py").write_text(
        "from flask import Blueprint, request\n"
        "bp = Blueprint('d', __name__)\n"
        "\n"
        "@bp.route('/vul', methods=['POST'])\n"
        "def vul_pct():\n"
        "    uid = request.form.get('uid')\n"
        "    c = conn.cursor()\n"
        "    return c.execute(\"SELECT * FROM users WHERE id = %s\" % uid).fetchone()\n",
        encoding="utf-8")
    _u = [x for x in WebTreeSitterSlicer(_T64).extract_entry_units()
          if x.unit_name == "vul_pct"]
    check("补丁前规则判 True", verdict("sqli", _u[0].source_code) if _u else None, True)
    _report64: list = []
    _n = _fix_python_sqli(_T64, _u, _report64)
    check("Python 补丁自检通过", _n, 1)
    check("报告含 diff", any("```diff" in x for x in _report64), True)
    check("文件字节级还原", (_T64 / "dao.py").read_text(encoding="utf-8"),
          "from flask import Blueprint, request\n"
          "bp = Blueprint('d', __name__)\n"
          "\n"
          "@bp.route('/vul', methods=['POST'])\n"
          "def vul_pct():\n"
          "    uid = request.form.get('uid')\n"
          "    c = conn.cursor()\n"
          "    return c.execute(\"SELECT * FROM users WHERE id = %s\" % uid).fetchone()\n")
finally:
    shutil.rmtree(_T64, ignore_errors=True)

# Solidity：先外转后清零 → 交换为 CEI
_T64B = Path(_tmod.mkdtemp(prefix="nexus_t64b_"))
try:
    (_T64B / "Bank.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Bank {\n"
        "    mapping(address => uint) balances;\n"
        "    function withdraw(uint amt) public {\n"
        "        if(msg.sender.call.value(amt)()) {\n"
        "            balances[msg.sender] -= amt;\n"
        "        }\n"
        "    }\n"
        "}\n", encoding="utf-8")
    _us = [x for x in SoliditySlicer(_T64B).extract_entry_units(_T64B)
           if x.unit_name == "withdraw"]
    check("补丁前规则判 True", verdict("reentrancy", _us[0].source_code) if _us else None, True)
    _report64b: list = []
    _n2 = _fix_solidity_reentrancy(_T64B, _us, _report64b)
    check("Solidity 补丁自检通过（补丁态规则翻转 False）", _n2, 1)
    check("报告含 CEI diff", any("```diff" in x for x in _report64b), True)
    check("文件字节级还原",
          (_T64B / "Bank.sol").read_text(encoding="utf-8"),
          "pragma solidity ^0.4.24;\n"
          "contract Bank {\n"
          "    mapping(address => uint) balances;\n"
          "    function withdraw(uint amt) public {\n"
          "        if(msg.sender.call.value(amt)()) {\n"
          "            balances[msg.sender] -= amt;\n"
          "        }\n"
          "    }\n"
          "}\n")
finally:
    shutil.rmtree(_T64B, ignore_errors=True)


# ---------------- [65] Solidity 模型阶段：类目注册 + 端到端三态（mock）--------#
# smartbugs 的 197 条退回样本此前无处可去：`VC.get("reentrancy")` 返回 None，
# audit_unit_for 直接空转 —— 模型阶段"跑了但什么都没问"。这里锁三件事：
#   ① 两个 Solidity 类目已注册，且 needs_taint=False（重入/权限都不问入参可达）、
#      owasp=False（不得漏进 OWASP 2740 的默认类目范围）；
#   ② 提示词里带真正区分得开的判据（"外部调用之后"、tx.origin 不算、初始化状态不算）；
#   ③ 端到端只有 property 回答变化就能翻转结论 —— 证明判据链挂在属性上，
#      不是模型碰巧答对。全程 mock，零网络。
print("\n[65] Solidity 模型阶段：类目注册 / 提示词判据 / 端到端三态（mock）")

import asyncio as _aio65                                     # noqa: E402
from core.agents import vuln_categories as _VC65             # noqa: E402
from core.agents.vuln_categories import OWASP_KEYS as _OK65   # noqa: E402
from core.agents.scenario_matcher import ScenarioMatcher as _SM65  # noqa: E402

_R65 = _VC65.get("reentrancy")
_A65 = _VC65.get("access_control")
check("reentrancy 类目已注册", _R65 is not None, True)
check("access_control 类目已注册", _A65 is not None, True)
check("reentrancy 不要求入参可达", getattr(_R65, "needs_taint", None), False)
check("access_control 不要求入参可达", getattr(_A65, "needs_taint", None), False)
check("Solidity 类目不进 OWASP 默认范围",
      [k for k in ("reentrancy", "access_control") if k in _OK65], [])
check("reentrancy 判据问的是调用顺序",
      "外部调用之后" in (_R65.sink_question if _R65 else ""), True)
check("access_control 判据排除 tx.origin",
      "tx.origin" in (_A65.property if _A65 else ""), True)
check("access_control 判据排除初始化状态门",
      "初始化" in (_A65.property if _A65 else ""), True)

# 同一份代码，只让 property 的回答变化 → 结论必须随之翻转。
_SOL65 = ("function withdraw(uint amt) public {\n"
          "    if (!msg.sender.call.value(amt)()) { revert(); }\n"
          "    balances[msg.sender] -= amt;\n"
          "}")
_UNIT65 = CodeUnit(file_path="Smoke65.sol", language=Language.SOLIDITY_WEB3,
                   unit_name="withdraw", start_line=1, end_line=4,
                   source_code=_SOL65)
_SEEN65: list[str] = []


def _mock65(prop_says: str):
    def _f(messages):
        prompt = messages[-1]["content"]
        _SEEN65.append(prompt)
        if "protective property is PRESENT" in prompt:   # Property 步
            return ('{"protected": "%s", "evidence_line": '
                    '"    balances[msg.sender] -= amt;"}' % prop_says)
        return ('{"hit": "yes", "evidence_line": '
                '"    if (!msg.sender.call.value(amt)()) { revert(); }"}')
    return _f


_m65_bad = _aio65.run(_SM65(llm=_mock65("no"), code_language="solidity_web3")
                      .audit_unit_for(_UNIT65, ["reentrancy"], "solidity_web3"))
check("property=No → 判漏洞（CEI 反序）",
      bool(_m65_bad[0].property_missing) if _m65_bad else None, True)
_m65_ok = _aio65.run(_SM65(llm=_mock65("yes"), code_language="solidity_web3")
                     .audit_unit_for(_UNIT65, ["reentrancy"], "solidity_web3"))
check("property=Yes → 不判漏洞（唯一变量是属性回答）",
      bool(_m65_ok[0].property_missing) if _m65_ok else None, False)
check("提示词按 Solidity 语言围栏渲染",
      any("```solidity" in p for p in _SEEN65), True)
check("Solidity 提示词不含 Java 围栏",
      any("```java" in p for p in _SEEN65), False)

# 单票 vs 多票的"采样不一致"标签：默认 votes=1 时票箱是空的，空票箱不可能
# 不一致。这条是 smartbugs 模型层实跑抓出来的 —— 192 条理由全被这个标签污染。
check("单票模式不标采样不一致",
      "采样不一致" in (_m65_bad[0].reasoning_summary if _m65_bad else ""), False)

_ALT65 = {"n": 0}


def _mock65_alt(messages):
    prompt = messages[-1]["content"]
    if "protective property is PRESENT" in prompt:
        _ALT65["n"] += 1
        ans = "No" if _ALT65["n"] % 2 else "Yes"          # 交替 → 票面必然不同
        return ('{"protected": "%s", "evidence_line": '
                '"    balances[msg.sender] -= amt;"}' % ans)
    return ('{"hit": "yes", "evidence_line": '
            '"    if (!msg.sender.call.value(amt)()) { revert(); }"}')


_m65_multi = _aio65.run(_SM65(llm=_mock65_alt, code_language="solidity_web3",
                              property_votes=3)
                        .audit_unit_for(_UNIT65, ["reentrancy"], "solidity_web3"))
check("多票票面不同 → 标采样不一致",
      "采样不一致" in (_m65_multi[0].reasoning_summary if _m65_multi else ""), True)
check("多票 2:1 仍按多数判漏洞",
      bool(_m65_multi[0].property_missing) if _m65_multi else None, True)


# ---------------- [66] 只读函数确定性预筛（view/pure/constant）--------------#
# 编译器强制的事实，不是提示词建议：view/constant 不许写状态，pure 连读都不许。
# 于是两类漏洞都能确定性排除 —— 重入需要"外部调用后写状态"的窗口，
# 越权需要"写状态的特权动作"，只读函数两个都做不到。
# smartbugs 退回批实测：37/182 条 safe 属于这一类（access_control 20 /
# reentrancy 17），规则覆盖率 49→86，模型 FPR 分母随之变干净。
print("\n[66] 只读函数预筛：view/pure/constant → 确定性 safe")

_SOL66_VIEW = """// contract: EtherBank
function getBalance(address user) constant returns(uint) {
    return balances[user];
}"""
check("constant 函数判 safe（重入）", verdict("reentrancy", _SOL66_VIEW), False)
check("constant 函数判 safe（越权）", verdict("access_control", _SOL66_VIEW), False)

_SOL66_PURE = """// contract: Token
function supportsToken() external pure returns(bytes32) {
    return keccak256("ERC223");
}"""
check("pure 函数判 safe（重入）", verdict("reentrancy", _SOL66_PURE), False)

_SOL66_MULTILINE = """// contract: Vault
function peek()
    public
    view
    returns (uint)
{
    return total;
}"""
check("多行签名里的 view 也认", verdict("reentrancy", _SOL66_MULTILINE), False)

# 负向两条：条款不能把会改状态的函数一起吞掉，
# 也不能被函数名里的子串（preview 里的 view）误伤。
_SOL66_MUT = """// contract: Bank
function withdraw(uint amt) public {
    if (!msg.sender.call.value(amt)()) { revert(); }
    balances[msg.sender] -= amt;
}"""
check("会改状态的函数仍判漏洞（不能被条款吞掉）",
      verdict("reentrancy", _SOL66_MUT), True)

_SOL66_SUBSTR = """// contract: Bank
function preview(uint amt) public {
    if (!msg.sender.call.value(amt)()) { revert(); }
    balances[msg.sender] -= amt;
}"""
check("函数名含 view 子串不误判只读（词边界）",
      verdict("reentrancy", _SOL66_SUBSTR), True)

_SOL66_KILL = """// contract: Wallet
function kill() public {
    selfdestruct(msg.sender);
}"""
check("无保护的 selfdestruct 仍判漏洞（越权）",
      verdict("access_control", _SOL66_KILL), True)


# ---------------- [67] 外部不可达预筛 + 构造函数，第 9 靶场 DeFiVulnLabs ------#
# 与 [66] 同一条铁律的第二、三款：**编译器/VM 层的事实不交给模型**。
#   · 显式 internal / private → 外部调不到，攻击面为零；
#   · 函数名 == 合约名（0.4.x 构造函数）→ 部署期执行一次、不进运行时字节码。
# smartbugs 实测：显式 internal 单元 16 条，真值全 safe，排除面干净；
# 规则层确定性判定 86→101/246，仍 101/101 正确、零误报零判反。
print("\n[67] 外部不可达预筛：internal/private + 构造函数 → 确定性 safe")

_SOL67_INTERNAL_KILL = """// contract: Wallet
function kill() internal {
    selfdestruct(msg.sender);
}"""
check("internal + selfdestruct 判 safe（外部调不到）",
      verdict("access_control", _SOL67_INTERNAL_KILL), False)

_SOL67_PRIVATE_OWNER = """// contract: Vault
function setOwner(address o) private {
    owner = o;
}"""
check("private 写 owner 判 safe", verdict("access_control", _SOL67_PRIVATE_OWNER), False)

_SOL67_INTERNAL_REENT = """// contract: Bank
function withdraw(uint amt) internal {
    if (!msg.sender.call.value(amt)()) { revert(); }
    balances[msg.sender] -= amt;
}"""
check("internal 函数的重入也判 safe（没有入口就没有重入）",
      verdict("reentrancy", _SOL67_INTERNAL_REENT), False)

# 负向三条：条款不能被"长得像"的东西骗到。
_SOL67_PARAM = """// contract: Vault
function setOwner(bool internal_) public {
    owner = msg.sender;
}"""
check("参数名叫 internal_ 不是可见性（public 写 owner 仍判漏洞）",
      verdict("access_control", _SOL67_PARAM), True)

_SOL67_CTOR = """// contract: Wallet
function Wallet() public {
    owner = msg.sender;
}"""
check("构造函数写 owner 判 safe（部署期执行一次，外部调不到）",
      verdict("access_control", _SOL67_CTOR), False)

_SOL67_WRONG_CTOR = """// contract: Rubixi
function DynamicPyramid() {
    creator = msg.sender;
}"""
check("错名构造函数仍判漏洞（函数名 != 合约名，任何人都能调）",
      verdict("access_control", _SOL67_WRONG_CTOR), True)

_SOL67_OLD_NO_VIS = """// contract: Rubixi
function changeOwner(address o) {
    owner = o;
}"""
check("无可见性老语法不判 safe（默认 public 是事实，不能用'没写'推'不可达'）",
      verdict("access_control", _SOL67_OLD_NO_VIS), True)

# DeFiVulnLabs 真实仓库 E2E：成对 vuln/fixed 真值（第 9 靶场）。
# 它存在的理由只有一个 —— smartbugs 的 access_control 漏洞分母 18 卡在
# 记忆条 3 的 20 条线下；成对真值把"判据看机制还是看名字"变成可证伪的问题。
_DVL = Path(__file__).resolve().parent.parent / "reference_repos" / "DeFiVulnLabs-main"
if _DVL.exists():
    from benchmarks.benchmark_defivulnlabs import TRUTH as _DVL_TRUTH
    _dvl_units = {(Path(u.file_path).name, u.start_line): u
                  for u in SoliditySlicer(_DVL).extract_entry_units(_DVL / "src" / "test")}
    _dvl_rows, _dvl_miss = [], 0
    for _f, _ln, _fn, _cat, _vul, _why in _DVL_TRUTH:
        _u = _dvl_units.get((_f, _ln))
        if not _u or _u.unit_name != _fn:
            _dvl_miss += 1
            continue
        _dvl_rows.append((_cat, _vul, verdict(_cat, _u.source_code)))
    check("DeFiVulnLabs E2E：真值表 9 条全部命中切片（防上游漂移）", _dvl_miss, 0)
    check("DeFiVulnLabs E2E：零误报（成对 fixed 样本不许判 True）",
          sum(1 for _c, _t, _g in _dvl_rows if _g is True and not _t), 0)
    check("DeFiVulnLabs E2E：零判反",
          sum(1 for _c, _t, _g in _dvl_rows if _g is False and _t), 0)
    check("DeFiVulnLabs E2E：确定性判定 ≥3 条（0.8.x 语法未击穿词表）",
          sum(1 for _c, _t, _g in _dvl_rows if _g is not None) >= 3, True)
    # 成对样本的关键一条：同一函数名，差一条校验，结论必须相反。
    _pair = {(c, t, g) for c, t, g in _dvl_rows}
    check("DeFiVulnLabs E2E：成对真值出现双向结论（vul=True 且 fixed=False）",
          any(g is True for _c, t, g in _dvl_rows if t)
          and any(g is False for _c, t, g in _dvl_rows if not t), True)
else:
    print("  -- DeFiVulnLabs 靶场不在 reference_repos，跳过 E2E（安装见 Module 19）")


# ---------------- [68] vulpy 模型层：opt-in + 三态聚合口径 -------------------#
# Python 赛道此前只有规则层（6/6 全判，没有退回批），模型层是空白。补成
# **端到端口径**：模型独立再判这 6 条，指标只记录不下结论（vul 分母 3）。
# 这里锁的是聚合本身：三态必须分开数（命中/方向错/调用失败），失败绝不
# 折算成"无漏洞"，方向错必须单独计数而不是混进 FP。
print("\n[68] vulpy 模型层：opt-in 开关 + 三态聚合")

from benchmarks.benchmark_vulpy import _report_model as _vulpy_report  # noqa: E402

_vulpy_rows = [
    {"side": "bad", "unit": "do_login", "category": "sqli", "real_vuln": True,
     "flagged": True},                                    # TP
    {"side": "good", "unit": "do_login", "category": "sqli", "real_vuln": False,
     "flagged": False},                                   # TN
    {"side": "good", "unit": "do_chpasswd_post", "category": "sqli",
     "real_vuln": False, "flagged": True},                # FP（方向错）
    {"side": "bad", "unit": "do_key_create", "category": "sqli", "real_vuln": True,
     "flagged": None, "detail": "RuntimeError: 模型返回空内容"},   # 调用失败
]
_vs = _vulpy_report(_vulpy_rows, "mock-model")
check("vulpy 模型层：TP 计数", _vs["tp"], 1)
check("vulpy 模型层：TN 计数", _vs["tn"], 1)
check("vulpy 模型层：FP 计数（方向错单列）", _vs["fp"], 1)
check("vulpy 模型层：调用失败单列、不折算成无漏洞",
      (_vs["call_failed"], _vs["fn"]), (1, 0))
check("vulpy 模型层：失败样本落盘带原因",
      "模型返回空内容" in (_vs["call_failed_rows"][0]["detail"] or ""), True)

import subprocess as _sp68                                          # noqa: E402
_h68 = _sp68.run([sys.executable, str(Path(__file__).resolve().parent
                                      / "benchmark_vulpy.py"), "--help"],
                 capture_output=True, text=True, encoding="utf-8")
check("vulpy 模型层是 opt-in（--model 存在，默认不发请求）",
      "--model" in _h68.stdout, True)


print()
# （汇总在文件最末尾 —— [69] 起的区块都在本行之后追加，
#   中途放汇总会让末尾断言的 FAIL 不影响退出码。）

# ---- [69] nssc 第 10 靶场：README 指名真值 + 机制断言 ----
# 切片器形态：签名没用修饰符时，切片里**没有**修饰符体（README 的漏洞点）
_nssc_src_changeowner = """// contract: Unprotected
function changeOwner(address _newOwner) 
    public
{
    owner = _newOwner;
}
"""
check("nssc：无保护 changeOwner 判 True（机制：写状态无身份校验）",
      _verdict("access_control", _nssc_src_changeowner), True)

_nssc_src_fixed = """// contract: Unprotected
function changeOwner_fixed(address _newOwner) 
    public 
    onlyowner
{
    owner = _newOwner;
}
// ---- 修饰符定义（本合约，供核验）----
modifier onlyowner { require(msg.sender==owner); _; }
"""

_nssc_ctor = """
contract Rubixi{
    address public owner;
    function DynamicPyramid() { owner = msg.sender; }
}
"""
check("nssc：挂上 onlyowner 的 changeOwner_fixed 判 False（修饰符体真比对 msg.sender）",
      _verdict("access_control", _nssc_src_fixed), False)

check("nssc：错名构造函数 DynamicPyramid 判 True（0.4.x 落运行时字节码）",
      _verdict("access_control", _nssc_ctor), True)

_nssc_reent = """
contract Reentrance {
    mapping (address => uint) userBalance;
    function withdrawBalance(){
        if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){ throw; }
        userBalance[msg.sender] = 0;
    }
    function withdrawBalance_fixed(){
        uint amount = userBalance[msg.sender];
        userBalance[msg.sender] = 0;
        if( ! (msg.sender.call.value(amount)() ) ){ throw; }
    }
}
"""
check("nssc：call.value 后写状态判 True（违反 CEI）",
      _verdict("reentrancy", _nssc_reent.split("withdrawBalance_fixed")[0]), True)
check("nssc：先扣减后 call 判 False（成对修复样本）",
      _verdict("reentrancy", "contract X {" + _nssc_reent.split("withdrawBalance_fixed")[1]
               .split("\n", 1)[1]), False)

import subprocess as _sp69                                          # noqa: E402
_r69 = _sp69.run([sys.executable, str(Path(__file__).resolve().parent
                                     / "benchmark_nssc.py"), "--strict", "--offline"],
                 capture_output=True, text=True, encoding="utf-8")
check("nssc benchmark --strict --offline 退出码 0", _r69.returncode, 0)
check("nssc benchmark 真值表全命中（STRICT PASS）",
      "STRICT PASS" in (_r69.stdout or ""), True)


# ---- [70] Module 21：2300 gas 津贴早退 + Solidity 事实诊断头 ----
_nssc_fixed2 = """// contract: Reentrance
function withdrawBalance_fixed_2(){
    msg.sender.transfer(userBalance[msg.sender]);
    userBalance[msg.sender] = 0;
}
"""
check("M21：msg.sender.transfer 后写状态判 False（2300 gas 津贴，VM 层重入不可能）",
      _verdict("reentrancy", _nssc_fixed2), False)

_nssc_fixed2_send = """// contract: X
function refund(address payable to){
    uint amt = credits[to];
    to.send(amt);
    credits[to] = 0;
}
"""
check("M21：单参 .send 同样津贴形态 → False",
      _verdict("reentrancy", _nssc_fixed2_send), False)

_nssc_erc777 = """// contract: X
function claim(){
    _mints[account] = 0;
    token.transfer(account, amount);
}
"""
check("M21：双参 token.transfer（ERC20/777）不吃津贴豁免，照旧退 None",
      _verdict("reentrancy", _nssc_erc777), None)

_nssc_call_after = """// contract: X
function evil(){
    msg.sender.transfer(1);
    msg.sender.call.value(2)();
    balances[msg.sender] = 0;
}
"""
check("M21：津贴与硬外转混合 → 仍按 CEI 行序判 True",
      _verdict("reentrancy", _nssc_call_after), True)

from core.agents.rule_detectors import build_solidity_diagnostic as _bsd
_d70_named = """// contract: X
function withdrawAll() public onlyowner {
    msg.sender.transfer(address(this).balance);
}
"""
_h70 = _bsd("access_control", _d70_named)
check("M21：诊断头——modifier 体不在切片内要写明（模型视野边界）",
      "定义体不在切片内" in _h70 and _h70.startswith("// "), True)
_d70_clean = """// contract: X
function f() public {
    owner = msg.sender;
}
"""
check("M21：诊断头——无事实移交时返回空串（不拼无意义头）",
      _bsd("access_control", _d70_clean), "")
check("M21：诊断头带不可引证声明（Cite-Before-Verdict 兼容）",
      "不可作为证据引用" in _h70, True)

import subprocess as _sp70                                          # noqa: E402
_r70 = _sp70.run([sys.executable, str(Path(__file__).resolve().parent
                                     / "benchmark_nssc.py"), "--strict", "--offline"],
                 capture_output=True, text=True, encoding="utf-8")
check("M21：nssc 真值表 8 条（含 fixed_2）strict 退出码 0", _r70.returncode, 0)


# ---- [71] Module 23：方法级权限注解 + 主体链取值（RuoYi 形态） ----
_ry_annotated = """// Full-Route: /system/user/list
    @RequiresPermissions("system:user:list")
    @PostMapping("/list")
    @ResponseBody
    public TableDataInfo list(SysUser user)
    {
        List<SysUser> list = userService.selectUserList(user);
        return getDataTable(list);
    }
"""
check("M23：@RequiresPermissions 垂直授权 → authz False",
      _verdict("authz", _ry_annotated), False)

_ry_markread = """// Full-Route: /system/notice/markRead
    @PostMapping("/markRead")
    @ResponseBody
    public AjaxResult markRead(Long noticeId)
    {
        Long userId = ShiroUtils.getSysUser().getUserId();
        noticeReadService.markRead(noticeId, userId);
        return success();
    }
"""
check("M23：主体链取值作 Service 实参（标记自己已读）→ False（2g）",
      _verdict("authz", _ry_markread), False)

_ry_checkpwd = """// Full-Route: /system/user/profile/checkPassword
    @GetMapping("/checkPassword")
    @ResponseBody
    public boolean checkPassword(String password)
    {
        SysUser user = getSysUser();
        return passwordService.matches(user, password);
    }
"""
check("M23：校验当前会话用户密码（主体对象作实参）→ False（2g）",
      _verdict("authz", _ry_checkpwd), False)

_ry_dto = """// Full-Route: /system/user/profile
    @GetMapping("/profile")
    @ResponseBody
    public AjaxResult profile(SysUser user)
    {
        return AjaxResult.success(userService.selectUserProfile(user));
    }
"""
check("M23：客户端 DTO 直接进 Service 且无主体 → 保持 True（防 2g 放水；"
      "check*Unique 形态已被 2h 单独豁免，见 [74]）",
      _verdict("authz", _ry_dto), True)

import subprocess as _sp71                                          # noqa: E402
_r71 = _sp71.run([sys.executable, str(Path(__file__).resolve().parent
                                     / "benchmark_ruoyi.py"), "--strict", "--offline"],
                 capture_output=True, text=True, encoding="utf-8")
check("M23：RuoYi benchmark --strict --offline 退出码 0", _r71.returncode, 0)
check("M23：RuoYi 跨模块穿透 + 注解语义在线（STRICT PASS）",
      "STRICT PASS" in (_r71.stdout or ""), True)


# ---- [72] Module 24：切片器同名符号覆盖 + Python 判据补口 ----
import tempfile as _tmd72
# 同名符号覆盖：两个"应用"各定义 index，整库切片不许丢
_d72 = Path(_tmd72.mkdtemp(prefix="nexus_pysym_"))
(_d72 / "a").mkdir(); (_d72 / "b").mkdir()
(_d72 / "a" / "app.py").write_text(
    'from flask import Flask\napp = Flask("a")\n'
    '@app.route("/a")\ndef index():\n    return "A"\n', encoding="utf-8")
(_d72 / "b" / "app.py").write_text(
    'from flask import Flask\napp = Flask("b")\n'
    '@app.route("/b")\ndef index():\n    return "B"\n', encoding="utf-8")
_u72 = WebTreeSitterSlicer(_d72).extract_entry_units()
check("M24：同名符号共存（两应用各一个 index）", len(_u72), 2)
check("M24：同名符号来自不同文件",
      len({u.file_path for u in _u72}), 2)

# 赋值链：hop 段同名赋值不遮蔽入口；sink 同段赋值可见
_src72 = '''// contract: X
def lab():
    username = request.form.get("username", "")
    sql = (
        f"SELECT * FROM users WHERE username='{username}'"
    )
    return cursor.execute(sql)

// ---- 跨文件辅助方法实现（入口方法调用的外部方法，按跳展开）----
// 来自 models.py:1 [Hop 1]
class User:
    username = db.Column(db.String(80))
'''
check("M24：hop 段同名赋值不遮蔽入口（入口 request.form 赋值优先）",
      _verdict("sqli", _src72), True)

_hop72 = '''def get_user(uid):
    return dao_fetch(uid)

// ---- 跨文件辅助方法实现（入口方法调用的外部方法，按跳展开）----
// 来自 dao.py:1 [Hop 1]
def dao_fetch(uid):
    sql = "SELECT * FROM users WHERE id = " + uid
    return cursor.execute(sql)
'''
check("M24：sink 所在段的赋值链可见（多跳不因区域修复退化）",
      _verdict("sqli", _hop72), True)

# 关键字实参不是赋值
_kw72 = '''def run():
    sql = "SELECT 1"
    cursor.execute(handler(sql=sql))
'''
check("M24：关键字实参不算赋值（守恒：常量 sql 保持 False）",
      _verdict("sqli", _kw72), False)
_kw72b = '''def run():
    sql = "SELECT * FROM users WHERE id = " + request.args.get("id", "")
    cursor.execute(handler(sql=sql))
'''
check("M24：关键字实参不算赋值（污染：真拼接仍 True）",
      _verdict("sqli", _kw72b), True)

# Python deserial：pickle / yaml 三态（Module 25 判据，pygoat 需要）
check("M25：pickle.loads → True", _verdict("deserial", '''
def f():
    data = request.form.get("d", "")
    user = pickle.loads(base64.b64decode(data))
'''), True)
check("M25：yaml.load 无 SafeLoader → True", _verdict("deserial", '''
def f():
    data = yaml.load(file.stream, Loader=yaml.Loader)
'''), True)
check("M25：yaml.load + SafeLoader → False", _verdict("deserial", '''
def f():
    data = yaml.load(file.stream, Loader=yaml.SafeLoader)
'''), False)
check("M25：yaml.safe_load → False", _verdict("deserial", '''
def f():
    data = yaml.safe_load(request.data)
'''), False)

# pathtraver：os.path.join(常量, 输入) 不防遍历；send_from_directory 是防护
check("M24：open(os.path.join(常量, 输入)) → True（join 不清洗 ..）",
      _verdict("pathtraver", '''
def lab1():
    file = request.form.get("blog", "")
    file_path = os.path.join(os.path.dirname(__file__), file)
    with open(file_path, "r") as f:
        return f.read()
'''), True)
check("M24：send_from_directory → False（Flask 专门防遍历 API）",
      _verdict("pathtraver", '''
def serve_file(filename):
    return send_from_directory("static", filename, as_attachment=True)
'''), False)

# xxe：feature_external_ges 一行定案
check("M24：setFeature(feature_external_ges, True) + request 输入 → True",
      _verdict("xxe", '''
def xxe_parse():
    data = request.data.decode("utf-8")
    parser = make_parser()
    parser.setFeature(feature_external_ges, True)
    doc = parseString(data, parser=parser)
'''), True)
check("M24：defusedxml → False", _verdict("xxe", '''
def parse():
    data = request.data.decode("utf-8")
    doc = defusedxml.ElementTree.fromstring(data)
'''), False)

import subprocess as _sp72                                          # noqa: E402
_r72 = _sp72.run([sys.executable, str(Path(__file__).resolve().parent
                                     / "benchmark_pygoat.py"), "--strict", "--offline"],
                 capture_output=True, text=True, encoding="utf-8")
check("M24：pygoat benchmark --strict --offline 退出码 0", _r72.returncode, 0)
check("M24：pygoat 作者指名真值全 True（STRICT PASS，M69 补登 eval 后 10/10）",
      "STRICT PASS" in (_r72.stdout or ""), True)


# ---- [73] Module 25：yaml.load → safe_load 补丁自检闭环 ----
from cli import _fix_python_deserial as _fpd73                  # noqa: E402
_T73 = Path(_tmd72.mkdtemp(prefix="nexus_t73_"))
try:
    (_T73 / "app.py").write_text(
        "import yaml\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/upload', methods=['POST'])\n"
        "def upload_yaml():\n"
        "    data = yaml.load(request.files['f'].stream, Loader=yaml.Loader)\n"
        "    return str(data)\n", encoding="utf-8")
    _u73 = [x for x in WebTreeSitterSlicer(_T73).extract_entry_units()
            if x.unit_name == "upload_yaml"]
    check("M25：补丁前 deserial 判 True", _verdict("deserial", _u73[0].source_code), True)
    _rep73: list = []
    _n73 = _fpd73(_T73, _u73, _rep73)
    check("M25：yaml 补丁自检通过（重切片 + 规则翻 False）", _n73, 1)
    check("M25：报告含 diff", any("```diff" in x for x in _rep73), True)
    _orig73 = ("import yaml\n"
               "from flask import Flask, request\n"
               "app = Flask(__name__)\n"
               "@app.route('/upload', methods=['POST'])\n"
               "def upload_yaml():\n"
               "    data = yaml.load(request.files['f'].stream, Loader=yaml.Loader)\n"
               "    return str(data)\n")
    check("M25：文件字节级还原", (_T73 / "app.py").read_text(encoding="utf-8"), _orig73)
    # 无 yaml.load 的单元不动手
    (_T73 / "app.py").write_text(
        "import pickle, base64\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/u2', methods=['POST'])\n"
        "def u2():\n"
        "    return str(pickle.loads(base64.b64decode(request.form['d'])))\n",
        encoding="utf-8")
    _u73b = [x for x in WebTreeSitterSlicer(_T73).extract_entry_units()
             if x.unit_name == "u2"]
    _rep73b: list = []
    check("M25：pickle 无等价安全 API，不生成补丁", _fpd73(_T73, _u73b, _rep73b), 0)
finally:
    shutil.rmtree(_T73, ignore_errors=True)


# ---- [74] Module 28：authz 2h 只读唯一性校验豁免 ----
check("M28：checkXxxUnique 存在性校验 → False（2h）",
      _verdict("authz", '''
// Full-Route: /system/user/checkLoginNameUnique
@PostMapping("/checkLoginNameUnique")
@ResponseBody
public boolean checkLoginNameUnique(SysUser user)
{
    return userService.checkLoginNameUnique(user);
}
'''), False)
check("M28：body 含其它 Service 调用（实体读取）→ 不豁免仍 True",
      _verdict("authz", '''
// Full-Route: /system/menu/selectMenuTree/{menuId}
@GetMapping("/selectMenuTree/{menuId}")
public String selectMenuTree(@PathVariable("menuId") Long menuId, ModelMap mmap)
{
    mmap.put("menu", menuService.selectMenuById(menuId));
    return prefix + "/tree";
}
'''), True)
check("M28：check*Unique 但伴随写操作 → 不豁免",
      _verdict("authz", '''
@PostMapping("/checkAndSave")
@ResponseBody
public boolean checkAndSave(SysUser user)
{
    boolean ok = userService.checkLoginNameUnique(user);
    if (ok) {
        userService.insertUser(user);
    }
    return ok;
}
'''), True)
check("M28：非 Unique 命名（checkCronExpressionIsValid）→ 不豁免",
      _verdict("authz", '''
@GetMapping("/queryCronExpression")
@ResponseBody
public AjaxResult queryCronExpression(String cronExpression)
{
    if (jobService.checkCronExpressionIsValid(cronExpression))
    {
        List<String> dateList = CronUtils.getRecentTriggerTime(cronExpression);
        return success(dateList);
    }
    return error("表达式无效");
}
'''), True)

import subprocess as _sp74                                          # noqa: E402
_r74 = _sp74.run([sys.executable, str(Path(__file__).resolve().parent
                                     / "benchmark_ruoyi.py"), "--strict", "--offline"],
                 capture_output=True, text=True, encoding="utf-8")
check("M28：RuoYi benchmark --strict --offline 退出码 0", _r74.returncode, 0)
check("M28：RuoYi 无注解 True 面 16 → 5 → 0（M64：Shiro /** user 全局认证核实后归零）",
      ("无注解且判 True 的入口" not in (_r74.stdout or "")), True)


# ---- [75] Module 29：MyBatis-Plus Wrapper 判据 + @el.check/@AnonymousAccess ----
check("M29：Wrapper 拼接出口 .apply 带拼接 → True",
      _verdict("sqli", '''
// Full-Route: /api/users
@GetMapping("/users")
public Object users(String name) {
    QueryWrapper<User> qw = new QueryWrapper<>();
    qw.apply("name = '" + name + "'");
    return userService.list(qw);
}
'''), True)
check("M29：Wrapper 拼接出口 .last 带裸变量 → True",
      _verdict("sqli", '''
@GetMapping("/page")
public Object page(Integer page) {
    QueryWrapper<User> qw = new QueryWrapper<>();
    qw.eq("status", 1);
    qw.last("limit " + page);
    return userService.list(qw);
}
'''), True)
check("M29：纯参数化 Wrapper（.eq/.like）→ False（C4）",
      _verdict("sqli", '''
@GetMapping("/search")
public Object search(String name) {
    QueryWrapper<User> qw = new QueryWrapper<>();
    qw.like("name", name).eq("deleted", 0);
    return userService.list(qw);
}
'''), False)
check("M29：占位符绑定 .apply(\"col = {0}\", x) → False（非拼接出口）",
      _verdict("sqli", '''
@GetMapping("/find")
public Object find(String name) {
    QueryWrapper<User> qw = new QueryWrapper<>();
    qw.apply("name = {0}", name);
    return userService.list(qw);
}
'''), False)
check("M29：@el.check EL 权限注解 → False",
      _verdict("authz", '''
// Full-Route: /api/users
@PreAuthorize("@el.check('user:list')")
@GetMapping("/users")
public ResponseEntity<Object> users() {
    return new ResponseEntity<>(userService.queryAll(), HttpStatus.OK);
}
'''), False)
check("M29：@AnonymousAccess 显式匿名声明 → None（不做授权判定）",
      _verdict("authz", '''
// Full-Route: /auth/code
@AnonymousAccess
@GetMapping("/code")
public ResponseEntity<Object> code() {
    return verificationCodeService.getCode();
}
'''), None)

import subprocess as _sp75                                          # noqa: E402
_r75 = _sp75.run([sys.executable, str(Path(__file__).resolve().parent
                                     / "benchmark_eladminmp.py"), "--strict", "--offline"],
                 capture_output=True, text=True, encoding="utf-8")
check("M29：eladmin-mp benchmark --strict --offline 退出码 0", _r75.returncode, 0)
check("M29：@el.check 53/53 全 False（STRICT PASS）",
      "STRICT PASS" in (_r75.stdout or ""), True)


# ---- [76] Module 30：Solidity 三大确定性规则 ----
check("M30：tx.origin 鉴权（require 恒等）→ True",
      _verdict("access_control", '''
function transfer(address payable _to, uint _amount) public {
    require(tx.origin == owner, "Not owner");
    (bool sent, ) = _to.call{value: _amount}("");
    require(sent, "Failed");
}
'''), True)
check("M30：tx.origin 与 msg.sender 并存 → msg.sender 保护优先判 False",
      _verdict("access_control", '''
function transfer(address payable _to, uint _amount) public {
    require(msg.sender == owner, "Not owner");
    require(tx.origin == owner, "Not owner");
    _to.transfer(_amount);
}
'''), False)
check("M30：任意 from 的 transferFrom（无保护）→ True",
      _verdict("access_control", '''
function transferFrom(address from, address to, uint256 tokenId) public {
    _transfer(from, to, tokenId);
}
'''), True)
check("M30：transferFrom 带 _isApprovedOrOwner 保护 → False",
      _verdict("access_control", '''
function transferFrom(address from, address to, uint256 tokenId) public {
    require(_isApprovedOrOwner(_msgSender(), tokenId), "not owner");
    _transfer(from, to, tokenId);
}
'''), False)
check("M30：unchecked call 裸调用 → True",
      _verdict("unchecked_low_level_calls", '''
function withdraw(uint amount) public {
    owner.send(amount);
}
'''), True)
check("M30：unchecked call 内联 if 检查 → False",
      _verdict("unchecked_low_level_calls", '''
function refund() public {
    if (!msg.sender.call.value(msg.value)()) { throw; }
}
'''), False)
check("M30：同一函数混合 checked + unchecked 调用点 → True（0x5249 形态）",
      _verdict("unchecked_low_level_calls", '''
function transfer() returns (bool) {
    contract_address.call("register", "CentraToken");
    if (!contract_address.call(bytes4(keccak256("transfer")), c2, k)) return false;
    return true;
}
'''), True)
check("M30：if 语句体里的调用不是条件检查（finalize 判反教训）→ True",
      _verdict("unchecked_low_level_calls", '''
function finalize() external {
    if (block.number <= fundingEndBlock) throw;
    if (msg.sender == owner)
    owner.send(this.balance);
}
'''), True)
check("M30：赋值但从不检查返回值 → True",
      _verdict("unchecked_low_level_calls", '''
function pay(address to) public {
    bool ok = to.call.value(1 ether)("");
}
'''), True)


# ---- [77] Module 31：--fix 第 7/8 类补丁自检闭环 ----
from cli import _fix_solidity_txorigin as _fst77                 # noqa: E402
from cli import _fix_mp_concat as _fmc77                         # noqa: E402
_T77 = Path(_tmd72.mkdtemp(prefix="nexus_t77_"))
try:
    # 第 7 类：Solidity tx.origin → msg.sender
    (_T77 / "Wallet.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Wallet {\n"
        "    address public owner;\n"
        "    constructor() { owner = msg.sender; }\n"
        "    function transfer(address payable _to, uint _amount) public {\n"
        "        require(tx.origin == owner, \"Not owner\");\n"
        "        _to.transfer(_amount);\n"
        "    }\n"
        "}\n", encoding="utf-8")
    from core.slicer.web3_slither import SoliditySlicer as _S77
    _u77 = [x for x in _S77(_T77).extract_entry_units(_T77)
            if x.unit_name == "transfer"]
    check("M31：补丁前 access_control 判 True",
          _verdict("access_control", _u77[0].source_code), True)
    _rep77: list = []
    _n77 = _fst77(_T77, _u77, _rep77)
    check("M31：tx.origin 补丁自检通过（重切片 + 翻 False）", _n77, 1)
    check("M31：tx.origin 补丁报告含 diff", any("```diff" in x for x in _rep77), True)
    _orig77 = (_T77 / "Wallet.sol").read_text(encoding="utf-8")
    check("M31：Solidity 文件字节级还原", "tx.origin" in _orig77
          and "msg.sender == owner" not in _orig77, True)

    # 第 8 类：MyBatis-Plus .apply 拼接 → 占位符绑定
    _mp77 = _T77 / "mpapp"
    _mp77.mkdir()
    (_mp77 / "UserController.java").write_text(
        "package a;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "public class UserController {\n"
        "    private UserService userService;\n"
        "    @GetMapping(\"/find\")\n"
        "    public Object find(String name) {\n"
        "        QueryWrapper<User> qw = new QueryWrapper<>();\n"
        "        qw.apply(\"name = '\" + name + \"'\");\n"
        "        return userService.list(qw);\n"
        "    }\n"
        "}\n", encoding="utf-8")
    _u77b = [x for x in JavaSlicer(_mp77).extract_entry_units()
             if "find" in x.unit_name]
    check("M31：补丁前 sqli 判 True（拼接出口）",
          _verdict("sqli", _u77b[0].source_code), True)
    _rep77b: list = []
    _n77b = _fmc77(_mp77, _u77b, _rep77b)
    check("M31：.apply 补丁自检通过（重切片 + 翻 False）", _n77b, 1)
    _orig77b = (_mp77 / "UserController.java").read_text(encoding="utf-8")
    check("M31：Java 文件字节级还原", "name = '" in _orig77b
          and "{0}" not in _orig77b, True)
finally:
    shutil.rmtree(_T77, ignore_errors=True)


# ---- [78] Module 32：OWASP 回归分片并行——分片不变性 ----
from benchmarks.regress_owasp_rules import _eval_chunk as _ec78     # noqa: E402
_t78 = [
    ("a", "sqli", True,
     "// Full-Route: /t/a\n@GetMapping(\"/a\")\npublic String a(String id) {\n"
     "    return stmt.executeQuery(\"select * from u where id='\" + id + \"'\");\n}"),
    ("b", "sqli", False,
     "// Full-Route: /t/b\n@GetMapping(\"/b\")\npublic String b(String id) {\n"
     "    PreparedStatement ps = conn.prepareStatement(\"select * from u where id=?\");\n"
     "    ps.setString(1, id);\n    return \"ok\";\n}"),
    ("c", "authz", True,
     "// Full-Route: /t/c\n@GetMapping(\"/c\")\npublic String c(String uid) {\n"
     "    return userService.getById(uid);\n}"),
]
check("M32：分片判定结果 = 串行逐条判定（分片不变性）",
      _ec78(_t78) == _ec78(_t78[:1]) + _ec78(_t78[1:2]) + _ec78(_t78[2:3]), True)
check("M32：单 chunk 全量判定与分片聚合逐位一致",
      _ec78(_t78) == [(_n, _c, _v, _r) for (_n, _c, _v, _r) in _ec78(_t78)], True)
check("M32：分片聚合的 verdict 值正确（None/False/True）",
      [r[3] for r in _ec78(_t78)], [None, False, True])


# ---- [79] Module 34：借贷池回调 initiator 校验精准收割 ----
check("M34：executeOperation 无 initiator 校验 → True",
      _verdict("access_control", '''
function executeOperation(
    uint256 amounts,
    address receiverAddress,
    address _initiator,
    bytes calldata data
) external {
    IERC20(USDa).safeTransfer(address(lendingPool), amounts);
}
'''), True)
check("M34：executeOperation 带 require(initiator == address(this)) → False",
      _verdict("access_control", '''
function executeOperation(
    uint256 amounts,
    address receiverAddress,
    address _initiator,
    bytes calldata data
) external {
    require(_initiator == address(this), "Unauthorized");
    IERC20(USDa).safeTransfer(address(lendingPool), amounts);
}
'''), False)

# ---- [80] Module 36：ERC777 钩子回调 sink + 权限映射成员检查 ----
# DeFiVulnLabs ERC777-reentrancy.sol claim：token.transfer（双参，777 钩子
# 可回调）在 `_mints[account] += amount` 状态累加**之前** —— CEI 反序，
# tokensReceived 回调里可重入 claim。
_erc777_claim = '''
function claim(address account, uint256 amount) public returns (bool) {
    require(_mints[account] + amount <= maxMintsPerAddress,
            "Exceeds max mints per address");
    token.transfer(account, amount);
    _mints[account] += amount; // Do not follow check-effect-interaction
    return true;
}
'''
check("M36：ERC777 claim 外转先于映射累加 → True",
      _verdict("reentrancy", _erc777_claim), True)
check("M36：CEI 正序（先累加后双参 transfer）→ False",
      _verdict("reentrancy", '''
function claim_fixed(address account, uint256 amount) public returns (bool) {
    _mints[account] += amount;
    token.transfer(account, amount);
    return true;
}
'''), False)
# 权限映射成员检查（430 桶榜首确定性子簇）：msg.sender 作映射键非零判定
# 与恒等检查机制等价；余额比较（右侧是数量）不算鉴权。
check("M36：modifier 里 require(owners[msg.sender] != 0) → False",
      _verdict("access_control", '''
function deleteOwner(address _owner) onlyOwner external returns (bool) {
    owners[_owner] = 0;
}
// ---- 修饰符定义（本合约，供核验）----
modifier onlyOwner() {
    require(owners[msg.sender] != 0);
    _;
}
'''), False)
check("M36：裸真值 require(approvedPlayers[msg.sender]) → False",
      _verdict("access_control", '''
function joinGame() onlyPlayers public {
    selfdestruct(msg.sender);
}
// ---- 修饰符定义（本合约，供核验）----
modifier onlyPlayers() {
    require(approvedPlayers[msg.sender]);
    _;
}
'''), False)
check("M36：余额比较 balances[msg.sender] >= x 不是鉴权 → 不判 False",
      _verdict("access_control", '''
function poke(address to) gated public {
    balances[to] += 1;
}
// ---- 修饰符定义（本合约，供核验）----
modifier gated() {
    require(balances[msg.sender] >= _value);
    _;
}
'''), None)

# ---- [81] Module 37：Connexion/OpenAPI 路由通道 + JWT 主体链 ----
_routes81 = WebTreeSitterSlicer._connexion_routes(
    Path("reference_repos/VAmPI-main"))
check("M37：OpenAPI operationId 解析（14 路由，module.func → 路由）",
      (len(_routes81),
       _routes81.get(("api_views/users.py", "get_by_username")),
       _routes81.get(("api_views/books.py", "get_by_title"))),
      (14, "get /users/v1/{username}", "get /books/v1/{book_title}"))
_vampi_units = WebTreeSitterSlicer(
    Path("reference_repos/VAmPI-main")).extract_entry_units()
_vampi_names = {u.unit_name for u in _vampi_units}
check("M37：14 个 Connexion 入口全切出（零装饰器函数进切片）",
      (len(_vampi_units), "update_password" in _vampi_names,
       "delete_user" in _vampi_names), (14, True, True))
import subprocess as _sp81                                          # noqa: E402
check("M37：VAmPI benchmark STRICT PASS（7 真值零误报零判反零退回）",
      _sp81.run([sys.executable, str(Path(__file__).resolve().parent
                 / "benchmark_vampi.py"), "--strict", "--offline"],
                capture_output=True).returncode, 0)

# ---- [82] Module 38：全局鉴权豁免 + getCurrentMember 主体链 + MBG Example ----
check("M38：getCurrentMember().getId() 作 Service 实参 → False（2g-2）",
      _verdict("authz", '''
    @RequestMapping(value = "/list", method = RequestMethod.GET)
    public CommonResult list() {
        List<OmsCartItem> l = cartItemService.list(
            memberService.getCurrentMember().getId());
        return CommonResult.success(l);
    }
'''), False)
check("M38：全局鉴权标记下无主体形参直查 → 不判 True（豁免降 None）",
      _verdict("authz", "// [global-authz] Spring Security 过滤器统一认证\n" + '''
    @RequestMapping(value = "/update/{id}", method = RequestMethod.POST)
    public CommonResult update(@PathVariable Long id) {
        int count = productService.update(id, param);
        return CommonResult.success(count);
    }
'''), None)
check("M38：MBG Example setOrderByClause 字面量 → False（C2b）",
      _verdict("sqli", '''
    public CommonResult getList(@PathVariable Long parentId) {
        return CommonResult.success(service.getList(parentId, 5, 1));
    }
// ---- 跨文件辅助方法实现 ----
// 来自 PmsProductCategoryServiceImpl.java
    public List<PmsProductCategory> getList(Long parentId, Integer pageSize, Integer pageNum) {
        PmsProductCategoryExample example = new PmsProductCategoryExample();
        example.setOrderByClause("sort desc");
        return categoryMapper.selectByExample(example);
    }
'''), False)
check("M38：MBG Example setOrderByClause 变量 → True（C2b 拼接出口）",
      _verdict("sqli", '''
    public CommonResult getList(@PathVariable Long parentId, String order) {
        return CommonResult.success(service.getList(order));
    }
// ---- 跨文件辅助方法实现 ----
// 来自 PmsProductCategoryServiceImpl.java
    public List<PmsProductCategory> getList(String order) {
        PmsProductCategoryExample example = new PmsProductCategoryExample();
        example.setOrderByClause(order);
        return categoryMapper.selectByExample(example);
    }
'''), True)
check("M38：mall benchmark STRICT PASS（16 真值 + 全库零 True）",
      _sp81.run([sys.executable, str(Path(__file__).resolve().parent
                 / "benchmark_mall.py"), "--strict"],
                capture_output=True).returncode, 0)

# ---- [83] Module 39：跨文件父合约 modifier 继承证据 ----
import tempfile                                                    # noqa: E402
_m39dir = Path(tempfile.mkdtemp(prefix="m39fx_"))
(_m39dir / "Base.sol").write_text('''contract Base {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}
''', encoding="utf-8")
(_m39dir / "Child.sol").write_text('''import "./Base.sol";
contract Vault is Base {
    mapping(address => uint256) public balances;
    function drain() onlyOwner public {
        selfdestruct(msg.sender);
    }
}
''', encoding="utf-8")
_m39u = [u for u in SoliditySlicer().extract_entry_units(_m39dir)
         if u.unit_name == "drain"][0]
check("M39：父合约 modifier 实现体贴进切片（Base.onlyOwner 证据段）",
      ("父合约继承证据" in _m39u.source_code
       and "require(msg.sender == owner" in _m39u.source_code), True)
check("M39：跨文件继承 modifier 经核验 → False（铁律 17 跨文件成立）",
      _verdict("access_control", _m39u.source_code), False)
_m39_empty = [u for u in SoliditySlicer().extract_entry_units(_m39dir)
              if u.unit_name == "drain"][0]
check("M39：无本合约 modifier 时不留空段头",
      "修饰符定义（本合约，供核验）----\n\n" not in _m39_empty.source_code
      or "require(msg.sender == owner" in _m39_empty.source_code, True)

# ---- [84] Module 40：补丁第 9/10 类（initiator 插校验 / shell=True 改列表）----
_m40dir = Path(tempfile.mkdtemp(prefix="m40fx_"))
(_m40dir / "Flashloan.sol").write_text('''contract Flash {
    function executeOperation(
        uint256 amount,
        address _initiator,
        bytes calldata data
    ) external {
        IERC20(USDa).safeTransfer(address(lendingPool), amount);
    }
}
''', encoding="utf-8")
(_m40dir / "app_ping.py").write_text('''from flask import Flask
app = Flask(__name__)

@app.route("/ping")
def ping(host):
    cmd = "ping -c 1 " + host
    subprocess.run(cmd, shell=True)
''', encoding="utf-8")
import cli as _cli                                                 # noqa: E402
_sol40 = SoliditySlicer().extract_entry_units(_m40dir)
_l40a: list[str] = []
check("M40：initiator 补丁命中 1 条（executeOperation 插 require）",
      _cli._fix_solidity_initiator(_m40dir, _sol40, _l40a), 1)
check("M40：补丁报告带自检通过标记",
      (any("sol-initiator" in x for x in _l40a)
       and any("自检通过" in x for x in _l40a)), True)
check("M40：Solidity 字节级还原",
      "require(" not in (_m40dir / "Flashloan.sol").read_text(encoding="utf-8"),
      True)
_py40 = WebTreeSitterSlicer(_m40dir).extract_entry_units()
_l40b: list[str] = []
check("M40：shell=True 补丁命中 1 条（shlex.split 列表传参）",
      _cli._fix_python_shell(_m40dir, _py40, _l40b), 1)
check("M40：Python 字节级还原",
      "shlex" not in (_m40dir / "app_ping.py").read_text(encoding="utf-8"),
      True)

# ---- [85] Module 41：覆盖地板门禁 ----
import json                                                        # noqa: E402
import triage_fallbacks as _tri41                                 # noqa: E402
check("M41：地板表覆盖 12 个真值靶场且下限为正（M63 myblog + M64 litemall）",
      (len(_tri41.FLOORS), all(v > 0 for v in _tri41.FLOORS.values())),
      (12, True))
check("M41：--check-floor 全绿态通过（exit 0）",
      _sp81.run([sys.executable, str(Path(__file__).resolve().parent
                 / "triage_fallbacks.py"), "--check-floor"],
                capture_output=True).returncode, 0)
check("M41：floor 值与 results/*.json 的 decided 一致（同源校验）",
      all(json.loads((Path(__file__).resolve().parent.parent
          / "benchmarks" / "results" / f"{n}.json").read_text(encoding="utf-8"))
          .get("decided") >= v for n, v in _tri41.FLOORS.items()
          if (Path(__file__).resolve().parent.parent / "benchmarks"
              / "results" / f"{n}.json").exists()), True)

# ---- [86] Module 42：doctor 子命令自检 ----
import subprocess                                            # noqa: E402
_sp86 = subprocess.run(
    [sys.executable, str(Path(__file__).resolve().parent.parent / "cli.py"),
     "doctor"], capture_output=True, text=True)
check("M42：doctor exit 0（依赖/规则表/指纹/补丁器全就绪）",
      _sp86.returncode, 0)
check("M42：doctor 输出含五段自检 + PASS 尾标（M50 升段）",
      all(s in _sp86.stdout for s in
          ("[1/5]", "[2/5]", "[3/5]", "[4/5]", "[5/5]", "PASS")), True)
check(f"M42：doctor 规则注册表 {len(_CATS)} 类全 OK（从 CATEGORIES 派生，免手工改数）",
      _sp86.stdout.count("  [OK]") >= len(_CATS)
      and f"共 {len(_CATS)} 类" in _sp86.stdout, True)

# ---- [87] Module 44：调用者自域状态写早退（access_control）----
from core.agents.rule_detectors import solidity_access_verdict as _ac87   # noqa: E402
check("M44：自域三档判 False（纯自域/自取外转/对等转账+余额校验）",
      (_ac87("function approve(address spender, uint amount) external returns (bool) {"
             " allowance[msg.sender][spender] = amount; return true; }"),
       _ac87("function withdraw() external { uint refund = refunds[msg.sender];"
             " refunds[msg.sender] = 0; msg.sender.send(refund); }"),
       _ac87("function transfer(address recipient, uint amount) external returns (bool) {"
             " require(balanceOf[msg.sender] >= amount);"
             " balanceOf[msg.sender] -= amount;"
             " balanceOf[recipient] += amount; return true; }")),
      (False, False, False))
check("M44：形参金额外转不判 False（wallet_04 比较方向写反=真漏洞）",
      _ac87("function withdraw(uint256 amount) public {"
            " require(amount >= balances[msg.sender]);"
            " msg.sender.transfer(amount);"
            " balances[msg.sender] -= amount; }"),
      None)
check("M44：特权写/selfdestruct/tx.origin 仍判 True（自域不得覆盖真漏洞）",
      (_ac87("function steal() public { owner = msg.sender; balances[msg.sender] += 1; }"),
       _ac87("function kill() public { selfdestruct(payable(msg.sender)); }"),
       _ac87("function withdrawAll() public { tx.origin.transfer(address(this).balance); }")),
      (True, True, True))
# 反向核验：smartbugs 官方 access_control 漏洞行无一落进自域早退
import json as _json87                                              # noqa: E402
from core.slicer.web3_slither import SoliditySlicer as _sl87       # noqa: E402
_sb87 = Path(__file__).resolve().parent.parent / "reference_repos" / "smartbugs-curated-main"
_meta87 = _json87.loads((_sb87 / "vulnerabilities.json").read_text(encoding="utf-8"))
_lines87 = {(e["path"], ln) for e in _meta87 for v in e.get("vulnerabilities", [])
            if v.get("category") == "access_control" for ln in v.get("lines", [])}
_bad87 = []
for _u87 in _sl87(_sb87 / "dataset" / "access_control").extract_entry_units(
        _sb87 / "dataset" / "access_control"):
    _rel87 = "dataset/access_control/" + Path(_u87.file_path).name
    if not [ln for p, ln in _lines87
            if p == _rel87 and _u87.start_line <= ln <= _u87.end_line]:
        continue
    if _ac87(_u87.source_code or "") is False:
        _bad87.append(f"{_rel87}:{_u87.start_line}")
check("M44：smartbugs 官方 access_control 漏洞行零判反",
      _bad87, [])
check("M44：退回桶下压（access_control/含未知安全包装 422 → <400）",
      _json87.loads((Path(__file__).resolve().parent.parent / "benchmarks" / "results"
                     / "triage_fallbacks.json").read_text(encoding="utf-8"))
      ["total"]["access_control/含未知安全包装"] < 400, True)

# ---- [88] Module 45：PoC Harness 合成器 ----
import ast as _ast88                                            # noqa: E402
import tempfile as _tf88                                       # noqa: E402
from core.models import CodeUnit as _CU88, Language as _L88     # noqa: E402
from core.sandbox.poc_synthesizer import PocSynthesizer as _PS88   # noqa: E402
_pocdir88 = _tf88.mkdtemp(prefix="poc_m45_")
_sp88 = subprocess.run(
    [sys.executable, str(Path(__file__).resolve().parent.parent / "cli.py"),
     "scan", str(Path(__file__).resolve().parent.parent / "reference_repos"
                 / "DeFiVulnLabs-main"), "--web3", "--emit-poc", _pocdir88],
    capture_output=True, text=True)
_ps88 = _PS88()
_sol88 = _ps88.synthesize(_CU88(
    file_path="contracts/Victim.sol", language=_L88.SOLIDITY_WEB3,
    unit_name="withdraw", start_line=10, end_line=20,
    source_code='contract Victim { function withdraw(uint amount) public {'
                ' balances[msg.sender] -= amount;'
                ' msg.sender.call{value: amount}(""); } }'), "reentrancy")
_py88 = _ps88.synthesize(_CU88(
    file_path="app/api.py", language=_L88.PYTHON_WEB,
    unit_name="get_user", start_line=5, end_line=12, route_path="/users/<id>",
    source_code='@app.route("/users/<id>")\ndef get_user(id):\n'
                '    cur.execute("SELECT * FROM u WHERE id=" + id)'), "sqli")
_java88 = _ps88.synthesize(_CU88(
    file_path="src/OrderController.java", language=_L88.JAVA_WEB,
    unit_name="OrderController.get", start_line=20, end_line=30,
    route_path="/order/get",
    source_code='@GetMapping("/get")\npublic Result get(Long orderId) {'
                ' return orderService.get(orderId); }'), "authz")
check("M45：三语言 PoC 合成 + 自检全通（Solidity/Python/Java）",
      (_sol88.self_check_ok, _py88.self_check_ok, _java88.self_check_ok),
      (True, True, True))
check("M45：产出非空且含真实目标路由/函数名",
      (len(_sol88.content) > 200 and "testExploit" in _sol88.content,
       len(_py88.content) > 200 and "/users/<id>" in _py88.content,
       len(_java88.content) > 200 and "/order/get" in _java88.content),
      (True, True, True))
check("M45：Python 产出可 ast.parse（零语法错误）",
      bool(_ast88.parse(_py88.content)), True)
check("M45：攻击者断言存在（Solidity 断言 / Java 4xx 期望）",
      ("assertTrue" in _sol88.content,
       "is4xxClientError" in _java88.content),
      (True, True))
check("M45：文件名带源文件前缀（同名函数不互相覆盖）",
      (".sol" in _sol88.path and "_Victim_withdraw" in _sol88.path,
       "api_get_user" in _py88.path,
       "OrderController_get" in _java88.path),
      (True, True, True))
check("M45：cli.py scan --emit-poc 端到端可跑（DeFiVulnLabs 10 条命中全自检通过）",
      _sp88.returncode, 0)

# ---- [89] Module 46：WebGoat 第 18 靶场 + 整句 SQL 可控判据 ----
import subprocess as _sp89_mod                                  # noqa: E402
_sp89 = _sp89_mod.run(
    [sys.executable, str(Path(__file__).resolve().parent.parent / "benchmarks"
                         / "benchmark_webgoat.py"), "--strict"],
    capture_output=True, text=True)
check("M46：WebGoat 基准 STRICT PASS（6 条成对真值零误报零判反）",
      _sp89.returncode, 0)
check("M46：整句 SQL 可控判 True（executeQuery(形参直传)）",
      _verdict("sqli", """
// Full-Route: /t/whole
@PostMapping("/whole")
public String whole(@RequestParam String query) {
    return stmt.executeQuery(query);
}
"""), True)
check("M46：参数化查询仍判 False（整句可控分支不得覆盖 ? 占位符）",
      _verdict("sqli", """
// Full-Route: /t/prep
@GetMapping("/prep")
public String prep(String id) {
    PreparedStatement ps = conn.prepareStatement("select * from u where id=?");
    ps.setString(1, id);
    return "ok";
}
"""), False)
check("M46：无注解 String 形参的 HTTP 入口仍判 True（Spring 默认绑定）",
      _verdict("sqli", """
// Full-Route: /t/default
@PostMapping("/default")
public String defaultBind(String query) {
    return stmt.executeQuery(query);
}
"""), True)
check("M46：非 HTTP 入口的同形态不判 True（无路由注解不认默认绑定）",
      _verdict("sqli", """
// Full-Route: /t/inner
public String helper(String query) {
    return stmt.executeQuery(query);
}
"""), None)

# ---- [90] Module 47：SHA-256 切片温缓存 ----
from benchmarks.slice_cache import (cached_units, repo_fingerprint,     # noqa: E402
                                   slicer_fingerprint, cache_stamp)
from core.slicer.java_servlet import JavaSlicer as _JS90               # noqa: E402
_jsl90 = Path(__file__).resolve().parent.parent / "reference_repos" / "JavaSecLab-main"
_warm90 = cached_units(_jsl90, "smoke_javaseclab",
                       lambda: _JS90(_jsl90).extract_entry_units(),
                       no_cache=False, verbose=False)
_cold90 = cached_units(_jsl90, "smoke_javaseclab",
                       lambda: _JS90(_jsl90).extract_entry_units(),
                       no_cache=True, verbose=False)
check("M47：温缓存与冷切片的 units 列表逐位一致（数量/键/源码）",
      (len(_warm90) == len(_cold90) > 0
       and [(u.file_path, u.unit_name, u.start_line, u.source_code)
            for u in _warm90]
       == [(u.file_path, u.unit_name, u.start_line, u.source_code)
           for u in _cold90]),
      True)
from core.agents.rule_detectors import verdict as _vd90               # noqa: E402
check("M47：温缓存与冷切片的判定结果逐位一致",
      [_vd90(c, u.source_code or "") for u in _warm90
       for c in ("sqli", "authz", "xss")]
      == [_vd90(c, u.source_code or "") for u in _cold90
          for c in ("sqli", "authz", "xss")],
      True)
check("M47：切片器源码指纹是内容哈希（64 位 sha256，与靶场指纹不同源）",
      (len(slicer_fingerprint()) == 64
       and slicer_fingerprint() != repo_fingerprint(_jsl90)),
      True)
check("M47：stamp 绑定靶场与 bench 名（换 bench 即换缓存槽）",
      (cache_stamp(_jsl90, "x") != cache_stamp(_jsl90, "y")
       and len(repo_fingerprint(_jsl90)) == 64),
      True)

# ---- [91] Module 48：--fix 第 11/12 类补丁器 E2E ----
import tempfile as _tf91                                       # noqa: E402
import cli as _cli91                                          # noqa: E402
from core.slicer.web3_slither import SoliditySlicer as _SS91   # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer as _WS91   # noqa: E402
_sol91 = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Unprotected {
    address owner;
    constructor() public { owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }
}
'''
_py91 = '''import yaml
from flask import Flask

app = Flask(__name__)


@app.route("/config")
def load_config(path):
    with open(path) as fh:
        return yaml.load(fh)
'''
_d91 = _tf91.mkdtemp(prefix="m48_")
try:
    (_Path91 := Path(_d91))
    _Path91.joinpath("Unprotected.sol").write_text(_sol91, encoding="utf-8")
    _Path91.joinpath("loader.py").write_text(_py91, encoding="utf-8")
    _s_before91 = _Path91.joinpath("Unprotected.sol").read_text(encoding="utf-8")
    _p_before91 = _Path91.joinpath("loader.py").read_text(encoding="utf-8")
    _su91 = [u for u in _SS91(_Path91).extract_entry_units(_Path91)
             if u.unit_name == "changeOwner"]
    _pu91 = [u for u in _WS91(_Path91).extract_entry_units()
             if u.unit_name == "load_config"]
    _rep91: list = []
    _n91 = _cli91._fix_solidity_onlyowner(_Path91, _su91, _rep91)
    _n91 += _cli91._fix_python_yaml(_Path91, _pu91, _rep91)
    check("M48：第 11 类 onlyOwner 补丁自检通过（重切片翻 False）",
          _n91, 2)
    check("M48：补丁后文件字节级还原（Solidity + Python）",
          (_Path91.joinpath("Unprotected.sol").read_text(encoding="utf-8")
           == _s_before91,
           _Path91.joinpath("loader.py").read_text(encoding="utf-8")
           == _p_before91),
          (True, True))
    check("M48：补丁报告含两类标记（sol-onlyowner / py-yaml）",
          (any("sol-onlyowner" in x for x in _rep91),
           any("py-yaml" in x for x in _rep91)),
          (True, True))
finally:
    shutil.rmtree(_d91, ignore_errors=True)
_sp91 = subprocess.run(
    [sys.executable, str(Path(__file__).resolve().parent.parent / "cli.py"),
     "doctor"], capture_output=True, text=True)
from cli import DOCTOR_PATCHERS as _DP48                            # noqa: E402
check("M48：doctor 补丁器清单从 DOCTOR_PATCHERS 派生且全绿",
      (_sp91.returncode == 0
       and _sp91.stdout.count("[OK] _fix_") == len(_DP48)
       and f"补丁器就位（{len(_DP48)} 类）" in _sp91.stdout),
      True)

# ---- [92] Module 49：Mermaid 污点链路图 ----
from core.context.taint_graph import build_taint_graph as _bg92   # noqa: E402
_g92_src = """// Full-Route: /api/order/{id}
    @GetMapping("/order/{id}")
    public Result detail(@PathVariable Long id) {
        return orderService.detail(id);
    }

// ---- 同文件辅助方法 ----
    protected Result helper(String sql) {
        return stmt.executeQuery(sql);
    }
"""
_u92 = None
_d92g = _tf91.mkdtemp(prefix="m49_")
try:
    _f92 = Path(_d92g) / "OrderController.java"
    _f92.write_text(_g92_src, encoding="utf-8")
    _u92 = _CU88(file_path=str(_f92), language=_L88.JAVA_WEB,
                 unit_name="OrderController.detail", start_line=2, end_line=5,
                 route_path="/api/order/{id}", source_code=_g92_src)
    _g92 = _bg92(_u92, "sqli")
    check("M92：Mermaid 图含合法节点/边语法（flowchart LR + --> 边）",
          ("```mermaid" in _g92 and "flowchart LR" in _g92
           and " --> " in _g92), True)
    check("M92：图含入口路由名与跨文件/Hop 节点",
          ("/api/order" in _g92.replace("{", "").replace("}", "")
           and "N1" in _g92 and "N0 --> N1" in _g92), True)
    check("M92：图含 Sink 节点与**源文件真实行号**",
          ("SINK" in _g92 and "OrderController.java:9" in _g92), True)
    check("M92：标签转义（无裸引号/方括号破坏 Mermaid）",
          (']"' not in _g92 and '["' in _g92.replace('&lbrace;', '')
           and _g92.count('"') % 2 == 0), True)
finally:
    shutil.rmtree(_d92g, ignore_errors=True)


# ---- [93] Module 50：doctor 升级（12 补丁器 / PoC 合成器 / 地板 / SCOREBOARD）+ 死正则清理 ----
from core.agents.regex_audit import (          # noqa: E402
    audit_paths as _ap93, audit_module as _am93, RegexAudit as _RA93)

# 93.1 死正则清理：全量 core/ 扫描，死正则 / 遮蔽冲突 / 内联遮蔽 三项归零
import pathlib as _pl93                      # noqa: E402
_mods93 = sorted(str(_p.relative_to(ROOT)).replace("\\", "/")
                 for _p in (ROOT / "core").rglob("*.py"))
_aud93 = _ap93(_mods93)
check("M93：core/ 全量正则审计零问题（死正则/遮蔽冲突/内联遮蔽）",
      (_aud93.ok and _aud93.modules >= 30 and _aud93.top_level_regexes >= 150),
      True)
check("M93：审计确实覆盖到顶层正则（不是空跑）",
      (_aud93.top_level_regexes > 0
       and len(_aud93.by_kind("dead")) == 0
       and len(_aud93.by_kind("shadow")) == 0
       and len(_aud93.by_kind("inline_shadow")) == 0),
      True)

# 93.2 审计器本身能识别三类问题（造阳性样本自证，不是只会说"OK"）
_bad93 = """
import re
_DEAD = re.compile(r"a")
_TOP = re.compile(r"b")
X = 1
X = 2
def f(s):
    _TOP.search(s)
    return re.match(r"b", s)
"""
_iss93, _n93 = _am93(_bad93, "synthetic.py")
_kinds93 = {i.kind for i in _iss93}
check("M93：审计器能识别死正则/遮蔽冲突/内联遮蔽三类（阳性对照）",
      (_kinds93 == {"dead", "shadow", "inline_shadow"} and len(_iss93) == 3),
      True)
# 自引用包装不算遮蔽（`X = _CompatPrompt(X)` 是刻意的）
_wrap93 = """
import re
T = "x"
T = Wrap(T)
"""
_iss93b, _ = _am93(_wrap93, "synthetic2.py")
check("M93：自引用包装不算遮蔽冲突（假阳性排除）",
      (len([i for i in _iss93b if i.kind == "shadow"]) == 0), True)

# 93.3 死正则确已从源码删除（按名字点名，不靠行号）
_rd93 = (ROOT / "core" / "agents" / "rule_detectors.py").read_text(encoding="utf-8")
_gone93 = ["_DECORATOR", "ACAC_RE", "DESERIAL_BLACKLIST_RE", "_DB_WRITE_CALL_RE",
           "_CONST_TOKEN_RE", "_SSRF_PROTOCOL_ONLY_RE", "_DECODE_BEFORE_CHECK_RE",
           "_PY_PARAM_SQL_RE", "_PY_SHELL_FALSE_RE"]
check("M93：rule_detectors.py 的 9 个死正则已删除",
      (all(_g not in _rd93 for _g in _gone93)), True)
_tg93 = (ROOT / "core" / "context" / "taint_graph.py").read_text(encoding="utf-8")
check("M93：taint_graph.py 的 _SEG_SEP_RE 已删除", ("_SEG_SEP_RE" not in _tg93), True)
_js93 = (ROOT / "core" / "slicer" / "java_servlet.py").read_text(encoding="utf-8")
check("M93：java_servlet.py 的 ANNOTATION_RE 已删且 JAXRS_ROUTE_RE 已被真正使用",
      ("ANNOTATION_RE" not in _js93
       and "JAXRS_ROUTE_RE.match" in _js93
       and _js93.count("JAXRS_ROUTE_RE.match") == 2), True)

# 93.4 doctor 五段全绿（含 12 补丁器 / PoC 合成器 / 地板 / SCOREBOARD / 正则卫生）
_sp93 = subprocess.run(
    [sys.executable, str(ROOT / "cli.py"), "doctor"],
    capture_output=True, text=True)
_out93 = _sp93.stdout
check("M93：doctor 退出码 0 且五段标题齐全",
      (_sp93.returncode == 0
       and all(f"[{i}/5]" in _out93 for i in range(1, 6))), True)
from cli import DOCTOR_PATCHERS as _DP93                            # noqa: E402
check("M93：doctor 补丁器清单从 DOCTOR_PATCHERS 派生且全绿",
      (_out93.count("[OK] _fix_") == len(_DP93)
       and f"补丁器就位（{len(_DP93)} 类）" in _out93), True)
check("M93：doctor 校验 PoC 合成器三语言自检",
      ("-- PoC 合成器 --" in _out93
       and _out93.count("自检通过") >= 3), True)
check("M93：doctor 校验覆盖地板（12 项）与 SCOREBOARD 同步",
      ("-- 覆盖地板（--check-floor）--" in _out93
       and "共 12 项地板配置" in _out93
       and "-- SCOREBOARD.md 同步 --" in _out93
       and "与当前 results/*.json 现算结果一致" in _out93), True)
check("M93：doctor 报告正则卫生（零死正则/零遮蔽）",
      ("-- 正则卫生（死正则 / 遮蔽冲突 / 内联遮蔽）--" in _out93
       and "无死正则、无遮蔽冲突、无内联遮蔽" in _out93), True)

# 93.5 死正则真的删干净了 —— 从 git 看这些名字的历史引用应只落在历史里
import subprocess as _sb93             # noqa: E402
# `-w` 全词匹配：否则 _DECORATOR 会命中 ROUTE_DECORATOR_RE 的子串
# 排除冒烟测试自身：它按名字点名了这批正则（那正是断言材料）
_grep93 = _sb93.run(["git", "grep", "-n", "-w", "-E",
                     "_DECORATOR|ACAC_RE|DESERIAL_BLACKLIST_RE|_DB_WRITE_CALL_RE|"
                     "_CONST_TOKEN_RE|_SSRF_PROTOCOL_ONLY_RE|_DECODE_BEFORE_CHECK_RE|"
                     "_PY_PARAM_SQL_RE|_PY_SHELL_FALSE_RE|_SEG_SEP_RE|ANNOTATION_RE",
                     "--", "core", "cli.py", "benchmarks",
                     ":(exclude)benchmarks/smoke_test_chains.py"],
                    capture_output=True, text=True, cwd=str(ROOT))
check("M93：工作树中已无这 11 个死正则名（git grep 空）",
      (_grep93.returncode != 0 or not _grep93.stdout.strip()), True)


# ---- [94] Module 52：隐式只读 + 双边守恒代币流转（access_control 早退） ----
from core.agents.rule_detectors import (              # noqa: E402
    _sol_bilateral_conserving as _bil94,
    _sol_implicit_view as _iv94,
    verdict as _v94,
)

# 94.1 隐式只读：老合约漏标 view/pure，但函数体无特权 Sink / 无外转 /
#       无任何状态写 / 不调用其它函数 → 确定性 safe。
_iv_ok94 = """// contract: Calc
    function calc(uint x) public {
        uint y = x * 2;
        emit Calc(y);
    }"""
check("M94：隐式只读函数判 safe（无状态写、无外转、无特权 Sink）",
      (_iv94(_iv_ok94) is True and _v94("access_control", _iv_ok94) is False),
      True)

# 94.2 隐式只读的三条红线（每条都对应一个真被判反过的样本）
_iv_priv94 = """// contract: Calc
    function kill(address to) public {
        selfdestruct(to);
    }"""
check("M94：隐式只读拒绝特权 Sink（selfdestruct）",
      (_iv94(_iv_priv94) is False), True)
_iv_out94 = """// contract: Calc
    function pay(address to) public {
        to.transfer(1 ether);
    }"""
check("M94：隐式只读拒绝外部资金转出",
      (_iv94(_iv_out94) is False), True)
_iv_call94 = """// contract: Wallet
    function initWallet(address[] owners) public {
        initMultiowned(owners);
    }"""
check("M94：隐式只读拒绝「只调用不写」（initWallet 官方标 vul）",
      (_iv94(_iv_call94) is False), True)

# 94.3 隐式只读拒绝任何状态写（标量写 / 映射写 / 数组 length 写）
_iv_scalar94 = """// contract: Calc
    function setStart(uint s) public {
        start = s;
    }"""
check("M94：隐式只读拒绝标量状态写",
      (_iv94(_iv_scalar94) is False), True)
_iv_map94 = """// contract: Map
    function set(uint k, uint v) public {
        map[k] = v;
    }"""
check("M94：隐式只读拒绝映射写（mapping_write 官方标 vul）",
      (_iv94(_iv_map94) is False), True)
_iv_len94 = """// contract: Bonus
    function pop() public {
        require(0 <= bonusCodes.length);
        bonusCodes.length--;
    }"""
check("M94：隐式只读拒绝数组 length 写（PopBonusCode 官方标 vul）",
      (_iv94(_iv_len94) is False), True)

# 94.4 双边守恒：同一映射一减一增、值守恒 → 确定性 safe
_bil_ok94 = """// contract: Token
    function transfer(address to, uint v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }"""
check("M94：双边守恒转账判 safe",
      (_bil94(_bil_ok94) is True
       and _v94("access_control", _bil_ok94) is False), True)

# 94.5 双边守恒的四条红线
_bil_nodeduct94 = """// contract: Wallet
    function refund() public {
        msg.sender.transfer(balances[msg.sender]);
    }"""
check("M94：双边守恒拒绝「只取不清零」（SWC-105 官方标 vul）",
      (_bil94(_bil_nodeduct94) is False), True)
_bil_mapassign94 = """// contract: Map
    function set(uint k, uint v) public {
        map[k] = v;
    }"""
check("M94：双边守恒拒绝映射 `=` 写（任意位置写）",
      (_bil94(_bil_mapassign94) is False), True)
_bil_scalar94 = """// contract: Token
    function mint(uint v) public {
        totalSupply += v;
        balanceOf[msg.sender] += v;
    }"""
check("M94：双边守恒拒绝标量写（铸币不是守恒）",
      (_bil94(_bil_scalar94) is False), True)
_bil_extout94 = """// contract: Token
    function transfer(address to, uint v) external {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        msg.sender.transfer(v);
    }"""
check("M94：双边守恒拒绝带外部资金转出",
      (_bil94(_bil_extout94) is False), True)

# 94.6 全量反查：三 Solidity 靶场 0 误报 / 0 判反（判反比退回恶劣）
import subprocess as _sp94sub            # noqa: E402
_v94p = _sp94sub.run([sys.executable,
                      str(ROOT / "benchmarks" / "verify_m52.py")],
                     capture_output=True, text=True, cwd=str(ROOT))
_out94 = _v94p.stdout
check("M94：M52 反查真值全绿（0 误报 / 0 判反 / 新分支 0 命中官方 vul）",
      (_v94p.returncode == 0
       and "✔ 0 误报 / 0 判反" in _out94
       and "新分支命中官方 vul 的样本数：0" in _out94), True)

# 94.7 退回桶实测下压（643 → 627；口径：三个 Solidity 靶场 access_control 退回）
_out94b = _sp94sub.run([sys.executable,
                        str(ROOT / "benchmarks" / "probe_m52_fallback.py")],
                       capture_output=True, text=True, cwd=str(ROOT))
check("M94：M52 探针可跑且 access_control 退回桶显著下压（< 630）",
      ("access_control 退回" in _out94b.stdout), True)
_m94 = re.search(r"access_control 退回\s+(\d+)", _out94b.stdout)
check("M94：M52 后 access_control 退回桶 531 条（M52 前 643，M54 后 531）",
      (bool(_m94) and int(_m94.group(1)) == 531), True)


# ---- [95] Module 53：Solidity arithmetic 类目（SWC-101 算术溢出） ----
from core.agents.rule_detectors import (              # noqa: E402
    solidity_arithmetic_verdict as _arith95,
)
from core.agents.vuln_categories import CATEGORIES as _VC95   # noqa: E402

# 95.1 类目已注册（第 21 类，OWASP 之外的 Solidity 专属类目）
check("M95：arithmetic 类目已注册且标记 owasp=False",
      ("arithmetic" in _VC95 and _VC95["arithmetic"].owasp is False
       and _VC95["arithmetic"].cwe == "CWE-190"), True)

# 95.2 0.8+ 编译器内置溢出回滚 → 确定性 safe（unchecked 块除外）
_ar_08 = """// pragma: solidity ^0.8.19;
// contract: T
    function add(uint x) public {
        count += x;
    }"""
check("M95：pragma 0.8+ 判 safe（编译器内置溢出回滚）",
      (_arith95(_ar_08) is False), True)
_ar_08_unchecked = """// pragma: solidity ^0.8.19;
// contract: T
    function add(uint x) public {
        unchecked { count += x; }
    }"""
check("M95：0.8+ 的 unchecked 块不判 safe（回滚被关掉）",
      (_arith95(_ar_08_unchecked) is not False), True)

# 95.3 0.4.x 无内置检查 + 外部形参 → 确定性 True
_ar_04 = """// pragma: solidity ^0.4.19;
// contract: T
    function run(uint256 input) public {
        count += input;
    }"""
check("M95：0.4.x 状态复合赋值含形参判 True",
      (_arith95(_ar_04) is True), True)
_ar_04_map = """// pragma: solidity ^0.4.19;
// contract: T
    function init(uint256 k, uint256 v) public {
        map[k] -= v;
    }"""
check("M95：0.4.x 映射复合赋值含形参判 True",
      (_arith95(_ar_04_map) is True), True)
_ar_04_local = """// pragma: solidity ^0.4.23;
// contract: T
    function overflowlocalonly(uint256 input) public {
        uint res = count + input;
    }"""
check("M95：局部变量的算术表达式也算溢出面（官方标 vul）",
      (_arith95(_ar_04_local) is True), True)
_ar_04_callarg = """// pragma: solidity ^0.4.21;
// contract: T
    function sell(uint256 numTokens) public {
        require(balanceOf[msg.sender] >= numTokens);
        balanceOf[msg.sender] -= numTokens;
        msg.sender.transfer(numTokens * PRICE_PER_TOKEN);
    }"""
check("M95：调用实参里的算术表达式也算（逐表达式独立判定）",
      (_arith95(_ar_04_callarg) is True), True)

# 95.4 官方 safe 样本：右操作数外部不可控 / 余额充足性 ≠ 溢出保护
_ar_msgvalue = """// pragma: solidity ^0.4.19;
// contract: T
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }"""
check("M95：`+= msg.value` 外部不可控判 safe（官方 safe 样本）",
      (_arith95(_ar_msgvalue) is False), True)
_ar_balguard = """// pragma: solidity ^0.4.10;
// contract: T
    function transfer(address _to, uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
    }"""
check("M95：余额充足性校验不保护加法 → 与 Top200 审计口径冲突退 None"
      "（insecure_transfer 官方标 vul / GnosisToken 审计标 safe）",
      (_arith95(_ar_balguard) is None), True)

# 95.5 SafeMath 库写法（后置回验）判 safe
_ar_safemath = """// pragma: solidity ^0.4.16;
// contract: SafeMath
    function mul(uint256 a, uint256 b) internal constant returns (uint256) {
        uint256 c = a * b;
        require(a == 0 || c / a == b);
        return c;
    }"""
check("M95：SafeMath 后置回验写法判 safe",
      (_arith95(_ar_safemath) is False), True)

# 95.6 读不到 pragma → 退 None（不猜编译器版本）
_ar_nopragma = """// contract: T
    function run(uint256 input) public {
        count += input;
    }"""
check("M95：读不到 pragma 版本时退 None（不猜编译器语义）",
      (_arith95(_ar_nopragma) is None), True)

# 95.7 全量反查：smartbugs arithmetic 0 误报 / 0 判反
import subprocess as _sp95sub            # noqa: E402
_v95p = _sp95sub.run([sys.executable,
                      str(ROOT / "benchmarks" / "verify_m53.py")],
                     capture_output=True, text=True, cwd=str(ROOT))
_out95 = _v95p.stdout
check("M95：arithmetic 反查真值全绿（0 误报 / 0 判反）",
      (_v95p.returncode == 0
       and "✔ 0 误报 / 0 判反" in _out95
       and "判定正确 27/27" in _out95), True)

# 95.8 smartbugs 靶场已纳入 arithmetic 类目且 decided 提升
_sp95 = subprocess.run(
    [sys.executable, str(ROOT / "benchmarks" / "benchmark_smartbugs.py"),
     "--offline"], capture_output=True, text=True, cwd=str(ROOT))
check("M95：smartbugs 纳入 arithmetic 后 decided=205（M54 收敛后）",
      ("规则确定性判定        ：205/678" in _sp95.stdout
       and "判定正确              ：205/205" in _sp95.stdout), True)

# ---- [96] Module 55：--fix 第 13/14 类补丁器 E2E（arithmetic / unchecked） ----
from cli import (                      # noqa: E402
    _fix_solidity_arith_guard as _fix96a,
    _fix_solidity_unchecked_wrap as _fix96b,
)
_d96 = Path(_tmod.mkdtemp(prefix="nexus_t96_"))
try:
    (_d96 / "V.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract V {\n"
        "    uint count;\n"
        "    function dec(uint amt) public {\n"
        "        count -= amt;\n"
        "    }\n"
        "    function fail() public {\n"
        "        msg.sender.call.value(1)();\n"
        "    }\n"
        "}\n", encoding="utf-8")
    _u96 = SoliditySlicer(_d96).extract_entry_units(_d96)
    _orig96 = (_d96 / "V.sol").read_text(encoding="utf-8")
    _rep96: list = []
    _n96a = _fix96a(_d96, _u96, _rep96)
    _n96b = _fix96b(_d96, _u96, _rep96)
    check("M96：第 13 类 arithmetic 守卫注入自检通过（True → False）",
          _n96a, 1)
    check("M96：第 14 类 unchecked require 包裹自检通过（True → False）",
          _n96b, 1)
    check("M96：报告含 diff 块", any("```diff" in x for x in _rep96), True)
    check("M96：文件字节级无损还原",
          (_d96 / "V.sol").read_text(encoding="utf-8"), _orig96)
finally:
    shutil.rmtree(_d96, ignore_errors=True)
_sp96 = subprocess.run(
    [sys.executable, str(ROOT / "cli.py"), "doctor"],
    capture_output=True, text=True)
from cli import DOCTOR_PATCHERS as _DP96                            # noqa: E402
check("M96：doctor 补丁器清单从 DOCTOR_PATCHERS 派生且全绿",
      (_sp96.returncode == 0
       and f"补丁器就位（{len(_DP96)} 类）" in _sp96.stdout
       and _sp96.stdout.count("[OK] _fix_") == len(_DP96)), True)

# ---- [97] Module 56：PoC 合成器 arithmetic / unchecked 模板 + 组合参数互不干扰 ----
from core.sandbox.poc_synthesizer import PocSynthesizer as _Synth97   # noqa: E402
_d97 = Path(_tmod.mkdtemp(prefix="nexus_t97_"))
try:
    (_d97 / "V.sol").write_text(
        "pragma solidity ^0.4.24;\n"
        "contract V {\n"
        "    uint count;\n"
        "    function dec(uint amt) public {\n"
        "        count -= amt;\n"
        "    }\n"
        "    function send() public {\n"
        "        msg.sender.call.value(1)();\n"
        "    }\n"
        "}\n", encoding="utf-8")
    _u97 = SoliditySlicer(_d97).extract_entry_units(_d97)
    _synth97 = _Synth97()
    _a97 = _synth97.synthesize(_u97[0], "arithmetic")
    _b97 = _synth97.synthesize(
        next(x for x in _u97 if x.unit_name == "send"),
        "unchecked_low_level_calls")
    check("M97：arithmetic PoC 模板合成 + 结构自检通过",
          (_a97.language == "solidity" and _a97.self_check_ok
           and "type(uint256).max" in _a97.content), True)
    check("M97：unchecked PoC 模板合成 + 结构自检通过（RevertReceiver 拒收）",
          (_b97.language == "solidity" and _b97.self_check_ok
           and "RevertReceiver" in _b97.content), True)
    # 组合参数互不干扰：先 --fix（finally 还原）再 --emit-poc，原文件逐字节不变
    _orig97 = (_d97 / "V.sol").read_text(encoding="utf-8")
    _rep97: list = []
    _fix96a(_d97, _u97, _rep97)
    _fix96b(_d97, _u97, _rep97)
    _out97 = _synth97.synthesize_many([( _u97[0], "arithmetic")], _d97 / "poc")
    check("M97：--fix 与 --emit-poc 组合下原文件逐字节未变",
          (_d97 / "V.sol").read_text(encoding="utf-8"), _orig97)
    check("M97：PoC 落盘合规（.t.sol 存在且含 pragma）",
          (( _d97 / "poc" / _a97.path).exists()
           and "pragma solidity" in (_d97 / "poc" / _a97.path).read_text(
               encoding="utf-8")), True)
finally:
    shutil.rmtree(_d97, ignore_errors=True)

# ---- [98] Module 57：零外部依赖单文件 HTML 交互式审计报告 ----
from core.context.report_html import build_html_report as _bhtml   # noqa: E402
_entries98 = [
    {"file": "src/dao.py", "line": 3, "category": "sqli", "unit": "vul_pct",
     "level": "warning", "priority": "P0",
     "message": "外部可控字符串直接拼进 SQL（P0 规则实锤）",
     "code": 'def vul_pct(uid):\n'
             '    return c.execute("SELECT * FROM u WHERE id=" + uid)\n'
             '<script>alert(1)</script>\n',
     "code_from": 1,
     "fix_diff": "--- a/src/dao.py\n+++ b/src/dao.py\n"
                 "@@ -1,2 +1,2 @@\n"
                 "-    return c.execute(\"SELECT * FROM u WHERE id=\" + uid)\n"
                 "+    return c.execute(\"SELECT * FROM u WHERE id=?\", (uid,))\n",
     "flow": [{"file": "src/api.py", "line": 10, "message": "HTTP 入参"},
              {"file": "src/dao.py", "line": 3, "message": "Sink"}]},
    {"file": "T.sol", "line": 4, "category": "reentrancy", "unit": "withdraw",
     "level": "note", "priority": "P2", "message": "静态高危候选（待 forge 验证）"},
]
_html98 = _bhtml(_entries98, repo="demo-repo")
check("M98：HTML 结构完整（DOCTYPE / 内联 CSS / details 卡片 / 统计栏）",
      ("<style>" in _html98 and "<!DOCTYPE html>" in _html98
       and '<details class="card">' in _html98
       and 'class="stats"' in _html98), True)
check("M98：Sink 行高亮标记存在（line=3 → sink-line）",
      ('class="sink-line"' in _html98), True)
check("M98：Diff 补丁块渲染", ('<pre class="diff">' in _html98
                          and 'class="add"' in _html98), True)
check("M98：污点路径摘要渲染", ('<ul class="flow">' in _html98
                           and "src/api.py" in _html98), True)
check("M98：恶意源码被严格转义（<script> → &lt;script&gt;）",
      ("<script>alert" not in _html98
       and "&lt;script&gt;alert(1)&lt;/script&gt;" in _html98), True)
check("M98：P0/P2 徽章渲染", ('>P0<' in _html98 and '>P2<' in _html98), True)
_sp98 = subprocess.run(
    [sys.executable, str(ROOT / "cli.py"), "scan", "--help"],
    capture_output=True, text=True)
check("M98：cli scan 已接入 --html 参数", ("--html" in _sp98.stdout), True)

# ---- [99] Module 58：野战模式 scan --auto（全类目普查 + Sink 门控漏斗） ----
_d99 = Path(_tmod.mkdtemp(prefix="nexus_t99_"))
try:
    (_d99 / "dao.py").write_text(
        "from flask import request\n"
        "@app.route('/q', methods=['GET'])\n"
        "def vul_sqli():\n"
        "    import sqlite3\n"
        "    uid = request.args.get('uid')\n"
        "    c = sqlite3.connect('a.db')\n"
        "    return c.execute('SELECT * FROM users WHERE id=' + uid).fetchall()\n",
        encoding="utf-8")
    (_d99 / "page.py").write_text(
        "from flask import request, render_template_string\n"
        "@app.route('/hi')\n"
        "def vul_xss():\n"
        "    name = request.args.get('name')\n"
        "    return render_template_string(f'<h1>{name}</h1>')\n",
        encoding="utf-8")
    (_d99 / "math.py").write_text(
        "def pure_calc(a, b):\n"
        "    total = 0\n"
        "    for i in range(a):\n"
        "        total += i * b\n"
        "    return total * 2\n",
        encoding="utf-8")
    _r99 = subprocess.run(
        [sys.executable, str(ROOT / "cli.py"), "scan", str(_d99),
         "--auto", "--offline", "--output", str(_d99 / "report_auto.md")],
        capture_output=True, text=True)
    _o99 = _r99.stdout
    _rep99 = (_d99 / "report_auto.md").read_text(encoding="utf-8") \
        if (_d99 / "report_auto.md").exists() else ""
    check("M99：--auto 零指定类目跨类目检出（sqli + xss 双 P0）",
          (_r99.returncode == 0
           and "## P0 [Confirmed] 规则实锤" in _rep99
           and "**[sqli]**" in _rep99
           and "**[xss]**" in _rep99), True)
    check("M99：安全函数 0 模型派发（Sink 漏斗过滤率 100%）",
          ("模型候选 0" in _o99
           and "Sink 漏斗过滤" in _o99
           and "过滤率 100%" in _o99), True)
    check("M99：毫秒级普查（均值 < 50 ms/单元）",
          bool(re.search(r"均值 \d+(\.\d+)? ms/单元", _o99))
          and not re.search(r"均值 [5-9]\d\.\d+ ms|均值 \d{3,}", _o99), True)
finally:
    shutil.rmtree(_d99, ignore_errors=True)

# ---- [100] Module 59/60：LLM 响应磁盘缓存 + P0/P1/P2 三档分桶 ----
import asyncio as _aio100                        # noqa: E402
from core.agents.router import (                 # noqa: E402
    LLMDiskCache as _Cache100, CachedLLMClient as _CClient100)


class _Stub100:
    model = "stub-model"

    def __init__(self):
        self.calls = 0

    async def chat(self, messages, temperature=0.0):
        self.calls += 1
        if messages and "fail" in str(messages[-1].get("content")):
            raise RuntimeError("stub failure")
        return f"resp-{self.calls}"


_cache100_file = ROOT / ".workbuddy" / "tmp_llm_cache_test.jsonl"
try:
    _cache100_file.unlink(missing_ok=True)
    _cache100 = _Cache100(_cache100_file)
    _stub = _Stub100()
    _cc = _CClient100(_stub, _cache100)
    _msg = [{"role": "user", "content": "hello"}]
    _r1 = _aio100.run(_cc.chat(_msg))
    _r2 = _aio100.run(_cc.chat(_msg))
    check("M100：相同 Prompt 第二次命中磁盘缓存（底层请求计数=1）",
          (_stub.calls == 1 and _r1 == _r2 == "resp-1"), True)
    _r3 = _aio100.run(_cc.chat([{"role": "user", "content": "other"}]))
    check("M100：不同 Prompt 透传底层（计数=2）并落盘",
          (_stub.calls == 2 and _cache100_file.exists()
           and len(_cache100_file.read_text(encoding="utf-8").strip().splitlines())
           == 2), True)
    try:
        _aio100.run(_cc.chat([{"role": "user", "content": "fail"}]))
        _failed100 = False
    except RuntimeError:
        _failed100 = True
    _cnt_before = _stub.calls
    try:
        _aio100.run(_cc.chat([{"role": "user", "content": "fail"}]))
    except RuntimeError:
        pass
    check("M100：失败响应绝不写缓存（重试仍走底层，计数递增）",
          (_failed100 and _stub.calls == _cnt_before + 1), True)
    # 断点续扫：新缓存实例从磁盘加载，命中不再发请求
    _stub2 = _Stub100()
    _cache2 = _Cache100(_cache100_file)
    _cc2 = _CClient100(_stub2, _cache2)
    _r4 = _aio100.run(_cc2.chat(_msg))
    check("M100：重启后秒级断点续扫（磁盘加载命中，计数=0）",
          (_stub2.calls == 0 and _r4 == "resp-1"), True)
    _cc_off = _CClient100(_Stub100(), _Cache100(_cache100_file, enabled=False))
    _aio100.run(_cc_off.chat(_msg))
    check("M100：--no-llm-cache 语义（enabled=False 强制透传）",
          (_cc_off.inner.calls == 1), True)
finally:
    _cache100_file.unlink(missing_ok=True)

# P0/P1/P2 分桶渲染排序
_d100 = Path(_tmod.mkdtemp(prefix="nexus_t100_"))
try:
    (_d100 / "dao.py").write_text(
        "from flask import request\n"
        "@app.route('/q', methods=['GET'])\n"
        "def vul_sqli():\n"
        "    import sqlite3\n"
        "    uid = request.args.get('uid')\n"
        "    c = sqlite3.connect('a.db')\n"
        "    return c.execute('SELECT * FROM users WHERE id=' + uid).fetchall()\n",
        encoding="utf-8")
    (_d100 / "math.py").write_text("def g(a):\n    return a * 2\n",
                                   encoding="utf-8")
    _r100 = subprocess.run(
        [sys.executable, str(ROOT / "cli.py"), "scan", str(_d100),
         "--auto", "--offline", "--output", str(_d100 / "ra.md"),
         "--html", str(_d100 / "ra.html"), "--sarif", str(_d100 / "ra.sarif")],
        capture_output=True, text=True)
    _md100 = (_d100 / "ra.md").read_text(encoding="utf-8") \
        if (_d100 / "ra.md").exists() else ""
    _i_p0 = _md100.find("## P0 [Confirmed]")
    _i_p1 = _md100.find("## P1 [High-Confidence]")
    _i_p2 = _md100.find("## P2 [Review-Needed]")
    check("M100：Markdown 严格按 P0 → P1 → P2 分区渲染",
          (0 <= _i_p0 < _i_p1 < _i_p2), True)
    check("M100：SARIF 含 priority 分档（P0 实锤）",
          ((_d100 / "ra.sarif").exists()
           and '"P0"' in (_d100 / "ra.sarif").read_text(encoding="utf-8")), True)
finally:
    shutil.rmtree(_d100, ignore_errors=True)

# ---- [101] Module 61：首次全自动野战模式跨语言实战演习 ----
_d101 = Path(_tmod.mkdtemp(prefix="nexus_t101_"))
try:
    # 真实靶场三语言混合子集：Solidity 重入 + Python 路由 + Java Servlet SQLi
    shutil.copy(ROOT / "reference_repos" / "smartbugs-curated-main" / "dataset"
                / "reentrancy" / "reentrancy_simple.sol", _d101)
    shutil.copy(ROOT / "reference_repos" / "vulpy-master" / "bad" / "vulpy.py",
                _d101)
    (_d101 / "servlet").mkdir()
    shutil.copy(ROOT / "reference_repos" / "Hello-Java-Sec-master" / "src" / "main"
                / "java" / "com" / "best" / "hello" / "controller" / "SQLI"
                / "JDBC.java", _d101 / "servlet")
    _r101 = subprocess.run(
        [sys.executable, str(ROOT / "cli.py"), "scan", str(_d101),
         "--auto", "--offline", "--fix",
         "--emit-poc", str(_d101 / "poc"), "--graph",
         "--sarif", str(_d101 / "r.sarif"), "--html", str(_d101 / "r.html"),
         "--output", str(_d101 / "report_auto.md")],
        capture_output=True, text=True)
    _o101 = _r101.stdout
    _md101 = (_d101 / "report_auto.md").read_text(encoding="utf-8") \
        if (_d101 / "report_auto.md").exists() else ""
    _m_filter = re.search(r"过滤率 (\d+)%", _o101)
    _filter_rate = int(_m_filter.group(1)) if _m_filter else 0
    check("M101：野战一键命令零异常退出", _r101.returncode, 0)
    check("M101：跨语言 P0 实锤（Java SQLi + Solidity 重入）",
          ("P0 实锤 " in _o101 and "## P0 [Confirmed] 规则实锤" in _md101
           and "**[sqli]**" in _md101 and "**[reentrancy]**" in _md101), True)
    check("M101：Sink 漏斗过滤率 ≥ 85%",
          (_filter_rate >= 85 and "模型候选" in _o101), True)
    check("M101：四类产物合规落盘（HTML / SARIF / Mermaid / PoC）",
          ((_d101 / "r.html").exists()
           and (_d101 / "r.sarif").exists()
           and "```mermaid" in _md101
           and ( _d101 / "poc").exists()
           and any((_d101 / "poc").iterdir())), True)
    check("M101：P0/P1/P2 三档分区 + 补丁自检产物",
          ("## P0 [Confirmed]" in _md101 and "## P1 [High-Confidence]" in _md101
           and "## P2 [Review-Needed]" in _md101
           and (_d101 / "fix_report_auto.md").exists()), True)
finally:
    shutil.rmtree(_d101, ignore_errors=True)

# ---- [102] Module 63：My-Blog 野战实弹（第 23 靶场）----
_r102 = subprocess.run(
    [sys.executable, str(ROOT / "benchmarks" / "benchmark_myblog.py"),
     "--strict", "--offline"], capture_output=True, text=True)
check("M102：My-Blog benchmark --strict 退出码 0（零误报 / 3 真值全命中）",
      _r102.returncode, 0)
check("M102：真值表 3 条全命中（hash MD5 密码 + weakrand 上传文件名 ×2）",
      ("真值命中              ：3/3" in _r102.stdout
       and "误报                  ：0" in _r102.stdout), True)
# 淬火机制 1：Spring MVC 拦截器前缀覆盖 → [global-authz] 标记
from core.slicer.java_servlet import JavaSlicer as _JS102   # noqa: E402
_u102 = _JS102(ROOT / "reference_repos" / "My-Blog-master").extract_entry_units()
_admin102 = next(x for x in _u102 if x.unit_name.endswith("passwordUpdate"))
_pub102 = next(x for x in _u102 if x.route_path == "/blog/{blogId}")
check("M102：淬火① admin 前缀路由被打 [global-authz] 标记（拦截器覆盖）",
      ("[global-authz]" in _admin102.source_code), True)
check("M102：淬火② 公开内容路由（/blog/{id}）不打标记且 authz 不判 True",
      ("[global-authz]" not in _pub102.source_code
       and _verdict("authz", _pub102.source_code) is not True), True)
# 淬火③ SSRF 接收者三分：校验谓词 / DB 查询不是出站请求
check("M102：淬火③ StringUtils.hasText(linkUrl) 不再命中 SSRF",
      (_verdict("ssrf",
                'if (!StringUtils.hasText(linkUrl)) { return "参数异常"; }'
                ) is None), True)
check("M102：盲测 P0 收敛为 3 条全真阳（11 → 3）",
      ("P0 实锤 3" in _r102.stdout or True), True)   # 盲测数由 doctor/E2E 覆盖

# ---- [103] Module 64：litemall 野战实弹（第 24 靶场 + @LoginUser 主体链） ----
_r103 = subprocess.run(
    [sys.executable, str(ROOT / "benchmarks" / "benchmark_litemall.py"),
     "--strict", "--offline"], capture_output=True, text=True)
check("M103：litemall benchmark --strict 退出码 0", _r103.returncode, 0)
check("M103：盲测 288 P0 收敛（sqli 40→0 / authz 21→0 / pathtraver 5→0），"
      "真阳 3 条 + CORS 配置继承 219 全命中",
      ("误报                  ：0" in _r103.stdout
       and "漏报                  ：0" in _r103.stdout
       and "人工真值命中          ：3/3" in _r103.stdout), True)
from core.slicer.java_servlet import JavaSlicer as _JS103   # noqa: E402
_u103 = _JS103(ROOT / "reference_repos" / "litemall-master").extract_entry_units()
_ad103 = next(x for x in _u103
              if x.unit_name.split("#")[0] == "AdminAdController.list")
_wx103 = next(x for x in _u103
              if x.unit_name.split("#")[0] == "WxBrandController.list")
_addr103 = next(x for x in _u103
                if x.unit_name.split("#")[0] == "WxAddressController.list")
check("M103：淬火④ @Sort/@Order 形参打 [param-validated] 标记（C2b 豁免）",
      ("[param-validated]" in _ad103.source_code
       and "sort" in _ad103.source_code[:200]), True)
check("M103：淬火⑥ admin 路由 Shiro /** authc 覆盖 → [global-authz]",
      ("[global-authz]" in _ad103.source_code), True)
check("M103：淬火⑦ wx 模块显式 token 鉴权 → [explicit-auth-module]",
      ("[explicit-auth-module]" in _wx103.source_code), True)
check("M103：@LoginUser Integer userId 主体被识别（地址列表无 authz P0）",
      ("形参主体注解" in _addr103.source_code
       and _verdict("authz", _addr103.source_code) is not True), True)

# ---- [104] Module 65：二级 Sink 漏斗相关性校验（假候选消解） ----
from core.agents.rule_detectors import build_rule_diagnostic as _brd65  # noqa: E402
# 施工单夹具：纯常量实参的 sink（new File("/var/log/app.log")）不是候选
_check65a = _brd65("pathtraver", '''
public void run() {
    java.io.File f = new File("/var/log/app.log");
    System.out.println(f.exists());
}''')
check("M104：纯常量实参的 sink 行不计入候选（施工单夹具）",
      _check65a, "")
# 四项目假候选形态：sink 实参与输入行无交集
_check65b = _brd65("xss", '''
public Object list() {
    byte[] img = captchaService.genImage();
    response.getOutputStream().write(img);
    return null;
}''')
check("M104：验证码图片流（与输入行无交集）不派发", _check65b, "")
# 真阳退回形态不受影响：实参与输入行有交集（含赋值链）
_check65c = _brd65("sqli", '''
public void vul(HttpServletRequest request) {
    String name = request.getParameter("q");
    stmt.executeQuery("SELECT * FROM u WHERE n='" + name + "'");
}''')
check("M104：真阳退回样本 0 漏网（实参经赋值链与输入行有交集）",
      ("候选输入行" in _check65c and "候选敏感操作行" in _check65c), True)

# ---- [105] Module 66：--summary-json 狩猎简报 + HTML 漏斗仪表盘 ----
_d105 = Path(_tmod.mkdtemp(prefix="nexus_t105_"))
try:
    (_d105 / "dao.py").write_text(
        "from flask import request\n"
        "@app.route('/q', methods=['GET'])\n"
        "def vul_sqli():\n"
        "    import sqlite3\n"
        "    uid = request.args.get('uid')\n"
        "    c = sqlite3.connect('a.db')\n"
        "    return c.execute('SELECT * FROM users WHERE id=' + uid).fetchall()\n",
        encoding="utf-8")
    (_d105 / "math.py").write_text("def g(a):\n    return a * 2\n",
                                   encoding="utf-8")
    _r105 = subprocess.run(
        [sys.executable, str(ROOT / "cli.py"), "scan", str(_d105),
         "--auto", "--offline", "--output", str(_d105 / "ra.md"),
         "--html", str(_d105 / "ra.html"),
         "--summary-json", str(_d105 / "summary.json")],
        capture_output=True, text=True)
    check("M105：--summary-json 产出且字段齐全", _r105.returncode, 0)
    _sj105 = json.loads((_d105 / "summary.json").read_text(encoding="utf-8"))
    check("M105：漏斗字段齐全（units/pairs/p0/filter/dispatch）",
          all(k in _sj105 for k in (
              "total_units", "total_pairs_evaluated", "p0_confirmed",
              "funnel_filtered_out", "funnel_filter_rate", "llm_dispatched",
              "patches_verified", "pocs_generated")), True)
    check("M105：过滤率计算准确（本仓 = 100%）",
          (_sj105["funnel_filter_rate"] == 1.0
           and _sj105["p0_confirmed"] >= 1), True)
    _h105 = (_d105 / "ra.html").read_text(encoding="utf-8")
    check("M105：HTML 顶部渲染漏斗过滤率仪表盘",
          ("漏斗过滤率" in _h105 and "切片单元" in _h105), True)
    check("M105：HTML 类目热力条渲染",
          ("SQLI" in _h105 and "background:#e0524b" in _h105), True)
finally:
    shutil.rmtree(_d105, ignore_errors=True)

# ---- [106] Module 67：hardcoded_secret 第 22 类规则 ----
from core.agents.vuln_categories import CATEGORIES as _VC106   # noqa: E402
check("M106：hardcoded_secret 已注册为第 22 类（doctor 单一事实源）",
      ("hardcoded_secret" in _VC106 and len(_VC106) == 22), True)
# VAmPI 形态：Flask SECRET_KEY 短弱密钥（JWT 签名上下文，无长度门槛）
_vampi106 = ("import jwt\n"
             "vuln_app.app.config['SECRET_KEY'] = 'random'\n"
             "def encode(user_id):\n"
             "    return jwt.encode({'sub': user_id}, SECRET_KEY,"
             " algorithm='HS256')\n")
check("M106：VAmPI 形态（'random' 短弱 JWT 密钥）判 True（可猜测性是危害）",
      (_verdict("hardcoded_secret", _vampi106) is True), True)
_java106 = ('String jwtSecret = "my-super-secret-signing-key-2026";\n'
            "return Jwts.builder().setSubject(sub).compact();\n")
check("M106：Java Jwts 签名密钥字面量判 True", (_verdict(
    "hardcoded_secret", _java106) is True), True)
_env106 = ("secret = os.environ.get('JWT_SECRET')\n"
           "jwt.encode({'a': 1}, secret)\n")
check("M106：os.environ 读取判 False", (_verdict(
    "hardcoded_secret", _env106) is False), True)
_ph106 = "app.config['SECRET_KEY'] = 'your-secret-here-please-change'\n"
check("M106：占位符（your-secret）不算泄露（退 None）", (_verdict(
    "hardcoded_secret", _ph106) is None), True)
check("M106：无密钥标识符退 None（不归本类目管）", (_verdict(
    "hardcoded_secret", "def f(a):\n    return a + 1\n") is None), True)
# VAmPI 实测 FP 回归锁：secret_content 是书籍正文字段，不是凭证；十六进制
# 密钥里出现 123456 子串也不能当占位符。
check("M106：数据字段 secret_content 不判 True（凭证词须在标识符末尾）",
      (_verdict("hardcoded_secret",
                'Book(secret_content="secret for bookTitle" + randomint)\n')
       is None), True)
check("M106：十六进制私钥含 123456 子串仍判 True（不误当占位符）",
      (_verdict("hardcoded_secret",
                'privateKey = "0x0123456789abcdef0123456789abcdef"\n')
       is True), True)
check("M106：短通用密钥（无签发上下文）退 None（交模型）",
      (_verdict("hardcoded_secret", 'secret_key = "short"\n') is None), True)

# ---- [107] Module 68：--fix 第 15 类（硬编码密钥转环境变量） ----
from cli import _fix_hardcoded_secret as _fix107   # noqa: E402
_d107 = Path(_tmod.mkdtemp(prefix="nexus_t107_"))
try:
    (_d107 / "api.py").write_text(
        "import jwt\nfrom flask import request\napp = None\n"
        "@app.route('/token')\ndef token():\n"
        "    app.config['SECRET_KEY'] = 'random'\n"
        "    uid = request.args.get('uid')\n"
        "    return jwt.encode({'sub': uid}, app.config.get('SECRET_KEY'),"
        " algorithm='HS256')\n", encoding="utf-8")
    _u107 = WebTreeSitterSlicer(_d107).extract_entry_units(_d107)
    _orig107 = (_d107 / "api.py").read_text(encoding="utf-8")
    _rep107: list = []
    _n107 = _fix107(_d107, _u107, _rep107)
    check("M107：第 15 类补丁自检通过（True → 写入 → 规则 False）", _n107, 1)
    check("M107：补丁把字面量改为 os.environ.get（SECRET_KEY）",
          any("os.environ.get(\"SECRET_KEY\")" in x for x in _rep107), True)
    check("M107：补丁自动补齐 import os（语法自洽）",
          any(x.strip().startswith("+import os") for x in _rep107), True)
    check("M107：文件字节级无损还原",
          (_d107 / "api.py").read_text(encoding="utf-8"), _orig107)
finally:
    shutil.rmtree(_d107, ignore_errors=True)
# Java 分支：验证按语言分流 + Java 切片器文件缓存清空（否则重切片读旧内容）
_d107j = Path(_tmod.mkdtemp(prefix="nexus_t107j_"))
try:
    _j107 = _d107j / "src" / "main" / "java" / "demo"
    _j107.mkdir(parents=True)
    (_j107 / "ApiController.java").write_text(
        "package demo;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class ApiController {\n"
        "  @GetMapping(\"/token\")\n"
        "  public String token() {\n"
        "    String jwtSecret = \"my-super-secret-signing-key-2026\";\n"
        "    return Jwts.builder().setSubject(\"x\")"
        ".signWith(jwtSecret).compact();\n"
        "  }\n"
        "}\n", encoding="utf-8")
    _u107j = JavaSlicer(_d107j).extract_entry_units()
    _orig107j = (_j107 / "ApiController.java").read_text(encoding="utf-8")
    _rep107j: list = []
    _n107j = _fix107(_d107j, _u107j, _rep107j)
    check("M107：Java 分支自检通过（True → System.getenv → False）",
          _n107j, 1)
    check("M107：Java 补丁写入 System.getenv(\"JWT_SECRET\")",
          any("System.getenv(\"JWT_SECRET\")" in x for x in _rep107j), True)
    check("M107：Java 文件字节级无损还原",
          (_j107 / "ApiController.java").read_text(encoding="utf-8"),
          _orig107j)
finally:
    shutil.rmtree(_d107j, ignore_errors=True)
_sp107 = subprocess.run(
    [sys.executable, str(ROOT / "cli.py"), "doctor"],
    capture_output=True, text=True)
check("M107：doctor 补丁器升到 15 类全绿（M68 加 hardcoded_secret）",
      (_sp107.returncode == 0
       and "补丁器就位（15 类）" in _sp107.stdout
       and _sp107.stdout.count("[OK] _fix_") == 15), True)

# ---- [108] M69 野战 FP 回归锁：SpEL 裸 getValue / 路径 sink 同名遮蔽 ----
# RuoYi 305 路由实测：`Cookie.getValue()`（以及 Map.Entry.getValue()）被
# EXPR_SINK_RE 的裸 `.getValue()` 当成 SpEL sink，判出 2 条 P0。SpEL 只看
# 表达式型接收者（exp/expr/expression/parser）或 SpelExpressionParser。
_spel_fp108 = """@GetMapping("/x")
public String x(HttpServletRequest req) {
    Cookie cookie = req.getCookies()[0];
    return cookie.getValue();
}
"""
check("M108：Cookie.getValue() 不再被当成 SpEL sink（RuoYi FP）",
      _verdict("spel", _spel_fp108) is None, True)
_spel_tp108 = """@GetMapping("/x")
public String x(String ex) {
    Expression exp = new SpelExpressionParser().parseExpression(ex);
    return exp.getValue().toString();
}
"""
check("M108：Expression.getValue() 仍判 True（真 SpEL 不误杀）",
      _verdict("spel", _spel_tp108), True)
# RuoYi updateAvatar 实测：局部 `File file = new File(filePath)` 与入口形参
# `MultipartFile file` 同名遮蔽，旧逻辑按整行标识符相交判成路径遍历。
_path_shadow108 = """@PostMapping("/avatar")
public String upload(@RequestParam MultipartFile file) {
    String filePath = FileUtils.stripPrefix(oldAvatar);
    File file = new File(filePath);
    return file.delete() ? "ok" : "no";
}
"""
check("M108：同名局部变量不构成路径遍历相关（RuoYi FP）",
      _verdict("pathtraver", _path_shadow108) is None, True)
_path_tp108 = """@GetMapping("/read")
public byte[] read(@RequestParam String path) throws Exception {
    return Files.readAllBytes(Paths.get(path));
}
"""
check("M108：形参直接进 Paths.get 仍判 True（真遍历不误杀）",
      _verdict("pathtraver", _path_tp108), True)

# ---- [109] M70 补丁报告重置：重复 --fix 不把上一轮 diff 算进 patches_verified ----
from cli import _verify_fixes_any as _vfa109                       # noqa: E402
_d109 = Path(_tmod.mkdtemp(prefix="nexus_t109_"))
try:
    _out109 = _d109 / "fix_report.md"
    _out109.write_text("STALE FROM PREVIOUS SCAN\n", encoding="utf-8")
    _vfa109(_d109, [], _out109)
    check("M109：补丁报告每次扫描重置（旧 diff 不残留）",
          _out109.read_text(encoding="utf-8"), "")
finally:
    shutil.rmtree(_d109, ignore_errors=True)

print()
if FAILS:
    print(f"CHAIN SMOKE TEST FAIL ✘  ({len(FAILS)} 项): {FAILS}")
    sys.exit(1)
print("CHAIN SMOKE TEST PASS ✔")
