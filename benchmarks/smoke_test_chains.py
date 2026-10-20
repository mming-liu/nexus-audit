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
check("同字段 → 双向各 1 条连接", len(ch_db.links), 2)
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
if FAILS:
    print(f"CHAIN SMOKE TEST FAIL ✘  ({len(FAILS)} 项): {FAILS}")
    sys.exit(1)
print("CHAIN SMOKE TEST PASS ✔")