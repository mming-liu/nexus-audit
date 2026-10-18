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
    redir_verdict, verdict, xss_verdict,
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

# (c) 拼接的操作数是"我们没见过的清洗函数"时，是"不确定"而不是"有把握"。
#     兜底判 True 会把正确防护冤枉成漏洞（ESAPI.encodeForSQL 就是）。
_SQLI_ESAPI = '''public String safe3(String id) {
    Statement st = conn.createStatement();
    String sql = "select * from users where id = '" + ESAPI.encoder().encodeForSQL(codec, id) + "'";
    st.executeQuery(sql);
}'''
check("未知清洗函数参与拼接 → None（交模型）",
      _verdict("sqli", _SQLI_ESAPI), None)
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



print()
if FAILS:
    print(f"CHAIN SMOKE TEST FAIL ✘  ({len(FAILS)} 项): {FAILS}")
    sys.exit(1)
print("CHAIN SMOKE TEST PASS ✔")
