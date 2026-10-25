"""第四层：确定性漏洞的可运行验证脚本（PoC Harness）合成器（M45）。

为什么要有这一层：前三层产出的是**判定**（True/False/None），第四层要
产出的是**可运行的证据**。规则层判 True 的漏洞往往是"结构上可证"的那类
（重入、tx.origin 钓鱼、缺授权、注入），它们的攻击路径可以在**不依赖任何
外部服务**的前提下写成骨架测试：

  · Solidity → Foundry `.t.sol`（Attacker 合约 + `testExploit()` 断言）
  · Python   → pytest `test_poc_*.py`（双账号 / 特殊载荷请求模板）
  · Java     → Spring MockMvc `*PocTest.java`（路由 + 污染形参）

设计口径（与全局铁律一致）：
  1. 合成器**不判定漏洞**——只把"规则层已判 True 的那条"翻译成可执行骨架；
  2. 产出必须**离线可跑**（不连数据库/不连真实服务），断言写的是
     "攻击者应当拿到的结果"，不是"服务必须崩溃"；
  3. 产出必须**自检通过**才算数：Python 走 `ast.parse`，Solidity/Java
     走括号配平 + 结构完整度（pragma/contract/class/import 齐备）；
  4. 合成失败**不抛异常**，返回错误信息交给调用方（兜底是"退回"，不是崩）。

用法：
    python cli.py scan <repo> --offline --emit-poc ./pocs
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from core.models import CodeUnit, Language

# ---------------------------------------------------------------- 语言识别

_SOL_RE = re.compile(r"\bpragma\s+solidity\b|\bcontract\s+\w+")
_JAVA_RE = re.compile(r"\b(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\],. ]+\s+\w+\s*\(")


@dataclass
class PocArtifact:
    """一份合成产出。"""
    path: str                       # 相对输出目录的文件名
    content: str                    # 文件内容
    language: str                   # solidity / python / java
    category: str                   # 规则层判据的类目
    target: str                     # 目标单元名
    self_check_ok: bool = False     # 语法/结构自检结果
    self_check_msg: str = ""


@dataclass
class SynthReport:
    artifacts: list[PocArtifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for a in self.artifacts if a.self_check_ok)


# ---------------------------------------------------------------- 公共工具

def _safe_name(s: str) -> str:
    """把任意名字规整成标识符片段（文件名/类名都要用）。"""
    s = re.sub(r"[^0-9A-Za-z_]+", "_", s or "")
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "Target"
    if s[0].isdigit():
        s = "T" + s
    return s


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _route_or_name(unit: CodeUnit) -> str:
    return unit.route_path or unit.unit_name


def _first_arg_name(unit: CodeUnit) -> str:
    """取入口函数的第一个形参名（注入载荷用）。"""
    m = re.search(r"function\s+\w+\s*\(([^)]*)\)|def\s+\w+\s*\(([^)]*)\)",
                  unit.source_code or "")
    args = (m.group(1) or m.group(2) or "") if m else ""
    args = args.split("=")[0].strip()
    if not args:
        return "id"
    first = args.split(",")[0].strip()
    first = re.sub(r"[:\s\[\]]+.*$", "", first)      # 去掉类型注解
    return first or "id"


# ---------------------------------------------------------------- Solidity

_SOL_HEADER = """// SPDX-License-Identifier: MIT
// 自动生成的 PoC 骨架（M45 PoC 合成器）—— 目标：{target}
// 规则层判定：{category} = True
// 目标位置：{file}:{line}
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
"""

_SOL_REENTRANCY = """
contract Attacker {{
    address public target;
    constructor(address _target) {{ target = _target; }}

    receive() external payable {{
        // 重入：回调里再次发起同一个提款请求
        (bool ok, ) = target.call{{value: msg.value}}("");
        require(ok, "reenter failed");
    }}
}}

contract {cls} is Test {{
    function testExploit() public {{
        // 攻击者合约为受害者合约的初始持币人
        address victim = address(new Victim());
        vm.deal(address(victim), 1 ether);

        Attacker attacker = new Attacker(address(victim));
        vm.deal(address(attacker), 1 ether);

        uint256 before = address(victim).balance;

        // 攻击者发起提款 → Victim 外部调用触发 receive() → 回调重入
        vm.prank(address(attacker));
        victim.withdraw(1 ether);

        // 断言：重入后合约余额被掏空（若被修复则断言不成立）
        assertTrue(address(victim).balance < before, "expected reentrancy drain");
    }}
}}
"""

_SOL_TX_ORIGIN = """
contract Phisher {{
    address public target;
    constructor(address _target) {{ target = _target; }}

    function attack() public {{
        // tx.origin == msg.sender 的钓鱼形态：诱导受害者自己调用提款
        (bool ok, ) = target.call(abi.encodeWithSignature("withdraw()"));
        require(ok, "phish failed");
    }}
}}

contract {cls} is Test {{
    function testExploit() public {{
        address victim = address(new Victim());
        vm.deal(address(victim), 1 ether);

        Phisher phisher = new Phisher(address(victim));
        vm.deal(address(phisher), 1 ether);

        vm.prank(address(phisher));
        phisher.attack();

        // 断言：受害者合约余额被钓鱼转走（tx.origin 鉴权不防钓鱼）
        assertTrue(address(victim).balance == 0, "expected tx.origin phishing drain");
    }}
}}
"""

_SOL_ACCESS = """
contract {cls} is Test {{
    function testExploit() public {{
        address victim = address(new Victim());
        vm.deal(address(victim), 1 ether);
        address attacker = address(0xBAD);
        vm.deal(attacker, 1 ether);

        // 攻击者（非管理员）直接调用特权函数
        vm.prank(attacker);
        victim.withdraw(1 ether);

        // 断言：非特权账户拿到了本不该拿到的资产
        assertTrue(attacker.balance > 1 ether, "expected unauthorized withdraw");
    }}
}}
"""


_SOL_ARITHMETIC = """
contract {cls} is Test {{
    function testExploit() public {{
        // 0.4.x~0.7.x 编译器不检查溢出（SWC-101）：
        // 极值输入 type(uint256).max 让算术回卷 —— sum += x 绕回成 0
        Victim victim = new Victim();

        // 第一次入账把累计值推到上界附近，第二次极值入账触发回卷
        // （骨架按 Victim 的入账入口 deposit(uint256) 形态生成；
        //  实际接入时按目标函数签名替换调用形态）
        vm.prank(address(0xA11CE));
        victim.deposit(type(uint256).max);

        vm.prank(address(0xBAD));
        victim.deposit(1);

        // 断言：上溢回卷 —— 累计值不增反减（修复后 require 会 revert）
        assertTrue(victim.totalSupply() < type(uint256).max,
                   "expected uint256 wraparound");
    }}
}}
"""

_SOL_UNCHECKED = """
contract RevertReceiver {{
    // 拒收 ETH 的合约（无 receive/payable fallback）
    // → 目标合约的低层调用静默失败，状态照常推进（SWC-104）
}}

contract {cls} is Test {{
    function testExploit() public {{
        Victim victim = new Victim();
        RevertReceiver receiver = new RevertReceiver();

        vm.deal(address(victim), 1 ether);
        uint256 receiverBalanceBefore = address(receiver).balance;

        // 目标合约向拒收地址发起底层调用 —— 返回值被丢弃，
        // 失败被静默吞掉，合约状态与预期不一致
        // （骨架按 Victim.withdraw(address) 形态生成；实际接入时
        //  按目标函数签名替换 encodeWithSignature 的内容）
        (bool ok, ) = address(victim).call(
            abi.encodeWithSignature("withdraw(address)", address(receiver)));
        ok; // 老语法双返回值占位

        // 断言：调用失败（资金未到账）—— 失败静默就是漏洞本身；
        // 修复版会 require(ok) 让整笔回滚
        assertTrue(address(receiver).balance == receiverBalanceBefore,
                   "receiver must not accept ETH");
    }}
}}
"""


# M141：不受信 delegatecall（SWC-112）—— 目标由调用方指定且无权限保护
_SOL_DELEGATE = """
contract Malicious {{
    bool public pwned;

    function pwn() external {{
        // 被委托执行时写的是**受害者合约**的存储（delegatecall 语义）
        pwned = true;
    }}
}}

contract {cls} is Test {{
    function testExploit() public {{
        Victim victim = new Victim();
        Malicious fakeImpl = new Malicious();

        // 攻击者（非管理员）把委托目标换成自己的实现
        vm.prank(address(0xBAD));
        victim.upgrade(address(fakeImpl),
                       abi.encodeWithSignature("pwn()"));

        // 断言：攻击者指定的实现被借受害者上下文执行；
        // 修复版 `require(target == address(this))` 会让这笔调用直接 revert
        assertTrue(fakeImpl.pwned(),
                   "expected delegatecall target hijack");
    }}
}}
"""


def _synth_solidity(unit: CodeUnit, category: str) -> str:
    cls = "Poc" + _safe_name(unit.unit_name)
    tpl = {"reentrancy": _SOL_REENTRANCY,
           "txorigin": _SOL_TX_ORIGIN,
           "tx_origin": _SOL_TX_ORIGIN,
           "access_control": _SOL_ACCESS,
           "arithmetic": _SOL_ARITHMETIC,
           "unchecked_low_level_calls": _SOL_UNCHECKED,
           "unchecked": _SOL_UNCHECKED,
           "delegatecall_untrusted": _SOL_DELEGATE,
           }.get(category, _SOL_ACCESS)
    body = tpl.format(cls=cls)
    return _SOL_HEADER.format(target=unit.unit_name, category=category,
                               file=Path(unit.file_path).name,
                               line=unit.start_line) + body


# ---------------------------------------------------------------- Python

_PY_HEADER = '''"""{target} 的 PoC 骨架（M45 PoC 合成器）。

规则层判定：{category} = True
目标位置：{file}:{line}
运行：pytest {fname} -q
"""
import pytest


@pytest.fixture
def client():
    """离线占位：真实环境应替换成 app.test_client() 或 requests.Session。"""
    raise NotImplementedError("请在此接入被测应用的测试客户端")


ATTACKER = "attacker"
VICTIM = "victim"
'''

_PY_SQLI = '''

def test_sqli_payload_reaches_backend(client):
    """注入载荷应被参数化查询挡住 —— 若后端报 SQL 语法错误即存在注入。"""
    payload = "' OR '1'='1' --"
    resp = client.get({call})
    assert resp.status_code not in (500,), (
        "SQL 注入载荷触发了服务端错误，疑似未参数化：%s" % payload)
'''

_PY_AUTHZ = '''

def test_bola_other_account_denied(client):
    """用他人身份访问本账户资源应被拒绝 —— 放行即越权。"""
    resp = client.get({call}, headers={{"Authorization": "Bearer " + ATTACKER}})
    assert resp.status_code in (401, 403, 404), (
        "越权访问未被拒绝（状态码 %s）" % resp.status_code)
'''

_PY_CORS = '''

def test_cors_evil_origin_not_echoed(client):
    """恶意 Origin + credentials 不应被 ACAO 回显。"""
    resp = client.get({call}, headers={{"Origin": "https://evil.example"}})
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    assert acao != "https://evil.example", "CORS 回显任意 Origin：%s" % acao
'''

_PY_SECRET = '''

def test_forged_admin_token_with_hardcoded_secret(client):
    """用代码里的硬编码密钥离线签发管理员 JWT，验证其可被用于伪造身份。"""
    import jwt
    forged = jwt.encode({{"sub": "admin", "role": "admin"}},
                        {secret!r}, algorithm="HS256")
    resp = client.get({call}, headers={{"Authorization": "Bearer " + forged}})
    assert resp.status_code != 200, "硬编码密钥可伪造管理员 Token"
'''

_PY_JWT = '''

def test_alg_none_forged_admin_token(client):
    """构造 alg=none 的无签名管理员 JWT，验证服务端是否真的验签。"""
    import jwt
    forged = jwt.encode({{"sub": "admin", "role": "admin"}},
                        key=None, algorithm="none")
    resp = client.get({call}, headers={{"Authorization": "Bearer " + forged}})
    assert resp.status_code != 200, "alg=none 的无签名 Token 被接受"
'''


# M139：不安全反射（CWE-470）—— 目标名由请求决定且无白名单
_PY_REFLECT = '''

def test_reflection_target_not_allowlisted(client):
    """把模块/类名换成非白名单值：若服务端仍导入并执行，说明目标可控。"""
    resp = client.get({call})
    assert resp.status_code in (400, 403, 404), (
        "非白名单的反射目标被接受（状态码 %s）" % resp.status_code)
'''

# M140：Zip Slip（CWE-22）—— 压缩包条目名逃逸目标目录
_PY_ZIP_SLIP = '''

def test_zip_slip_archive_rejected(client):
    """上传含 `../` 条目的压缩包：解压结果不应落在目标目录之外。"""
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../escape.txt", "poc")
    buf.seek(0)
    resp = client.post({call}, files={{"f": (buf, "poc.zip")}})
    assert resp.status_code in (400, 403, 422), (
        "含 ../ 条目的压缩包被接受（状态码 %s）" % resp.status_code)
'''


def _extract_secret(unit: CodeUnit) -> str:
    from core.agents.rule_detectors import SECRET_ASSIGN_RE
    m = SECRET_ASSIGN_RE.search(unit.source_code or "")
    return m.group("val") if m else "REDACTED_SECRET"


def _synth_python(unit: CodeUnit, category: str) -> str:
    arg = _first_arg_name(unit)
    route = _route_or_name(unit)
    call = f'"{route}", params={{"{arg}": "1"}}'
    tpl = {"sqli": _PY_SQLI, "cors": _PY_CORS,
           "hardcoded_secret": _PY_SECRET,
           "jwt_weakness": _PY_JWT,
           "unsafe_reflection": _PY_REFLECT,
           "zip_slip": _PY_ZIP_SLIP}.get(category, _PY_AUTHZ)
    return _PY_HEADER.format(target=unit.unit_name, category=category,
                              file=Path(unit.file_path).name,
                              line=unit.start_line,
                              fname="test_poc_" + _safe_name(unit.unit_name) + ".py") \
        + tpl.format(call=call, secret=_extract_secret(unit))


# ---------------------------------------------------------------- Java

_JAVA_HEADER = """// 自动生成的 PoC 骨架（M45 PoC 合成器）
// 规则层判定：{category} = True
// 目标位置：{file}:{line}
package poc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.*;
import static org.hamcrest.Matchers.not;

@SpringBootTest
@AutoConfigureMockMvc
public class {cls}PocTest {{

    @Autowired
    private MockMvc mockMvc;
"""

_JAVA_SQLI = """
    @Test
    void sqlInjectionPayloadRejected() throws Exception {{
        mockMvc.perform(get("{route}").param("{arg}", "' OR '1'='1' --"))
            .andExpect(status().is4xxClientError());
    }}
}}
"""

_JAVA_AUTHZ = """
    @Test
    void otherAccountResourceDenied() throws Exception {{
        mockMvc.perform(get("{route}").param("{arg}", "9999")
                .header("Authorization", "Bearer attacker-token"))
            .andExpect(status().is4xxClientError());
    }}
}}
"""

_JAVA_CORS = """
    @Test
    void corsEvilOriginNotReflected() throws Exception {{
        mockMvc.perform(options("{route}")
                .header("Origin", "https://evil.example")
                .header("Access-Control-Request-Method", "GET"))
            .andExpect(header().string("Access-Control-Allow-Origin",
                                       not("https://evil.example")));
    }}
}}
"""

_JAVA_SECRET = """
    @Test
    void forgedAdminTokenWithHardcodedSecret() throws Exception {{
        String forged = io.jsonwebtoken.Jwts.builder()
            .setSubject("admin").claim("role", "admin")
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, "{secret}")
            .compact();
        mockMvc.perform(get("{route}")
                .header("Authorization", "Bearer " + forged))
            .andExpect(status().is4xxClientError());
    }}
}}
"""

_JAVA_JWT = """
    @Test
    void algNoneForgedAdminToken() throws Exception {{
        String forged = io.jsonwebtoken.Jwts.builder()
            .setSubject("admin").claim("role", "admin")
            .compact();   // 无签名，alg=none
        mockMvc.perform(get("{route}")
                .header("Authorization", "Bearer " + forged))
            .andExpect(status().is4xxClientError());
    }}
}}
"""


# M139：不安全反射 —— 用 Runtime 这类非白名单类名探针
_JAVA_REFLECT = """
    @Test
    void reflectionTargetNotAllowlisted() throws Exception {{
        mockMvc.perform(get("{route}")
                .param("{arg}", "java.lang.Runtime"))
            .andExpect(status().is4xxClientError());
    }}
}}
"""

# M140：Zip Slip —— 上传含 `../` 条目的压缩包
_JAVA_ZIP_SLIP = """
    @Test
    void zipSlipEntryRejected() throws Exception {{
        // 条目名带 ../：落盘前必须被规范化前缀校验挡住
        byte[] pocZip = new byte[0];   // 接入时换成真实构造的 zip 字节
        mockMvc.perform(multipart("{route}")
                .file(new org.springframework.mock.web.MockMultipartFile(
                        "file", "poc.zip", "application/zip", pocZip)))
            .andExpect(status().is4xxClientError());
    }}
}}
"""


def _synth_java(unit: CodeUnit, category: str) -> str:
    cls = _safe_name(unit.unit_name).capitalize()
    arg = _first_arg_name(unit)
    route = _route_or_name(unit)
    if not route.startswith("/"):
        route = "/" + route
    tpl = {"sqli": _JAVA_SQLI, "cors": _JAVA_CORS,
           "hardcoded_secret": _JAVA_SECRET,
           "jwt_weakness": _JAVA_JWT,
           "unsafe_reflection": _JAVA_REFLECT,
           "zip_slip": _JAVA_ZIP_SLIP}.get(category, _JAVA_AUTHZ)
    secret = _extract_secret(unit).replace("\\", "\\\\").replace('"', '\\"')
    body = tpl.format(route=route, arg=arg, secret=secret)
    return _JAVA_HEADER.format(target=unit.unit_name, category=category,
                               file=Path(unit.file_path).name,
                               line=unit.start_line, cls=cls) + body


# ---------------------------------------------------------------- 自检

def _balance_ok(src: str) -> tuple[bool, str]:
    """括号配平（三种语言通用）。"""
    cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', src)
    cleaned = re.sub(r"//[^\n]*", "", cleaned)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.S)
    for open_c, close_c in (("{", "}"), ("(", ")"), ("[", "]")):
        if cleaned.count(open_c) != cleaned.count(close_c):
            return False, f"{open_c}{close_c} 不配平（{cleaned.count(open_c)} vs {cleaned.count(close_c)}）"
    return True, "括号配平"


def _python_ok(src: str) -> tuple[bool, str]:
    try:
        ast.parse(src)
    except SyntaxError as e:
        return False, f"ast.parse 失败：{e}"
    if "def test" not in src:
        return False, "缺少测试函数"
    return True, "ast.parse 通过"


def _java_ok(src: str) -> tuple[bool, str]:
    ok, msg = _balance_ok(src)
    if not ok:
        return ok, msg
    if not re.search(r"\bclass\s+\w+", src):
        return False, "缺少 class 定义"
    if "@Test" not in src:
        return False, "缺少 @Test 注解"
    if "import " not in src:
        return False, "缺少 import"
    return True, "括号配平 + class/@Test/import 齐备"


def _solidity_ok(src: str) -> tuple[bool, str]:
    ok, msg = _balance_ok(src)
    if not ok:
        return ok, msg
    if not re.search(r"\bcontract\s+\w+", src):
        return False, "缺少 contract 定义"
    if not re.search(r"\bfunction\s+test\w*", src):
        return False, "缺少测试入口函数"
    if "pragma solidity" not in src:
        return False, "缺少 pragma solidity"
    return True, "括号配平 + contract/test/pragma 齐备"


def self_check(art: PocArtifact) -> tuple[bool, str]:
    """按语言做语法/结构自检，回填到 art。"""
    if art.language == "python":
        ok, msg = _python_ok(art.content)
    elif art.language == "java":
        ok, msg = _java_ok(art.content)
    else:
        ok, msg = _solidity_ok(art.content)
    art.self_check_ok, art.self_check_msg = ok, msg
    return ok, msg


# ---------------------------------------------------------------- 主入口

class PocSynthesizer:
    """把"规则层判 True 的单元"翻译成可运行的验证骨架。"""

    def synthesize(self, unit: CodeUnit, category: str) -> PocArtifact:
        lang = unit.language
        # 文件名带源文件前缀：不同合约/模块的同名函数不能互相覆盖
        stem = _safe_name(Path(unit.file_path).stem)
        base = f"{stem}_{_safe_name(unit.unit_name)}"
        try:
            if lang == Language.SOLIDITY_WEB3 or _SOL_RE.search(unit.source_code or ""):
                content = _synth_solidity(unit, category)
                art = PocArtifact(path=f"poc_{base}.t.sol",
                                  content=content, language="solidity",
                                  category=category, target=unit.unit_name)
            elif lang == Language.PYTHON_WEB or not _JAVA_RE.search(unit.source_code or ""):
                content = _synth_python(unit, category)
                art = PocArtifact(path=f"test_poc_{base}.py",
                                  content=content, language="python",
                                  category=category, target=unit.unit_name)
            else:
                content = _synth_java(unit, category)
                art = PocArtifact(path=f"{base}PocTest.java",
                                  content=content, language="java",
                                  category=category, target=unit.unit_name)
        except Exception as e:  # noqa: BLE001 —— 合成失败不崩，退回给调用方
            art = PocArtifact(path=f"poc_{base}.txt",
                              content=f"# 合成失败：{type(e).__name__}: {e}",
                              language="unknown", category=category,
                              target=unit.unit_name, self_check_ok=False,
                              self_check_msg=f"{type(e).__name__}: {e}")
        self_check(art)
        return art

    def synthesize_many(self, hits: list[tuple[CodeUnit, str]],
                        out_dir: Path) -> SynthReport:
        """hits: [(unit, category), ...]；逐条合成 + 自检 + 落盘。"""
        rep = SynthReport()
        out_dir.mkdir(parents=True, exist_ok=True)
        for unit, category in hits:
            art = self.synthesize(unit, category)
            if art.language == "unknown":
                rep.errors.append(f"{unit.unit_name}@{category}: {art.self_check_msg}")
                continue
            (out_dir / art.path).write_text(art.content, encoding="utf-8")
            rep.artifacts.append(art)
        return rep
