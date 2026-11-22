"""M287：陌生野仓板块 A 降噪（三条可核对规则，不做语义猜测）。

  · DEMO_CONTROLLER          —— 路径/入口带 demo 的示例 Controller，非生产代码
  · PUBLIC_READONLY_ENDPOINT —— /app-api/ /public/ 下的 get*List / get*Page
                                 等公开只读接口（仅 authz 类：公开只读本来就是
                                 设计意图，不是越权）
  · AUTHZ_SIBLING_GUARD      —— **反向**规则：同文件其它写接口都带
                                 @PreAuthorize / @RequiresPermissions /
                                 @SaCheckPermission，唯独当前写接口没加
                                 → 高置信度真洞，提拔到板块 A 顶部（不拦截）

M294 追加：
  · LOCAL_UNIX_SOCKET_SERVER —— 绑定 AF_UNIX + 0700/0600 + SO_PEERCRED 的
                                 本地控制通道（ssh-agent / docker.sock 同类），
                                 本来就不可从网络到达，压进板块 B
  · Python 版兄弟守卫         —— Depends(get_current_*) / Security(...) /
                                 @login_required / @jwt_required / IsAuthenticated

M302 追加：
  · NO_SQL_SINK              —— Python sqli 但入口文件里一个
                                 .execute/.executemany/.executescript 都没有：
                                 根因来自切片里未被入口调用的辅助函数
                                 （跨跳污染），压进板块 B 等人工复核

M305 追加：
  · LOW_SEVERITY_LOG_INJECTION —— CWE-117 日志伪造属低危，维护者与 MITRE
                                 极少单独下发 CVE，不占板块 A 的交单席位

M307 追加：
  · NO_CMD_SINK              —— Python cmdi 但入口文件里一个
                                 os.system/subprocess/asyncio.create_subprocess
                                 都没有：根因来自跨模块贴进来的辅助函数
"""
from __future__ import annotations

import re
from pathlib import Path

from core.agents.rule_detectors import python_entry_sql_sink, ws_auth_guard

DEMO_CONTROLLER = "DEMO_CONTROLLER"
PUBLIC_READONLY_ENDPOINT = "PUBLIC_READONLY_ENDPOINT"
AUTHZ_SIBLING_GUARD = "AUTHZ_SIBLING_GUARD"
# M322：同文件没有"兄弟注解反差"时（新写的 Controller 整类漏注解），
# 退到同目录其它 Controller 的鉴权基线；但当前文件若已有身份校验
# （JWT/session/checkAuthor）则不算漏鉴权，避免把作者 API 打成假阳。
AUTHZ_PACKAGE_GUARD = "AUTHZ_PACKAGE_GUARD"
LOCAL_UNIX_SOCKET_SERVER = "LOCAL_UNIX_SOCKET_SERVER"
# M337：显式只允许 loopback 的单机工作台（LocalAccessMiddleware / 127.0.0.1
# 客户端校验）。这类应用没有远程攻击面，不能占板块 A 的交单席位。
LOCAL_LOOPBACK_ONLY = "LOCAL_LOOPBACK_ONLY"
# M361：WebSocket 路由在 accept() 前做了主体校验并 close(4401/1008)。
# 这类"鉴权存在"的 WS 入口不再是未授权候选（redcell 5 条由此归零）。
WS_AUTH_PRESENT = "WS_AUTH_PRESENT"
# M375：上传已防路径穿越、且没有任何"静态挂载 / 内联渲染"出口 ——
# 攻击者写不进可执行文件，也拿不到 inline 响应，不占 A 板席位。
UPLOAD_SERVING_ONLY = "UPLOAD_SERVING_ONLY"
# M375：落盘目录不是 Web 根/静态目录（无 StaticFiles / addResourceHandlers），
# 上传物只能被内部读取 —— 同上，压 B。
NON_EXECUTABLE_UPLOAD = "NON_EXECUTABLE_UPLOAD"
# M459：系统更新/插件/固件包上传是"可执行包"面，不能按不可执行普通文件压 B。
_EXEC_PACKAGE_UPLOAD_RE = re.compile(
    r"(?:update_package|upgrade|firmware|install_plugin|install_skill|"
    r"hotfix|patch_package)", re.I)
# M383：redir 三类野仓降噪 —— 服务端构造跳转 / Referer 自引用 / 短链设计。
SERVER_BUILT_REDIRECT = "SERVER_BUILT_REDIRECT"
REFERER_OPEN_REDIRECT = "REFERER_OPEN_REDIRECT"
SAFE_REDIRECT_GUARD = "SAFE_REDIRECT_GUARD"
# M468：签名认证后的 OAuth 回调中转。入口类名/方法名含 OpenAuth / OAuth /
# getOpenId，且切片里能看到**商户验签**（paymentSignService.signVerify /
# verifySign / checkSign / validateSign / SignUtil）—— 验签通过后 redirect_url
# 才可信，302 到 OAuth 授权页是设计内的中转，不是开放重定向。
# dax-pay 的 OpenAuthController.getOpenId 就是这个形态（11-22 A 板假阳 #3）。
SIGNED_OAUTH_RELAY = "SIGNED_OAUTH_RELAY"
# M435：类级/基类级鉴权注解（@Permission / @SaCheckLogin / @PreAuthorize /
# @RequiresPermissions）覆盖到的 authz 入口 —— 框架已在类层面做了鉴权，
# 不是"裸 authz"（SPMS RoleController 继承 BaseController 的 @Permission）。
AUTHZ_CLASS_OR_BASE_GUARD = "AUTHZ_CLASS_OR_BASE_GUARD"
# M449：野仓 securecookie 低危（缺 Secure 标记）统一压 B，不占 A 板。
LOW_SEVERITY_SECURECOOKIE = "LOW_SEVERITY_SECURECOOKIE"
# M428：测试夹具/集成测试后端（tests-common / fixtures / integration-tests）
# 不是生产入口，直接拦截，避免测试用 PeopleRestService 占 A 板。
TEST_FIXTURE_ONLY = "TEST_FIXTURE_ONLY"
# M469：开发叠加 compose（docker-compose.keycloak.yaml 这类）里头部显式标注
# 「OPTIONAL local overlay / NOT part of the default stack / for developing/
# testing」的文件，里面的凭据是本地开发用的示例值，不是生产硬编码密钥 ——
# 压 B 板，不占 A 板首杀席位（v1.5.29 遗留的 akb 实测）。
DEV_OVERLAY_SECRET = "DEV_OVERLAY_SECRET"
SHORTLINK_BY_DESIGN = "SHORTLINK_BY_DESIGN"
# M387：第三方 Webhook/公众号验签挑战串（echostr / hub.challenge）原样回显。
# 它不是浏览器 HTML 页面，不能按反射型 XSS 交单；也不能在 rule_detectors
# 一刀切排除 @RestController 的 String 返回（会打穿 [6]/[10] 与靶场地板）。
WEBHOOK_CHALLENGE_ECHO = "WEBHOOK_CHALLENGE_ECHO"
UNVERIFIED_WILD_AUTHZ = "UNVERIFIED_WILD_AUTHZ"
ZERO_ENTRY_LIB = "ZERO_ENTRY_LIB"
RULE_LANGUAGE_MISMATCH = "RULE_LANGUAGE_MISMATCH"
# M411：服务默认回环绑定 + 全局请求鉴权 —— 认证后的本地管理面，
# 不作为远程未授权 0-day 交单（tubecli 的 4 条本地项由此收归 B 板）。
AUTHENTICATED_LOCAL_ONLY = "AUTHENTICATED_LOCAL_ONLY"
# M407：zip_slip 但解压对象来自固定域名下载的组件包（自更新/内置资源），
# 且入口没有任何上传入参 —— 攻击者不能控制压缩包内容，不是可交单的 zip_slip。
VENDOR_ARCHIVE_EXTRACT = "VENDOR_ARCHIVE_EXTRACT"
# M302：入口文件里根本没有 SQL 执行语句，sqli 根因一定来自切片里
# 未被入口调用的辅助函数（跨跳污染）。宁可进 B 等人工复核，不进 A。
NO_SQL_SINK = "NO_SQL_SINK"
# M305：CWE-117 日志伪造属低危，维护者与 MITRE 极少单独下发 CVE，
# 野仓模式下不占板块 A 的交单席位。
LOW_SEVERITY_LOG_INJECTION = "LOW_SEVERITY_LOG_INJECTION"
# M307：入口文件里根本没有命令执行调用，cmdi 根因来自切片里未被入口
# 调用的辅助函数（`.run()` 这类通用方法名被跨模块贴进来）。
NO_CMD_SINK = "NO_CMD_SINK"
# M318：超管专属入口（haveSuperAdminAuth() 或 /superadmin/ 路径）——
# 超管本就拥有全部权限，这类"路径拼接/缺注解"按厂商惯例不立项。
SUPERADMIN_ONLY = "SUPERADMIN_ONLY"

_CMD_SINK_RE = re.compile(
    r"\b(?:os\s*\.\s*(?:system|popen|exec\w*|spawn\w*)|"
    r"subprocess\s*\.\s*\w+|commands\s*\.\s*getoutput|"
    r"asyncio\s*\.\s*create_subprocess\w*|pty\s*\.\s*spawn)\s*\(",
    re.I)

# M395：只在 Solidity 里成立的类目；落到 .py/.java 入口一定是判据串了语言。
# 必须与 core/agents/rule_detectors.py 的 SOLIDITY_ONLY_CATEGORIES **逐项一致**
# （冒烟 [335] 有等值断言）。规则层在 verdict() 入口挡第一道，降噪层在
# classify() 按文件后缀挡第二道；缺任一端都会让跨语言假根因漏到 B 板。
# M394 只补了 ERC20/预言机两项，剩下 5 项（access_control / broken_access /
# arithmetic / bad_randomness / tx_origin / delegatecall_untrusted /
# signature_replay）在 agenticos 的 Python 切片上同样会误命中。
SOLIDITY_ONLY = frozenset({
    "reentrancy", "access_control", "broken_access",
    "unchecked_low_level_calls", "arithmetic", "bad_randomness",
    "tx_origin", "delegatecall_untrusted", "signature_replay",
    "unchecked_erc20_return", "oracle_stale_price",
})

# M423：只在 Java 里成立的类目（JNDI / SpEL）；落到 .py 入口一定是判据串了语言。
JAVA_ONLY = frozenset({"jndi_injection", "spel"})

PUBLIC_PREFIXES = ("/app-api/", "/public/", "/open-api/")

_READONLY_VERB = re.compile(
    r"^(?:get|list|query|page|search|find|select|fetch|count|export|download|"
    r"view|show|load|detail|info)[A-Z_0-9]")
_WRITE_VERB = re.compile(
    r"^(?:save|create|add|insert|update|edit|modify|delete|remove|batch|submit|"
    r"upload|import|pay|refund|transfer|approve|audit|publish|cancel|reset|"
    r"bind|grant|assign|set|do|handle|confirm)[A-Z_0-9]")

GUARD_ANNOTATIONS = ("@PreAuthorize", "@RequiresPermissions",
                     "@SaCheckPermission", "@RequiresRoles", "@SaCheckRole",
                     "@CrmPermission")

_METHOD_DECL = re.compile(
    r"^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?"
    r"(?:synchronized\s+)?(?:[\w<>\[\],.?]+\s+)+(\w+)\s*\(")


def _norm(value: str) -> str:
    return str(value or "").replace("\\", "/").lower()


def _read(repo_root: Path | None, rel: str) -> str:
    if not rel or repo_root is None:
        return ""
    try:
        path = Path(repo_root) / rel
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ---------------- M469：开发叠加 compose 的示例凭据 ----------------
# 只认 compose 文件**头部**（前 40 行）的显式声明 —— 文件中间某处提到
# "for developing" 不算，避免把生产 compose 也误归 B 板。
_DEV_OVERLAY_MARKER_RE = re.compile(
    r"(?i)optional\s+local\s+(?:\w+\s+){0,3}overlay|"
    r"not\s+part\s+of\s+the\s+default\s+stack|"
    r"for\s+develop(?:ing|ment)\s*/\s*testing|"
    r"for\s+(?:local\s+)?develop(?:ing|ment)\b|"
    r"local\s+(?:dev(?:elopment)?\s+)?overlay")
_COMPOSE_NAME_RE = re.compile(r"(?i)^(?:docker-)?compose(?:[.-].*)?\.ya?ml$")


def _dev_overlay_compose(rel: str, src: str) -> bool:
    """文件是否是「头部显式标注的开发叠加 compose」（M469）。"""
    name = Path(str(rel or "")).name
    if not _COMPOSE_NAME_RE.match(name):
        return False
    head = "\n".join((src or "").splitlines()[:40])
    return bool(_DEV_OVERLAY_MARKER_RE.search(head))


# ---------------- M435：Java 类级/基类级鉴权注解 ----------------
_JAVA_AUTHZ_ANN_RE = re.compile(
    r"@(?:Permission|SaCheckLogin|SaCheckPermission|PreAuthorize|"
    r"RequiresPermissions|RequiresAuthentication|RequiresUser|"
    r"CsPermission|HasPermission)\b")
_JAVA_METHOD_GUARD_RE = re.compile(
    r"@(?:SaCheckPermission|PreAuthorize|RequiresPermissions|"
    r"CsPermission|HasPermission)\b")
_JAVA_ANON_ANN_RE = re.compile(
    r"@(?:Anonymous|IgnoreToken|PermitAll)\b|"
    r"@Permission\s*\(\s*authorize\s*=\s*false\s*\)|"
    r"\blogin\s*=\s*false\b|"
    r"\bauthorize\s*=\s*false\b")


def _java_annotations_before(lines: list[str], idx: int) -> str:
    """声明行之前的注解块（含多行注解/注释的简单回扫）。"""
    out: list[str] = []
    j = idx - 1
    while j >= 0:
        s = lines[j].strip()
        if not s:
            if out:
                break
            j -= 1
            continue
        if (s.startswith("@") or s.startswith("//") or s.startswith("*")
                or s.startswith("/*") or s.endswith("*/")):
            out.append(s)
            j -= 1
            continue
        if out and (s.endswith(")") or s.endswith(",") or s.endswith("{")):
            out.append(s)
            j -= 1
            continue
        break
    return "\n".join(reversed(out))


def _java_method_and_class(lines: list[str], method: str):
    """返回 (方法行, 类声明行, 类名, 父类名)。"""
    mi = -1
    for i, ln in enumerate(lines):
        if re.search(rf"\b{re.escape(method)}\s*\(", ln):
            mi = i
            break
    if mi < 0:
        return -1, -1, "", ""
    for j in range(mi, -1, -1):
        m = re.search(r"\bclass\s+(\w+)", lines[j])
        if m:
            parent = ""
            pm = re.search(r"\bextends\s+([\w.]+)", lines[j])
            if pm:
                parent = pm.group(1).split(".")[-1]
            return mi, j, m.group(1), parent
    return mi, -1, "", ""


def _repo_has_authz_framework(repo_root: Path) -> bool:
    """仓内是否有成规模的类级鉴权注解或 AirPower/Spring Security 线索。"""
    count = 0
    for p in repo_root.rglob("*.java"):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "@Permission" in text or "@SaCheckLogin" in text:
            count += 1
            if count >= 3:
                return True
    for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        for p in repo_root.rglob(name):
            try:
                text = p.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            if "airpower" in text or "spring-security" in text or "shiro" in text:
                return True
    return False


def _repo_has_global_auth_filter(repo_root: Path) -> bool:
    """M449：Shiro/Spring 全局鉴权链（filterChainDefinitionMap + authc、
    或 addPathPatterns(\"/**\") + 鉴权 interceptor）。"""
    for p in repo_root.rglob("*.java"):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "filterChainDefinitionMap" in text and "authc" in text:
            return True
        if ('addPathPatterns("/**")' in text
                and re.search(r"(?:Auth|Permission|Token|Security)\w*Interceptor",
                              text)):
            return True
    return False


def _py_authz_guard_present(source: str, body: str) -> bool:
    """M449：FastAPI Depends(...) / WS token 鉴权 / 显式 verify_* 守卫。"""
    for m in re.finditer(r"Depends\s*\(\s*(\w+)", body):
        if re.search(r"(?:auth|admin|user|login|token|session|permission|"
                     r"principal|current)", m.group(1), re.I):
            return True
    if re.search(r"\bget_current_\w+\s*\(", body):
        return True
    if re.search(r"\b(?:verify|require|check)_(?:auth|token|jwt|session|"
                 r"user|admin|permission|principal)\w*\s*\(", body, re.I):
        return True
    return False


def _java_authz_class_guard(repo_root: Path | None, rel: str,
                            unit: str) -> bool:
    """当前类或其 `extends Base*` 父类是否有类级鉴权注解（M435）。"""
    if repo_root is None:
        return False
    text = _read(repo_root, rel)
    if not text:
        return False
    lines = text.splitlines()
    method = (unit or "").rsplit(".", 1)[-1].split("#")[0]
    mi, ci, _cls, parent = _java_method_and_class(lines, method)
    if mi < 0 or ci < 0:
        return False
    if _JAVA_ANON_ANN_RE.search(_java_annotations_before(lines, mi)):
        return False
    # M449：方法级权限注解（CordysCRM @CsPermission / Shiro / Sa-Token）。
    if _JAVA_METHOD_GUARD_RE.search(_java_annotations_before(lines, mi)):
        return True
    if _JAVA_AUTHZ_ANN_RE.search(_java_annotations_before(lines, ci)):
        return _repo_has_authz_framework(Path(repo_root))
    # M449：仓级全局鉴权链（Shiro authc / 全路径 interceptor）覆盖所有入口。
    if _repo_has_global_auth_filter(Path(repo_root)):
        return True
    if parent:
        _found_parent = False
        for p in Path(repo_root).rglob(parent + ".java"):
            _found_parent = True
            try:
                plines = p.read_text(
                    encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for i, ln in enumerate(plines):
                if re.search(rf"\bclass\s+{re.escape(parent)}\b", ln):
                    if _JAVA_AUTHZ_ANN_RE.search(
                            _java_annotations_before(plines, i)):
                        return _repo_has_authz_framework(Path(repo_root))
                    break
            break
        # M440：父类来自外部 Maven/Gradle Jar（AirPower），本地无源码 ——
        # 文件显式 import cn.hamm.airpower. 且 extends *Controller 时，
        # 未标 @Anonymous/login=false/authorize=false 即视为框架类级鉴权覆盖。
        if not _found_parent and re.search(
                r"import\s+cn\.hamm\.airpower\.", text) and re.search(
                r"\bextends\s+\w*Controller\b", text):
            return True
    return False


def _ws_handler_block(src: str, unit: str) -> str:
    """截出入口函数（含装饰器）的一段源码，供 WS 前置鉴权判定（M361）。

    不能整文件判定：同一个 ws.py 里可能既有前置鉴权路由、也有后置校验路由，
    按文件判会把真洞一起放过。
    """
    meth = (unit or "").rsplit(".", 1)[-1]
    if not src or not meth:
        return ""
    m = re.search(rf"^[ \t]*(?:async\s+)?def\s+{re.escape(meth)}\s*\(",
                  src, re.M)
    if not m:
        return ""
    start = src.rfind("@", 0, m.start())
    start = start if start >= 0 and m.start() - start < 800 else m.start()
    tail = src[m.start():]
    head_end = tail.find("\n")
    if head_end < 0:
        head_end = len(tail)
    nxt = re.search(r"^[ \t]*(?:async\s+)?def\s+\w+\s*\(", tail[head_end:], re.M)
    end = m.start() + (head_end + nxt.start() if nxt else len(tail))
    return src[start:end]


def looks_local_socket(text: str) -> bool:
    """AF_UNIX + 对端凭据/套接字路径 → 本地 IPC，不是网络服务。"""
    if not text:
        return False
    if not any(h in text for h in ("AF_UNIX", "SO_PEERCRED", "LOCAL_PEERCRED")):
        return False
    return any(h in text for h in ("SO_PEERCRED", "LOCAL_PEERCRED",
                                   "socket_path", "uds=", ".bind("))


def looks_local_loopback(text: str) -> bool:
    """入口文件是否显式把访问限制为本机 loopback。

    `LocalAccessMiddleware` 是强信号（creatorhub 的 local_access.py 要求
    client.host 与 Host 都是 loopback）；否则必须同时看到 loopback 字面量
    和客户端地址校验，避免把只在注释里写 localhost 的业务仓误杀。
    """
    if not text:
        return False
    if "LocalAccessMiddleware" in text:
        return True
    if not re.search(r"127\.0\.0\.1|::1|\bloopback\b|\blocalhost\b",
                     text, re.I):
        return False
    return bool(re.search(
        r"request\s*\.\s*client\s*\.\s*host|remote_addr|getRemoteAddr|"
        r"client_address|is_loopback|\bloopback\s*\(",
        text, re.I))


# M359：同仓级 loopback 继承。主服务入口（server.py 里
# `uvicorn.run(app, host="127.0.0.1")`）或全局 LocalAccessMiddleware 已经
# 证明整套服务只对本机开放时，同仓其它子路由文件（dashboard/app.py）不该
# 因为自己文件里没有 loopback 字面量就被判成"可远程"——否则同一个仓会
# 分类撕裂：server.py 的路由进 B，dashboard 的路由进 A。
_LOOPBACK_BIND_RE = re.compile(
    r"\b(?:uvicorn\s*\.\s*run|app\s*\.\s*run|hypercorn\s*\.\s*run|serve)\s*"
    r"\([^)]*?host\s*=\s*[\"'](?:127\.0\.0\.1|localhost|::1)[\"']",
    re.I | re.S)
_PUBLIC_BIND_RE = re.compile(
    r"\b(?:uvicorn\s*\.\s*run|app\s*\.\s*run|hypercorn\s*\.\s*run|serve)\s*"
    r"\([^)]*?host\s*=\s*[\"'](?:0\.0\.0\.0|::)[\"']",
    re.I | re.S)
# Dockerfile / Procfile / compose 的 --host 0.0.0.0 是公网绑定。
_PUBLIC_CLI_HOST_RE = re.compile(
    r"(?:--host|--bind|-b)[ =][\"']?(?:0\.0\.0\.0|::)\b", re.I)
# compose 端口映射：`127.0.0.1:8080:8080` 是回环，裸 `8080:8080` 是公网。
# M463：主机 IP 前缀必须**可选**。v1.5.28 及之前的正则写死了 `host:port:port`
# 三段式，标准公网映射 `- "8000:8000"` 只有两段，根本匹配不到 —— 于是
# `elif not host_ip: public_hit = ...` 成了 100% 死代码。akb 的主
# `docker-compose.yaml` 发布 `9000:9000` / `9001:9001`，却因为
# `eval/longmemeval/docker-compose.yaml` 里的 `127.0.0.1:18000:8000` 被判成
# 整仓 LOCAL_LOOPBACK_ONLY，18 条记录误压 B 板。
_PORT_MAP_RE = re.compile(
    r"^\s*-\s*[\"']?(?:([0-9A-Za-z_.:\[\]-]+):)?(\d+):(\d+)"
    r"(?:/(?:tcp|udp))?[\"']?\s*(?:#.*)?$",
    re.M)
_SCAN_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
                   "site-packages", "dist", "build", "tests", "test",
                   "docs", "examples", "example",
                   # M463：评测 / 基准 / CI / 脚本目录里的 compose 是"跑分环境"，
                   # 不是生产部署面。akb 的 eval/longmemeval/docker-compose.yaml
                   # 只写了 loopback 映射，曾把整个仓连带判成单机服务。
                   "eval", "evals", "benchmark", "benchmarks",
                   "scripts", "hack", "ci"}
# M463：云原生部署清单（k8s / helm / charts）本身就是"要部署到集群"的
# 显式证据。有清单的仓不可能因为本地 compose 写了 loopback 就变成单机
# 工具 —— akb 的 deploy/k8s、deploy/helm 正是这种仓。
_ORCHESTRATION_DIRS = ("deploy/k8s", "k8s", "deploy/helm", "helm",
                       "deploy/charts", "charts", "deploy/manifests",
                       "manifests")
_REPO_LOOPBACK_MEMO: dict[str, tuple[bool, str]] = {}

# ---------------- M375：上传落盘面（是否可服务/可执行） ----------------
# 前提 A：文件名/落盘路径已做防穿越约束。
_UPLOAD_TRAVERSAL_GUARD_RE = re.compile(
    r"os\s*\.\s*path\s*\.\s*basename|\bsecure_filename\b|"
    r"\bPath\s*\([^)]{0,120}\)\s*\.\s*name\b|\bre\s*\.\s*sub\s*\(|"
    r"_contained_upload_path|\.\s*relative_to\s*\(|getCanonicalPath|"
    r"FilenameUtils\s*\.\s*getName|\.\s*normalize\s*\(", re.I)
# 条件 B-a：同文件下载出口是附件下载（浏览器不内联渲染）。
_UPLOAD_ATTACHMENT_RE = re.compile(
    r"content-disposition[^\n]{0,120}attachment|"
    r"\bFileResponse\s*\([^)]{0,200}filename\s*=|"
    r"as_attachment\s*=\s*True", re.I)
# 条件 B-a'：入口本身就是 RAG/索引/入库，不对外提供取回。
_UPLOAD_RAG_HINT_RE = re.compile(
    r"\b(?:rag|index|ingest|embed|vector|corpus|knowledge)\b", re.I)
# 条件 B-b：仓内是否把上传目录挂成静态目录。
_UPLOAD_STATIC_MOUNT_RE = re.compile(
    r"StaticFiles\s*\([^)]{0,200}upload|"
    r"\.\s*mount\s*\(\s*[\"'][^\"']*upload|"
    r"addResourceHandlers[\s\S]{0,400}upload|"
    r"send_from_directory\s*\([^)]{0,120}upload", re.I)
_REPO_UPLOAD_SERVE_MEMO: dict[str, bool] = {}


# ---------------- M387：Webhook 验签回显 ----------------
_WEBHOOK_NAME_RE = re.compile(r"(?i)(?:wxcallback|wechatcallback|webhook)")
_WEBHOOK_CHALLENGE_RE = re.compile(
    r"(?i)(?:echostr|hub\.challenge|zd_echo|hub_mode|hub_verify_token)")
_WEBHOOK_SIG_RE = re.compile(
    r"(?:wxCallbackSecurityCheck|checkSignature|verifySignature|"
    r"verify_signature|check_signature|computeWechatSignature)")


# ---------------- M383：redir 野仓降噪 ----------------
_REDIR_CALL_RE = re.compile(r"sendRedirect\s*\(\s*([^;]{0,300}?)\s*\)\s*;", re.S)
_SERVER_URL_HELPER_RE = re.compile(
    r"(?i)\b(?:build\w*Url|\w*LoginUrl|\w*Oauth\w*Url|\w*Sso\w*Url|"
    r"getRedirectUrl)\b")
_REFERER_HEADER_RE = re.compile(
    r"getHeader\s*\(\s*[\"']referer[\"']\s*\)|"
    r"headers?\s*\.\s*get\s*\(\s*[\"']referer", re.I)
_SHORTLINK_RE = re.compile(r"(?i)shortlink|getOriginalLink")
# M468：OAuth 中转入口（只认 unit 里的类名/方法名，路径目录名不算）。
_OAUTH_ENTRY_RE = re.compile(r"(?i)open_?auth|\boauth\b|get_?open_?id")
# 商户验签调用的各种写法：verifySign / checkSign / validateSign / signVerify /
# signCheck / SignUtil（dax-pay 用的是 paymentSignService.signVerify）。
_MERCHANT_SIGN_RE = re.compile(
    r"(?i)(?:(?:verify|check|validate)[_ ]?sign\w*|"
    r"sign(?:Verify|Check|Validate)\w*|\bSignUtil\b)")
# 入口跳转目标里的「服务字段.方法(」调用 —— 验签通常在做跳转的 Hop 服务方法里。
_OAUTH_HOP_CALL_RE = re.compile(r"([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(")
_OAUTH_HOP_MEMO: dict[tuple[str, str], bool] = {}


def _java_hop_sign_verified(repo_root: Path | None,
                            hop_calls: dict[str, set[str]],
                            src: str = "") -> bool:
    """跨文件读 Hop 方法实现体，确认里面做了商户验签（M468）。

    hop_calls: {接收者变量名: {方法名}}。先按「字段声明类型 / 接收者首字母大写」
    定位候选类文件（`openAuthService` → `OpenAuthService.java`），找不到才退回
    有界内容扫描 —— dax-pay 有 3000+ 个 .java，无脑全仓扫会在 400 个文件处
    截断，正好错过 daxpay-payment 模块里的 OpenAuthService。
    """
    if repo_root is None or not hop_calls:
        return False
    root = Path(repo_root)
    key = (str(root), "|".join(sorted(
        f"{recv}:{name}" for recv, names in hop_calls.items()
        for name in sorted(names))))
    if key in _OAUTH_HOP_MEMO:
        return _OAUTH_HOP_MEMO[key]
    # 变量 → 类型：字段声明（`private final OpenAuthService openAuthService;`）
    type_of = {var: typ for typ, var in re.findall(
        r"\b([A-Z]\w*(?:<[^>]*>)?)\s+([a-z]\w*)\s*(?=[;=,)])", src)}
    class_names: set[str] = set()
    for recv in hop_calls:
        typ = type_of.get(recv, "")
        if typ:
            class_names.add(typ.split("<")[0])
        class_names.add(recv[:1].upper() + recv[1:])
    candidates: list[Path] = []
    for nm in sorted(class_names):
        if not re.fullmatch(r"[A-Za-z_]\w*", nm):
            continue
        try:
            candidates.extend(root.rglob(f"{nm}.java"))
            candidates.extend(root.rglob(f"{nm}Impl.java"))
        except OSError:
            continue
    all_names = {name for names in hop_calls.values() for name in names}
    found = False
    for p in candidates[:40]:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name in all_names:
            if f"{name}(" in text and _MERCHANT_SIGN_RE.search(
                    _java_method_block(text, name)):
                found = True
                break
        if found:
            break
    if not found:
        # 回退：有界内容扫描（小仓 / 命名不规则）。
        scanned = 0
        for p in root.rglob("*.java"):
            if any(part in _SCAN_SKIP_DIRS for part in p.parts):
                continue
            scanned += 1
            if scanned > 400:
                break
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if any(f"{name}(" in text for name in all_names) and any(
                    f"{name}(" in text
                    and _MERCHANT_SIGN_RE.search(_java_method_block(text, name))
                    for name in all_names):
                found = True
                break
    _OAUTH_HOP_MEMO[key] = found
    return found


def _oauth_signed_relay(repo_root: Path | None, src: str, unit: str) -> bool:
    """签名认证后的 OAuth 回调中转（M468）。

    三条证据任一成立即可（都要求入口类名/方法名是 OAuth 入口）：
      1. 入口方法体里有商户验签调用；
      2. 入口类内（同一类的其它方法/字段）有商户验签；
      3. 入口跳转目标调用的 Hop 服务方法里做了商户验签
         （dax-pay：`openAuthService.generateOpenAuthRedirect` →
          `paymentSignService.signVerify(param)`）。
    """
    if not _OAUTH_ENTRY_RE.search(str(unit or "")) or not src:
        return False
    meth = unit.rsplit(".", 1)[-1]
    block = _java_method_block(src, meth)
    if _MERCHANT_SIGN_RE.search(block):
        return True
    cls = unit.rsplit(".", 1)[0] if "." in unit else ""
    lines = src.splitlines()
    span = _class_span(lines, cls) if cls else None
    if span and _MERCHANT_SIGN_RE.search(
            "\n".join(lines[span[0]:span[1] + 1])):
        return True
    hop_calls: dict[str, set[str]] = {}
    for m in _OAUTH_HOP_CALL_RE.finditer(block):
        recv, name = m.group(1), m.group(2)
        if name == meth:
            continue
        hop_calls.setdefault(recv, set()).add(name)
    return _java_hop_sign_verified(repo_root, hop_calls, src)


def _java_method_block(src: str, meth: str) -> str:
    """截出 Java 方法体（含签名），避免同文件兄弟方法的 Referer 连坐（M383）。"""
    if not meth:
        return src
    m = re.search(rf"\b{re.escape(meth)}\s*\(", src)
    if not m:
        return src
    start = src.rfind("\n", 0, m.start())
    start = start + 1 if start >= 0 else 0
    brace = src.find("{", m.end())
    if brace < 0:
        return src[start:]
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    return src[start:]


def _redir_targets(src: str) -> list[str]:
    """sendRedirect 的实参；裸变量先回溯到同方法内的赋值右值。"""
    out: list[str] = []
    for m in _REDIR_CALL_RE.finditer(src):
        t = m.group(1).strip()
        if re.fullmatch(r"[A-Za-z_]\w*", t):
            am = re.search(rf"\b{re.escape(t)}\s*=\s*([^;]+);", src)
            if am:
                out.append(am.group(1).strip())
                continue
        out.append(t)
    return out


def _redirect_from_referer(src: str, targets: list[str]) -> bool:
    """跳转目标是否直接/间接取自 Referer 头（M383）。"""
    for t in targets:
        if _REFERER_HEADER_RE.search(t):
            return True
        if re.fullmatch(r"[A-Za-z_]\w*", t) and re.search(
                rf"\b{re.escape(t)}\s*=\s*[^;]{{0,240}}?"
                rf"getHeader\s*\(\s*[\"']referer", src, re.I):
            return True
    return False


def _redir_args_non_free(src: str, target: str) -> bool:
    """构造 helper 的实参里有没有自由文本（String 形参/请求读取）（M383）。"""
    if re.search(r"getParameter|getHeader|getQueryString", target):
        return False
    for ident in set(re.findall(r"[A-Za-z_]\w*", target)):
        if re.search(rf"\bString\s+{re.escape(ident)}\b", src):
            return False
    return True


def _repo_serves_uploads(repo_root: Path | None) -> bool:
    """仓内是否把上传目录挂成静态目录（M375）。

    只认"挂载路径/目录名里带 upload"的装配；`StaticFiles("/static", ...)`
    这种与上传无关的挂载不能当成"上传可服务"。
    """
    if repo_root is None:
        return False
    root = Path(repo_root)
    try:
        key = str(root.resolve())
    except OSError:
        key = str(root)
    if key in _REPO_UPLOAD_SERVE_MEMO:
        return _REPO_UPLOAD_SERVE_MEMO[key]
    found = False
    scanned = 0
    for pattern in ("*.py", "*.java"):
        for p in root.rglob(pattern):
            if any(part in _SCAN_SKIP_DIRS for part in p.parts):
                continue
            scanned += 1
            if scanned > 300:
                break
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if _UPLOAD_STATIC_MOUNT_RE.search(text):
                found = True
                break
        if found:
            break
    _REPO_UPLOAD_SERVE_MEMO[key] = found
    return found


def _has_orchestration_manifests(root: Path) -> bool:
    """仓内是否有 k8s / helm / charts 部署清单（M463）。

    只要清单目录里至少有一个 `.yaml` / `.yml`，就说明这个仓的服务是按
    "部署到集群"设计的 —— 本地 compose 的回环映射只是开发便利，不能据此
    把整仓判成单机工具。
    """
    for rel in _ORCHESTRATION_DIRS:
        d = root / rel
        if not d.is_dir():
            continue
        try:
            for p in d.rglob("*"):
                if p.is_file() and p.suffix.lower() in (".yaml", ".yml"):
                    return True
        except OSError:
            continue
    return False


def _repo_loopback_only(repo_root: Path | None) -> tuple[bool, str]:
    """整仓是否只监听本机回环（M359）。

    返回 (True, 证据文件)；只要仓内任何地方显式绑定 0.0.0.0 / 公网端口映射，
    就判 False —— 宁可漏拦一个单机工具，也不能把真远程服务整仓放过。
    """
    if repo_root is None:
        return False, ""
    root = Path(repo_root)
    try:
        key = str(root.resolve())
    except OSError:
        key = str(root)
    if key in _REPO_LOOPBACK_MEMO:
        return _REPO_LOOPBACK_MEMO[key]

    # M463：云原生部署清单优先于本地回环证据（akb 的 deploy/k8s + deploy/helm）。
    if _has_orchestration_manifests(root):
        _REPO_LOOPBACK_MEMO[key] = (False, "")
        return False, ""

    loop_hit = ""
    public_hit = ""
    scanned = 0
    for p in root.rglob("*.py"):
        if any(part in _SCAN_SKIP_DIRS for part in p.parts):
            continue
        scanned += 1
        if scanned > 400:
            break
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        if not loop_hit:
            if _LOOPBACK_BIND_RE.search(text):
                loop_hit = rel
            elif "LocalAccessMiddleware" in text:
                loop_hit = f"{rel}（LocalAccessMiddleware）"
        if _PUBLIC_BIND_RE.search(text):
            public_hit = f"{rel} 绑定 0.0.0.0"
            break

    if not public_hit:
        for name in ("Dockerfile", "Procfile", "docker-compose.yml",
                     "docker-compose.yaml", "compose.yml", "compose.yaml"):
            for p in list(root.rglob(name))[:8]:
                if any(part in _SCAN_SKIP_DIRS for part in p.parts):
                    continue
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                rel = p.relative_to(root).as_posix()
                if _PUBLIC_CLI_HOST_RE.search(text):
                    public_hit = f"{rel} --host 0.0.0.0"
                    break
                for m in _PORT_MAP_RE.finditer(text):
                    host_ip = m.group(1)
                    if host_ip in ("127.0.0.1", "::1", "localhost"):
                        loop_hit = loop_hit or f"{rel} 端口映射 {host_ip}"
                    elif host_ip in (None, "", "0.0.0.0", "::"):
                        # M463：裸 `8000:8000` / `0.0.0.0:8000:8000` /
                        # `[::]:8000:8000` 都是公网映射。旧正则只认三段式，
                        # 这一段永远到不了（死代码）。
                        public_hit = f"{rel} 端口映射 {m.group(2)}:{m.group(3)}"
                        break
                if public_hit:
                    break
            if public_hit:
                break

    res = (bool(loop_hit) and not public_hit, loop_hit if not public_hit else "")
    _REPO_LOOPBACK_MEMO[key] = res
    return res


# ---------------- M411：默认回环绑定 + 全局请求鉴权 ----------------
# tubecli 的启动方式不是字面量 `uvicorn.run(app, host="127.0.0.1")`，而是
#   host: str = "127.0.0.1"
#   uvicorn.run(app, host=host)
# 旧 `_LOOPBACK_BIND_RE` 只认字面量，漏掉了这种变量/默认参数形态。
_LOOPBACK_DEFAULT_RE = re.compile(
    r"\bhost\s*(?::\s*str)?\s*=\s*[\"'](?:127\.0\.0\.1|localhost|::1)[\"']|"
    # tubecli：host = "0.0.0.0" if (in_container() or headless) else "127.0.0.1"
    r"\bhost\s*=\s*[\"']0\.0\.0\.0[\"']\s+if\b[^\n]*\belse\s+[\"']"
    r"(?:127\.0\.0\.1|localhost|::1)[\"']|"
    r"os\s*\.\s*(?:getenv|environ\s*\.\s*get)\s*\([^)]*,\s*[\"']"
    r"(?:127\.0\.0\.1|localhost|::1)[\"']\s*\)")
_HOST_VAR_BIND_RE = re.compile(
    r"\b(?:uvicorn\s*\.\s*run|app\s*\.\s*run|hypercorn\s*\.\s*run|serve)\s*"
    r"\([^)]*?\bhost\s*=\s*host\b", re.I | re.S)
# 全局请求鉴权：FastAPI/Flask 中间件、before_request、或通用 auth 校验调用。
_GLOBAL_AUTH_RE = re.compile(
    r"@app\s*\.\s*middleware\s*\(\s*[\"']http[\"']\s*\)|"
    r"@app\s*\.\s*before_request|"
    r"add_middleware\s*\(\s*\w*(?:Auth|Token|Session)\w*|"
    r"\bauth\s*\.\s*check_request\s*\(|"
    r"\bverify_token\s*\(|\bcheck_auth\s*\(", re.I)
_REPO_AUTH_LOCAL_MEMO: dict[str, tuple[bool, str]] = {}


def _repo_authenticated_local(repo_root: Path | None) -> tuple[bool, str]:
    """M411：整仓是否「默认回环绑定 + 全局请求鉴权」。

    条件 A：主服务有显式回环绑定（字面量或 `host = "127.0.0.1"` 变量形态），
            且**没有无条件**的字面量 0.0.0.0 启动（android-agent 的
            `run.py:11` 就是无条件 0.0.0.0 → 不满足）。
    条件 B：主服务挂有全局请求鉴权中间件/守卫。
    容器/headless 分支里的条件公网绑定（`host = "0.0.0.0" if ... else ...`）
    不直接判公网 —— 那是显式部署选择，且全局鉴权仍在。
    """
    if repo_root is None:
        return False, ""
    root = Path(repo_root)
    try:
        key = str(root.resolve())
    except OSError:
        key = str(root)
    if key in _REPO_AUTH_LOCAL_MEMO:
        return _REPO_AUTH_LOCAL_MEMO[key]

    loop_ev = ""
    auth_ev = ""
    public_ev = ""
    scanned = 0
    for p in root.rglob("*.py"):
        if any(part in _SCAN_SKIP_DIRS for part in p.parts):
            continue
        scanned += 1
        if scanned > 400:
            break
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        if not loop_ev:
            if _LOOPBACK_BIND_RE.search(text):
                loop_ev = f"{rel} 显式回环绑定"
            elif (_LOOPBACK_DEFAULT_RE.search(text)
                  and _HOST_VAR_BIND_RE.search(text)):
                loop_ev = f"{rel} 默认 host=127.0.0.1 变量绑定"
        if not auth_ev and _GLOBAL_AUTH_RE.search(text):
            auth_ev = f"{rel} 全局请求鉴权"
        if not public_ev and _PUBLIC_BIND_RE.search(text):
            public_ev = f"{rel} 无条件绑定 0.0.0.0"
            break

    res = (bool(loop_ev) and bool(auth_ev) and not public_ev,
           f"{loop_ev} + {auth_ev}" if not public_ev else "")
    _REPO_AUTH_LOCAL_MEMO[key] = res
    return res


# M379：跨文件 2-Hop 上传守卫。入口把校验/落盘委托给 service 时，
# 单文件切片看不到白名单与固定命名，规则层会判 True；这里用 repo_root
# 把 Hop1（service）与 Hop2（校验/存储 helper）拼回证据面。
_UPLOAD_EXT_WHITELIST_RE = re.compile(
    r"(?:\b(?:not\s+in|in)\s+\w*(?:EXTENSIONS?|ALLOWED|SUPPORTED|WHITELIST|VALID)\w*|"
    r"\b(?:EXTENSIONS?|ALLOWED_\w+|SUPPORTED_\w+|WHITELIST)\b\s*(?:=|:)|"
    r"\.\s*suffix\b[^\n]{0,60}\bin\b)", re.I)
_UPLOAD_GENERATED_NAME_RE = re.compile(
    r"uuid\s*\.\s*uuid4|uuid4\s*\(|secrets\s*\.\s*token_hex", re.I)
_PY_CALL_EXCLUDE = frozenset({
    "if", "for", "while", "with", "return", "print", "len", "str", "int",
    "float", "bool", "dict", "list", "set", "tuple", "open", "range",
    "enumerate", "zip", "sorted", "isinstance", "super", "type", "getattr",
    "setattr", "hasattr", "format", "join", "split", "strip", "lower",
    "upper", "replace", "startswith", "endswith", "append", "extend",
    "get", "keys", "values", "items", "read", "write", "close", "encode",
    "decode", "raise", "assert", "await", "async", "def", "class", "lambda",
})


def _py_function_blocks(text: str, names: set[str],
                        limit: int = 8) -> dict[str, str]:
    """在文本里找 `def <name>(` 的函数体（M379）。"""
    out: dict[str, str] = {}
    for name in names:
        if len(out) >= limit:
            break
        m = re.search(rf"(?m)^[ \t]*(?:async\s+)?def\s+{re.escape(name)}\s*\(",
                      text)
        if not m:
            continue
        tail = text[m.start():]
        # 从**当前 def 行之后**找下一个 def：旧写法 `tail[1:]` 会把同一个
        # def 行（缩进后整体右移一位）再次匹配上，函数体被截成 1 个字符。
        head_end = tail.find("\n")
        if head_end < 0:
            head_end = len(tail)
        nxt = re.search(r"(?m)^[ \t]*(?:async\s+)?def\s+\w+\s*\(",
                        tail[head_end:])
        out[name] = tail[:head_end + nxt.start()] if nxt else tail
    return out


def _repo_def_bodies(repo_root: Path, names: set[str],
                     max_files: int = 400) -> dict[str, str]:
    """跨文件找函数定义体（Hop 1/2），有界扫描（M379）。"""
    out: dict[str, str] = {}
    if not names:
        return out
    scanned = 0
    for p in Path(repo_root).rglob("*.py"):
        if any(part in _SCAN_SKIP_DIRS for part in p.parts):
            continue
        scanned += 1
        if scanned > max_files or len(out) >= len(names):
            break
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, body in _py_function_blocks(text, names - set(out)).items():
            out[name] = body
    return out


def _py_called_names(text: str) -> set[str]:
    # 允许点号前缀：`chat_attachment_service.save_upload(` 要取到
    # `save_upload`（M379 实测：带 `(?<![\w.])` 会把跨文件 service 调用
    # 整条漏掉，2-Hop 守卫永远拼不起来）。
    names = set(re.findall(r"(?<![\w])([a-z_][\w]*)\s*\(", text))
    return {n for n in names if n not in _PY_CALL_EXCLUDE and len(n) > 3}


def upload_guard_scope(repo_root: Path | None, src: str, unit: str) -> str:
    """入口 + Hop1 + Hop2 的上传守卫证据面（M379）。

    RAG_LearnLittleCode 形态：`routers/chat.py:upload_chat_file` →
    `services/chat_attachment_service.py:save_upload`（Hop 1）→
    `utils/file_handler.py:validate_chat_attachment`（Hop 2，白名单 + magic）。
    切片只带入口，规则层因此判 True；这里用 repo_root 把两跳拼回来。
    """
    if repo_root is None or not src:
        return src or ""
    meth = unit.rsplit(".", 1)[-1]
    entry = _py_function_blocks(src, {meth}).get(meth) or src
    hop1 = _repo_def_bodies(Path(repo_root), _py_called_names(entry))
    hop1_text = "\n".join(hop1.values())
    hop2 = _repo_def_bodies(Path(repo_root), _py_called_names(hop1_text))
    return entry + "\n" + hop1_text + "\n" + "\n".join(hop2.values())


def classify(record: dict, repo_root: Path | None = None) -> dict:
    """判定一条 FRESH 根因是否属于“陌生野仓噪音”。

    返回 {"blocked": bool, "code": str, "reason": str}；blocked=True 的
    记录由调用方改判 UNKNOWN 并压进板块 B。
    """
    unit = str(record.get("unit") or "")
    file = _norm(record.get("file"))
    if "demo" in file or "demo" in unit.lower():
        return {"blocked": True, "code": DEMO_CONTROLLER,
                "reason": "demo/示例入口（非生产代码）"}
    # M428：测试夹具 / 集成测试后端不是生产入口（WSO2 product-apim 的
    # modules/integration/tests-common/backend-service）。
    if re.search(r"(?:^|/)(?:tests?-common|test-fixtures?|fixtures?|"
                 r"integration-tests?)(?:/|$)", file):
        return {"blocked": True, "code": TEST_FIXTURE_ONLY,
                "reason": "测试夹具/集成测试后端代码，不是生产入口"}

    # M469：开发叠加 compose 的示例凭据压 B（akb 的
    # `docker-compose.keycloak.yaml` → `# OPTIONAL local Keycloak overlay`）。
    # M463 让 hardcoded_secret 不再继承 LOCAL_LOOPBACK_ONLY 之后，这类文件
    # 会直接进 A 板；它需要的是"这是开发叠加"的专属归因，不是回环继承。
    if str(record.get("category") or "") == "hardcoded_secret":
        _drel = str(record.get("file") or "")
        _dsrc = _read(repo_root, _drel)
        if _dsrc and _dev_overlay_compose(_drel, _dsrc):
            return {"blocked": True, "code": DEV_OVERLAY_SECRET,
                    "reason": ("文件头部显式标注 OPTIONAL local overlay / "
                               "NOT part of the default stack / for "
                               "developing/testing 的开发叠加 compose，"
                               "里面的凭据是本地开发示例值")}

    # M361：WebSocket 前置鉴权。accept() 前校验会话并 close(4401/1008) 的
    # WS 入口不是未授权候选（redcell 5 条 authz 在此归零）。
    if (record.get("category") == "authz" and file.endswith(".py")):
        _ws_src = _read(repo_root, str(record.get("file") or ""))
        if _ws_src and ws_auth_guard(_ws_handler_block(_ws_src, unit)):
            return {"blocked": True, "code": WS_AUTH_PRESENT,
                    "reason": ("WebSocket 路由在 accept() 前校验会话并 "
                               "close(4401/1008)：鉴权存在，不是未授权入口")}

    # M449：野仓 securecookie（缺 Secure 标记）是低危加固项，统一归 B。
    if record.get("category") == "securecookie":
        return {"blocked": True, "code": LOW_SEVERITY_SECURECOOKIE,
                "reason": "Cookie 缺 Secure 标记，低危加固项归 B 板"}

    # M449：FastAPI Depends(...) / WS token 鉴权 / 显式 verify_* 守卫。
    if (record.get("category") == "authz" and file.endswith(".py")):
        _psrc = _read(repo_root, str(record.get("file") or ""))
        if _psrc and _py_authz_guard_present(_psrc, _ws_handler_block(_psrc, unit)):
            return {"blocked": True, "code": AUTHZ_CLASS_OR_BASE_GUARD,
                    "reason": ("入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / "
                               "显式 verify_* 守卫")}

    # M435：类级/基类级鉴权注解（AirPower @Permission / Sa-Token @SaCheckLogin /
    # Spring @PreAuthorize / Shiro @RequiresPermissions）。
    if (record.get("category") == "authz" and file.endswith(".java")
            and _java_authz_class_guard(
                repo_root, str(record.get("file") or ""), unit)):
        return {"blocked": True, "code": AUTHZ_CLASS_OR_BASE_GUARD,
                "reason": ("当前类或继承基类挂有类级 @Permission/鉴权注解，"
                           "框架已在类层面鉴权")}

    # M387：Webhook 验签挑战串回显（echostr / hub.challenge）。
    if record.get("category") == "xss":
        _xu = str(unit or "")
        _xf = str(record.get("file") or "")
        _xsrc = _read(repo_root, _xf)
        if _xsrc:
            _xblock = (_java_method_block(_xsrc, _xu.rsplit(".", 1)[-1])
                       if _xf.endswith(".java") else _xsrc)
            if (_WEBHOOK_NAME_RE.search(_xu) or _WEBHOOK_NAME_RE.search(_xf)
                    or _WEBHOOK_CHALLENGE_RE.search(_xblock)
                    or _WEBHOOK_SIG_RE.search(_xblock)):
                return {"blocked": True, "code": WEBHOOK_CHALLENGE_ECHO,
                        "reason": ("第三方 Webhook 验签挑战串原样回显"
                                   "（echostr/challenge），非浏览器 HTML 页面")}

    # M383：redir 三类野仓降噪（paicoding 实测：5 条 A 全是 redir）。
    if record.get("category") == "redir":
        _ru = str(unit or "")
        _rf = str(record.get("file") or "")
        if _SHORTLINK_RE.search(_ru) or _SHORTLINK_RE.search(_rf):
            return {"blocked": True, "code": SHORTLINK_BY_DESIGN,
                    "reason": ("短链还原服务按设计跳转到创建者写入的 "
                               "originalUrl，不是开放重定向缺陷")}
        _rsrc = _read(repo_root, _rf)
        if _rsrc:
            # M468：签名认证后的 OAuth 回调中转归 B（dax-pay OpenAuth）。
            if _oauth_signed_relay(repo_root, _rsrc, _ru):
                return {"blocked": True, "code": SIGNED_OAUTH_RELAY,
                        "reason": ("OAuth 中转入口带商户验签（verifySign / "
                                   "checkSign / signVerify / SignUtil），"
                                   "验签通过后 302 到授权方是设计内跳转，"
                                   "redirect_url 不可被未签名请求控制")}
            if _rf.endswith(".py"):
                # M423：同源跳转 helper（_local_next / netloc 判空）兜底。
                from core.agents.rule_detectors import (
                    _PY_REDIR_GUARD_RE as _py_guard)
                if _py_guard.search(_rsrc):
                    return {"blocked": True, "code": SAFE_REDIRECT_GUARD,
                            "reason": ("Python 跳转目标经 _local_next / "
                                       "netloc 等同源校验 helper 处理，"
                                       "不是开放重定向")}
            _block = (_java_method_block(_rsrc, _ru.rsplit(".", 1)[-1])
                      if _rf.endswith(".java") else _rsrc)
            _targets = _redir_targets(_block)
            if _redirect_from_referer(_block, _targets):
                return {"blocked": True, "code": REFERER_OPEN_REDIRECT,
                        "reason": ("跳转目标取自 Referer 头（自引用跳转），"
                                   "外部域名不可由参数注入，低危")}
            for _t in _targets:
                if (_SERVER_URL_HELPER_RE.search(_t)
                        and _redir_args_non_free(_block, _t)):
                    return {"blocked": True, "code": SERVER_BUILT_REDIRECT,
                            "reason": ("跳转目标由服务端 URL 构造 helper 产出，"
                                       "实参为常量/布尔/非自由文本，"
                                       "外部域名不可控")}

    # M407：zip_slip 降噪 —— 入口没有上传入参，解压对象来自固定域名下载的
    # 组件包（引擎/资源自更新），压缩包内容不可由请求方控制。
    if (record.get("category") == "zip_slip" and file.endswith(".py")
            and repo_root is not None):
        _zsrc = _read(repo_root, str(record.get("file") or ""))
        if _zsrc:
            _zblock = _ws_handler_block(_zsrc, unit) or _zsrc
            _has_upload = bool(re.search(
                r"\bUploadFile\b|\bFile\s*\(|request\s*\.\s*files|"
                r"request\s*\.\s*FILES", _zblock))
            # M409：压缩包来源若可由请求体/查询参数控制（download_url 等），
            # 就不是"固定域名组件包" —— 不能降噪，否则会把真 zip_slip 藏掉。
            _body_url = bool(re.search(
                r"body\s*\.\s*get\s*\(\s*[\"'](?:download_url|url|file_url)"
                r"[\"']|request\s*\.\s*(?:json|form|args|GET|POST)|"
                r"\bparams\s*\.\s*get\s*\(", _zblock))
            _fixed_dl = bool(
                re.search(r"f?[\"']https?://[A-Za-z0-9._-]+/", _zblock)
                and re.search(r"requests|httpx|urllib|urlretrieve",
                              _zblock, re.I))
            if not _has_upload and not _body_url and _fixed_dl:
                return {"blocked": True, "code": VENDOR_ARCHIVE_EXTRACT,
                        "reason": ("无外部上传入参，解压对象来自固定域名"
                                   "下载的组件包（自更新/内置资源）")}

    # M375：上传面。前提 A（已防穿越）+ 条件 B（无可服务/可执行出口）
    # 同时成立 → 攻击者既跳不出目录，也拿不到 inline 响应，压 B 板。
    # 落点必须在 wild_noise（有 repo_root 才能看全局挂载）；放进
    # rule_detectors 的单函数切片会误伤 PyGoat/Hello-Java-Sec 等基准靶场。
    if (record.get("category") == "unrestricted_upload"
            and repo_root is not None and file.endswith((".py", ".java"))
            and not _EXEC_PACKAGE_UPLOAD_RE.search(
                f"{unit} {record.get('file') or ''}")):
        _up_src = _read(repo_root, str(record.get("file") or ""))
        if _up_src:
            # M379：入口把校验/落盘委托给 service 时，把 Hop1/Hop2 拼回证据面。
            _scope = (upload_guard_scope(repo_root, _up_src, unit)
                      if file.endswith(".py") else _up_src)
            _guarded = bool(_UPLOAD_TRAVERSAL_GUARD_RE.search(_scope))
            _whitelisted = bool(_UPLOAD_EXT_WHITELIST_RE.search(_scope)
                                and _UPLOAD_GENERATED_NAME_RE.search(_scope))
            if (_guarded or _whitelisted) and not _repo_serves_uploads(repo_root):
                if (_UPLOAD_ATTACHMENT_RE.search(_up_src)
                        or _UPLOAD_ATTACHMENT_RE.search(_scope)
                        or _UPLOAD_RAG_HINT_RE.search(unit)
                        or _UPLOAD_RAG_HINT_RE.search(
                            str(record.get("file") or ""))):
                    return {"blocked": True, "code": UPLOAD_SERVING_ONLY,
                            "reason": ("已防路径穿越 / 已做扩展名白名单+固定"
                                       "命名，且下载为 attachment 或仅内部"
                                       "语料入库，无静态挂载或内联渲染面")}
                return {"blocked": True, "code": NON_EXECUTABLE_UPLOAD,
                        "reason": ("已防路径穿越 / 已做扩展名白名单+固定命名，"
                                   "落盘目录非 Web 静态挂载"
                                   "（无 StaticFiles/addResourceHandlers 指向"
                                   "上传目录），上传物不可执行")}

    if str(record.get("category") or "") in SOLIDITY_ONLY and not file.endswith(
            ".sol"):
        return {"blocked": True, "code": RULE_LANGUAGE_MISMATCH,
                "reason": (f"{record.get('category')} 是 Solidity 类目，"
                           f"入口文件是 {Path(file).suffix or '未知类型'}")}
    if str(record.get("category") or "") in JAVA_ONLY and not file.endswith(
            ".java"):
        return {"blocked": True, "code": RULE_LANGUAGE_MISMATCH,
                "reason": (f"{record.get('category')} 是 Java 专属类目，"
                           f"入口文件是 {Path(file).suffix or '未知类型'}")}

    src = _read(repo_root, str(record.get("file") or ""))
    if looks_local_socket(src):
        return {"blocked": True, "code": LOCAL_UNIX_SOCKET_SERVER,
                "reason": ("AF_UNIX 本地控制通道（0700/0600 + 对端 UID 校验），"
                           "设计上不可从网络到达")}
    if looks_local_loopback(src):
        return {"blocked": True, "code": LOCAL_LOOPBACK_ONLY,
                "reason": ("显式仅允许 loopback 客户端的单机工作台"
                           "（LocalAccessMiddleware / 127.0.0.1 校验），"
                           "无远程攻击面")}
    # M359：文件本身没写 loopback，但同仓主服务入口已经证明整仓只监听
    # 本机时，子路由继承 LOCAL_LOOPBACK_ONLY（消除同仓分类撕裂）。
    # M463：hardcoded_secret 不继承。凭据一旦提交进仓库，任何能读仓的人
    # （含把仓 clone 到本机跑的人）都拿到了它，"本机服务"不是它的信任边界；
    # 而且 11-21 的 akb 实测里，压掉 `[secret-file] docker-compose.keycloak.yaml`
    # 的证据文件是 `eval/longmemeval/docker-compose.yaml` —— 理由和对象根本
    # 不是同一个部署面。
    _repo_loop, _repo_ev = _repo_loopback_only(repo_root)
    if _repo_loop and str(record.get("category") or "") != "hardcoded_secret":
        return {"blocked": True, "code": LOCAL_LOOPBACK_ONLY,
                "reason": (f"同仓主服务仅绑定回环（{_repo_ev}），"
                           f"子路由继承单机边界，无远程攻击面")}
    # M411：默认回环绑定（变量/默认参数形态）+ 全局请求鉴权 —— 认证后的
    # 本地管理面。tubecli 的 4 条本地项由此收归 B 板；android-agent 的
    # `run.py:11` 是无条件 0.0.0.0，条件 A 不成立，不受影响。
    _repo_auth_local, _repo_auth_ev = _repo_authenticated_local(repo_root)
    if _repo_auth_local and str(record.get("category") or "") not in (
            "hardcoded_secret", "jwt_weakness"):
        # M415：硬编码密钥 / JWT 弱校验是鉴权基石类目 —— 攻击者可借它
        # 直接伪造全局鉴权凭据，不能被"认证后本地管理面"降噪压掉。
        return {"blocked": True, "code": AUTHENTICATED_LOCAL_ONLY,
                "reason": (f"服务默认回环绑定且挂有全局请求鉴权"
                           f"（{_repo_auth_ev}），属认证后本地管理面，"
                           f"不作为远程未授权 0-day 交单")}

    if record.get("category") == "cmdi" and file.endswith(".py"):
        src = _read(repo_root, str(record.get("file") or ""))
        if src and not _CMD_SINK_RE.search(src):
            return {"blocked": True, "code": NO_CMD_SINK,
                    "reason": ("入口文件无任何命令执行调用"
                               "（os.system/subprocess/asyncio.create_subprocess），"
                               "cmdi 来自切片里未被入口调用的辅助函数")}

    if record.get("category") == "log_injection":
        return {"blocked": True, "code": LOW_SEVERITY_LOG_INJECTION,
                "reason": ("CWE-117 日志伪造（CRLF 注入）属低危，"
                           "不作为首杀交单项")}

    if record.get("category") == "sqli" and file.endswith(".py"):
        raw = str(record.get("file") or "")
        src = _read(repo_root, raw)
        # M372：从"整份文件有没有 .execute"收紧到"入口函数体 + 其可达
        # 辅助函数"。apowerb 的 list_skills / list_tool_configs 入口体
        # 里没有任何 SQL，但同文件别处有 .execute —— 旧判据因此放行。
        if src and not python_entry_sql_sink(src, unit.rsplit(".", 1)[-1]):
            return {"blocked": True, "code": NO_SQL_SINK,
                    "reason": ("入口函数体（含其可达辅助函数）里没有任何 SQL "
                               "执行语句（.execute/.executemany/.executescript），"
                               "sqli 来自切片里未被入口调用的辅助函数")}

    if record.get("category") in ("authz", "pathtraver",
                                  "arbitrary_file_delete", "unrestricted_upload"):
        src = _read(repo_root, str(record.get("file") or ""))
        if (src and "haveSuperAdminAuth(" in src) or "/superadmin/" in "/" + file:
            return {"blocked": True, "code": SUPERADMIN_ONLY,
                    "reason": ("超管专属入口（haveSuperAdminAuth / superadmin 路径），"
                               "超管信任边界内的路径拼接不立项")}

    if record.get("category") == "authz":
        path = "/" + file.lstrip("/")
        meth = unit.rsplit(".", 1)[-1]
        if any(p in path for p in PUBLIC_PREFIXES) and _READONLY_VERB.match(meth):
            return {"blocked": True, "code": PUBLIC_READONLY_ENDPOINT,
                    "reason": f"公开只读接口 {meth}（{'/'.join(PUBLIC_PREFIXES)}）"}
    return {"blocked": False, "code": "", "reason": ""}


def _class_span(lines: list[str], cls: str) -> tuple[int, int] | None:
    pat = re.compile(rf"\bclass\s+{re.escape(cls)}\b")
    for i, line in enumerate(lines):
        if not pat.search(line):
            continue
        depth = 0
        seen = False
        for k in range(i, len(lines)):
            depth += lines[k].count("{") - lines[k].count("}")
            if "{" in lines[k]:
                seen = True
            if seen and depth <= 0:
                return i, k
        return i, len(lines) - 1
    return None


def _methods(lines: list[str], start: int, end: int) -> list[dict]:
    out: list[dict] = []
    for i in range(start, end + 1):
        m = _METHOD_DECL.match(lines[i])
        if not m:
            continue
        name = m.group(1)
        annotations: list[str] = []
        j = i - 1
        blanks = 0
        while j >= start and i - j <= 12:
            s = lines[j].strip()
            if not s:
                blanks += 1
                if blanks > 2:
                    break
                j -= 1
                continue
            if s.startswith("@"):
                annotations.append(s.split("(")[0].strip())
                j -= 1
                continue
            if s.startswith((")", ",")) or s.endswith("),"):
                j -= 1
                continue
            break
        guarded = any(a in GUARD_ANNOTATIONS or a.startswith(tuple(GUARD_ANNOTATIONS))
                      for a in annotations)
        out.append({"name": name, "line": i + 1, "annotations": annotations,
                    "guarded": guarded})
    return out


_PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")
_PY_GUARD = ("Depends(get_current", "Depends(require", "Depends(verify",
             "Depends(auth", "Security(", "@login_required", "@jwt_required",
             "IsAuthenticated", "permission_required", "@requires_auth",
             "LoginRequiredMixin")
_PY_WRITE_DECOR = re.compile(r"@\w[\w.]*\.(?:post|put|patch|delete)\s*\(", re.I)


def _py_functions(lines: list[str]) -> list[dict]:
    out: list[dict] = []
    for i, line in enumerate(lines):
        m = _PY_DEF.match(line)
        if not m:
            continue
        decos: list[str] = []
        j = i - 1
        while j >= 0:
            s = lines[j].strip()
            if s.startswith("@"):
                decos.append(s)
                j -= 1
                continue
            if not s:
                j -= 1
                continue
            break
        block = "\n".join(decos + [line] + lines[i + 1:i + 4])
        out.append({"name": m.group(1), "line": i + 1,
                    "guarded": any(g in block for g in _PY_GUARD),
                    "write": bool(_PY_WRITE_DECOR.search("\n".join(decos)))})
    return out


def _python_promote(path: Path, lines: list[str], meth: str) -> dict:
    funcs = _py_functions(lines)
    target = next((f for f in funcs if f["name"] == meth), None)
    if target is None or target["guarded"] or not target["write"]:
        return {"level": "", "code": "", "evidence": ""}
    guarded = [f for f in funcs if f["guarded"] and f["name"] != meth]
    if not guarded:
        return {"level": "", "code": "", "evidence": ""}
    return {"level": "HIGH", "code": AUTHZ_SIBLING_GUARD,
            "evidence": (f"同文件 {len(guarded)} 个入口带鉴权依赖"
                         f"（Depends/Security/login_required），"
                         f"唯 {meth} 无（{path.name}:{target['line']}）")}


_IDENTITY_GUARD_RE = re.compile(
    r"\b(?:getUserDetails|checkAuthor|getCurrentUser|getLoginUser|"
    r"SecurityUtils\s*\.\s*get|StpUtil\s*\.\s*(?:check|get)|"
    r"request\s*\.\s*user\s*\.\s*is_authenticated|@login_required|"
    r"get_current_user|current_user\b|"
    # M376：WebSocket 前置鉴权（redcell 形态）也算身份校验证据。
    r"jwt\s*\.\s*decode|_authed\s*\(|verify_token\s*\()")


def _package_guard(path: Path, lines: list[str]) -> dict:
    """同目录 >=2 个 Controller 有鉴权注解，当前文件整类没有（M322）。"""
    text = "\n".join(lines)
    if _IDENTITY_GUARD_RE.search(text):
        return {"level": "", "code": "", "evidence": ""}
    if any(a in text for a in GUARD_ANNOTATIONS):
        return {"level": "", "code": "", "evidence": ""}
    peers = 0
    for p in sorted(path.parent.glob("*.java")):
        if p == path:
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(a in t for a in GUARD_ANNOTATIONS):
            peers += 1
    if peers >= 2:
        return {"level": "HIGH", "code": AUTHZ_PACKAGE_GUARD,
                "evidence": (f"同目录 {peers} 个 Controller 带 "
                             f"@PreAuthorize/@RequiresPermissions，"
                             f"{path.name} 整类无鉴权注解且无身份校验")}
    return {"level": "", "code": "", "evidence": ""}


def promote(record: dict, repo_root: Path | None = None) -> dict:
    """authz 高置信度提拔：同文件其它写接口都被注解守卫，唯独当前写接口漏加。"""
    if record.get("category") != "authz" or repo_root is None:
        return {"level": "", "code": "", "evidence": ""}
    unit = str(record.get("unit") or "")
    cls, _, meth = unit.rpartition(".")
    if not cls or not meth:
        return {"level": "", "code": "", "evidence": ""}
    path = Path(repo_root) / str(record.get("file") or "")
    if not path.is_file():
        return {"level": "", "code": "", "evidence": ""}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {"level": "", "code": "", "evidence": ""}
    if path.suffix.lower() == ".py":
        return _python_promote(path, lines, meth)
    if not _WRITE_VERB.match(meth):
        return {"level": "", "code": "", "evidence": ""}
    span = _class_span(lines, cls.split(".")[-1])
    start, end = span if span else (0, len(lines) - 1)
    methods = _methods(lines, start, end)
    target = next((m for m in methods if m["name"] == meth), None)
    if target is None or target["guarded"]:
        return {"level": "", "code": "", "evidence": ""}
    guarded = [m for m in methods if m["guarded"] and m["name"] != meth]
    if not guarded:
        pkg = _package_guard(path, lines)
        if pkg:
            return pkg
        return {"level": "", "code": "", "evidence": ""}
    names = sorted({a for m in guarded for a in m["annotations"]
                    if a in GUARD_ANNOTATIONS})
    return {"level": "HIGH", "code": AUTHZ_SIBLING_GUARD,
            "evidence": (f"同文件 {len(guarded)} 个接口带 {'/'.join(names)}，"
                         f"唯 {meth} 无鉴权注解（{path.name}:{target['line']}）")}
