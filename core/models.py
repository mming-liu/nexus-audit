"""统一数据契约：CodeUnit, CallEdge, VulnHypothesis, PoCResult"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# 同名重载的序号后缀：`ShoppingCartController.updateX#2`。
# 切片器给重载方法加 `#N` 以保证 unit_name 全局唯一（否则跨路由串接会把
# PUT 和 DELETE 当成同一个方法），但**真值表按 `类.方法` 硬编码**、判据按
# 方法名做正则匹配 —— 凡是"拿 unit_name 去对表"的地方都必须先剥掉它。
_OVERLOAD_SUFFIX_RE = re.compile(r"#\d+$")


def base_unit_name(unit_name: str) -> str:
    """去掉同名重载的 `#N` 序号后缀，还原「类名.方法名」。"""
    return _OVERLOAD_SUFFIX_RE.sub("", unit_name)


class Language(str, Enum):
    PYTHON_WEB = "python_web"
    JAVA_WEB = "java_web"
    SOLIDITY_WEB3 = "solidity_web3"


@dataclass
class CodeUnit:
    """第一层切片器输出的统一单元：路由函数或合约方法。"""
    file_path: str
    language: Language
    unit_name: str                       # 路由函数名或合约方法名
    start_line: int
    end_line: int
    decorators_or_modifiers: list[str] = field(default_factory=list)
    called_symbols: list[str] = field(default_factory=list)  # 供第2层按需展开
    source_code: str = ""                # 带行号的源码切片
    own_body: str = ""                   # 仅本方法体（不含同文件辅助方法与各类证据）
    # 完整路由路径，已拼上类级前缀：`@RequestMapping("/admin")` + `@GetMapping("/list")`
    # → `/admin/goods/list`。
    #
    # 为什么必须**记在单元里**而不是只用来查装配索引：真实项目的鉴权几乎全挂在
    # 前缀拦截器上（`addPathPatterns("/admin/**")` + `excludePathPatterns("/admin/login")`），
    # 判定"这条路由归不归拦截器管"只能拿完整 URL 去比，拿方法级的 "/list" 必错。
    # newbee-mall 实测：没有类级前缀时后台 20 余条路由只能靠"切片里出现了
    # /admin/** 这个字符串"间接退回 None，而 /admin/login（被 exclude 掉）也被
    # 一起当成"受保护" —— 方向错了。
    route_path: str = ""
    # own_body 存在的原因：source_code 为便于模型推理，拼进了同文件辅助方法，
    # 而"辅助方法"里会混入同类的其它路由方法。跨路由串接需要判断"当前方法
    # 自己写了什么"，用 source_code 会把它类方法的写入也算进来。
    #
    # 使用边界（踩过坑，别越界）：
    #   只给 —— taint_chain（判本方法写了哪个介质）、rule_detectors 的入口体截取。
    #   不给 —— ScenarioMatcher / SkepticReviewer 这类"读代码做判断"的推理 agent。
    #   给它们的应当是 source_code：P0-2 之后它已排除兄弟路由方法，剩下的
    #   同文件辅助方法体、跨文件实现体、框架装配证据全是必需上下文。
    #   曾让 Skeptic 改读 own_body，结果 XSS.safe 只剩 `return encode(xss);`，
    #   而 encode 的逐字符转义体在 source_code 里 —— 质检员看不见清洗逻辑，
    #   本该推翻的误报被放过。


@dataclass
class CallEdge:
    """跨文件调用边：caller -> callee。"""
    caller: str                          # 形如 "path/file.py:FuncName"
    callee: str
    callee_file: Optional[str] = None
    callee_line: Optional[int] = None


@dataclass
class VulnHypothesis:
    """第三层推理产出的漏洞假设（未经沙箱验证）。"""
    unit: CodeUnit
    vuln_type: str                       # 如 IDOR / RCE / reentrancy / unauthorized_withdraw
    scenario_hit: bool                   # GPTScan 第一步：场景匹配通过
    property_missing: str                # GPTScan 第二步：缺失的属性/校验描述
    reasoning_summary: str = ""
    confidence: float = 0.0
    skeptic_rejected: bool = False       # 反方挑刺 Agent 是否推翻
    # 多次采样时记录每一轮结论，便于事后审计模型有多犹豫。
    # 一致性（全票通过）比结论本身更能说明可信度：3 轮 2:1 的结论应当降权。
    votes: tuple[bool, ...] = ()


@dataclass
class PoCResult:
    """第四层沙箱验证结果。"""
    hypothesis: VulnHypothesis
    poc_script_path: str = ""
    verified: bool = False               # 是否成功复现
    # 沙箱到底有没有真跑过。
    # `verified=False` 有两种完全不同的含义：跑过但没复现（结论可信）、
    # 根本没跑（结论还是静态猜测）。早期只有 verified 一个字段，Web3 赛道
    # 不跑 Foundry，于是静态置信度被塞进 verified，报告里把从未执行的
    # 假设渲染成"已复现"——把猜测冒充成已验证，比漏报更危险。
    sandbox_ran: bool = True
    output_digest: str = ""              # StateParser 压缩后的关键日志摘要
    self_heal_rounds: int = 0            # 编译报错自愈轮数
    patch_diff: str = ""                 # 修复补丁 Git Diff（验证通过后生成）
