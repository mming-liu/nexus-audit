"""统一数据契约：CodeUnit, CallEdge, VulnHypothesis, PoCResult"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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
    # own_body 存在的原因：source_code 为便于模型推理，拼进了同文件辅助方法，
    # 而"辅助方法"里会混入同类的其它路由方法。跨路由串接需要判断"当前方法
    # 自己写了什么"，用 source_code 会把它类方法的写入也算进来。


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
