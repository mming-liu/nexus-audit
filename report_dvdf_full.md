# nexus-audit 扫描报告

- 目标仓库：`C:\myFloders\git\nexus-audit\reference_repos\damn-vulnerable-defi-master`
- 初筛漏洞假设：5
- 沙箱验证确认：0
- 静态高危候选（未跑沙箱）：2（本赛道未执行 make test / forge test，需人工或 CI 复核）

## [PRECISION_LOSS] getAmountIn
- 位置：`C:\myFloders\git\nexus-audit\reference_repos\damn-vulnerable-defi-master\src\puppet-v2\UniswapV2Library.sol:70`
- 状态：⚠ 静态低置信度候选（未验证）
- 缺失校验：`reserveOut - amountOut * 997` 未加括号，实际求值为 `reserveOut - (amountOut * 997)`；需人工确认用途
- 分析：UniswapV2Library 风格减乘混排 @ 文件第 78 行
- 沙箱摘要：static: 未执行 forge test，仅静态推断
- PoC 脚本：``
- 自愈轮数：0

## [REENTRANCY_SURFACE] flashLoan
- 位置：`C:\myFloders\git\nexus-audit\reference_repos\damn-vulnerable-defi-master\src\side-entrance\SideEntranceLenderPool.sol:35`
- 状态：⚠ 静态低置信度候选（未验证）
- 缺失校验：外部调用目标为 msg.sender 且无重入锁；回调期间可通过 deposit 记账绕过余额差校验
- 分析：flashLoan 内 msg.sender 外部调用 @ 函数级检测
- 沙箱摘要：static: 未执行 forge test，仅静态推断
- PoC 脚本：``
- 自愈轮数：0

## [ARBITRARY_EXTERNAL_CALL] execute
- 位置：`C:\myFloders\git\nexus-audit\reference_repos\damn-vulnerable-defi-master\src\abi-smuggling\AuthorizedExecutor.sol:46`
- 状态：⚠ 静态高危候选（待 forge 验证）
- 缺失校验：外部调用目标 (target) 与 calldata (actionData) 均为调用方参数，且还款仅靠余额差校验——可借 approve 劫持代币
- 分析：target.functionCall(data) gadget @ execute
- 沙箱摘要：static: 未执行 forge test，仅静态推断
- PoC 脚本：``
- 自愈轮数：0

## [ARBITRARY_EXTERNAL_CALL] flashLoan
- 位置：`C:\myFloders\git\nexus-audit\reference_repos\damn-vulnerable-defi-master\src\truster\TrusterLenderPool.sol:20`
- 状态：⚠ 静态高危候选（待 forge 验证）
- 缺失校验：外部调用目标 (target) 与 calldata (data) 均为调用方参数，且还款仅靠余额差校验——可借 approve 劫持代币
- 分析：target.functionCall(data) gadget @ flashLoan
- 沙箱摘要：static: 未执行 forge test，仅静态推断
- PoC 脚本：``
- 自愈轮数：0

## [MISSING_PAYABLE_RECEIVER] flashLoan
- 位置：`C:\myFloders\git\nexus-audit\reference_repos\damn-vulnerable-defi-master\src\side-entrance\SideEntranceLenderPool.sol:35`
- 状态：⚠ 静态低置信度候选（未验证）
- 缺失校验：非 payable 函数中读取 address(this).balance，但合约未定义 receive()/fallback——外部无法直接向合约注资，只能靠 payable 入口内转（可能正是重入面）
- 分析：issue #104 同型缺陷 @ SideEntranceLenderPool.sol
- 沙箱摘要：static: 未执行 forge test，仅静态推断
- PoC 脚本：``
- 自愈轮数：0
