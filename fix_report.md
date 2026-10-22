# Solidity CEI 补丁（状态清零行移到外部调用之前）

## [sol-reentrancy] withdraw（`Bank.sol`）
```diff
--- a/Bank.sol
+++ b/Bank.sol
@@ -2,8 +2,8 @@
 contract Bank {
     mapping(address => uint) balances;
     function withdraw(uint amt) public {
+            balances[msg.sender] -= amt;
         if(msg.sender.call.value(amt)()) {
-            balances[msg.sender] -= amt;
         }
     }
 }
```

> 自检通过：重切片 + 重跑 reentrancy 规则 → False（CEI 正序）。
> 注意：若扣减可能 revert（余额不足），先扣减后转账的顺序
> 同时改变了失败语义 —— 需人工确认回滚路径。

