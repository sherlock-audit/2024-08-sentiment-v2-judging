Sparkly Taffy Fly

High

# Incorrect accounting in `reallocate` function will cause asset mismanagement for SuperPool users

### Summary

The [`reallocate` function](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L431-L454) in the `SuperPool` contract does not update the `lastTotalAssets` variable after reallocating assets, leading to discrepancies between the actual assets in the `SuperPool` and the recorded amount. This will cause asset mismanagement for SuperPool users as the function does not handle potential failures in deposits or withdrawals, leading to incorrect internal accounting.

### Root Cause

In [`protocol-v2/src/SuperPool.sol: function reallocate`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L431-L454), the `lastTotalAssets` variable is not updated after reallocating assets.


### Internal pre-conditions

1. Allocator or owner needs to call `reallocate` to move assets between underlying pools.
2. The `lastTotalAssets` variable is not updated after reallocations.


### External pre-conditions

None.

### Attack Path

1. Allocator or owner calls `reallocate` to withdraw assets from one pool and deposit them into another.
2. The `reallocate` function performs the withdrawals and deposits but does not update `lastTotalAssets`.
3. Even if all withdrawals and deposits succeed, the `lastTotalAssets` variable remains outdated.
4. The internal accounting of the `SuperPool` becomes incorrect, leading to potential asset mismanagement.


### Impact

The SuperPool users suffer from incorrect asset accounting, leading to potential asset mismanagement. The protocol may overcharge or undercharge fees, and users may receive incorrect amounts of shares or assets.


### PoC

1. Allocator calls `reallocate` with parameters to withdraw assets from Pool A and deposit them into Pool B.
2. The `reallocate` function performs the withdrawals and deposits but does not update `lastTotalAssets`.
3. Even if the deposit to Pool B succeeds, the `lastTotalAssets` variable remains outdated.
4. The `lastTotalAssets` variable remains outdated, leading to incorrect internal accounting.


### Mitigation

To fix this issue, the `reallocate` function should update the `lastTotalAssets` variable after reallocating assets. Additionally, the function should handle potential failures in deposits or withdrawals and emit events to track reallocations.

```diff
function reallocate(ReallocateParams[] calldata withdraws, ReallocateParams[] calldata deposits) external {
    if (!isAllocator[msg.sender] && msg.sender != Ownable.owner()) {
        revert SuperPool_OnlyAllocatorOrOwner(address(this), msg.sender);
    }

    uint256 totalWithdrawn;
    uint256 totalDeposited;

    uint256 withdrawsLength = withdraws.length;
    for (uint256 i; i < withdrawsLength; ++i) {
        if (poolCapFor[withdraws[i].poolId] == 0) revert SuperPool_PoolNotInQueue(withdraws[i].poolId);
        uint256 withdrawn = POOL.withdraw(withdraws[i].poolId, withdraws[i].assets, address(this), address(this));
        totalWithdrawn += withdrawn;
    }

    uint256 depositsLength = deposits.length;
    for (uint256 i; i < depositsLength; ++i) {
        uint256 poolCap = poolCapFor[deposits[i].poolId];
        if (poolCap == 0) revert SuperPool_PoolNotInQueue(deposits[i].poolId);
        uint256 assetsInPool = POOL.getAssetsOf(deposits[i].poolId, address(this));
        if (assetsInPool + deposits[i].assets <= poolCap) {
            ASSET.approve(address(POOL), deposits[i].assets);
            uint256 deposited = POOL.deposit(deposits[i].poolId, deposits[i].assets, address(this));
            totalDeposited += deposited;
        }
    }

+   // Update lastTotalAssets
+   lastTotalAssets = totalAssets();

+   // Emit events for tracking
+   emit ReallocationCompleted(totalWithdrawn, totalDeposited);
}
```
