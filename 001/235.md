Sparkly Taffy Fly

High

# Incorrect asset accounting can lead to asset mismanagement for SuperPool users

### Summary

Incorrect asset accounting in the [`_deposit` function](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L497-L506) will cause asset mismanagement for SuperPool users as the contract will assume all assets are successfully deposited into underlying pools, leading to discrepancies in total asset accounting.


### Root Cause

In [`SuperPool.sol: _deposit`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L497-L506) the function assumes all assets are successfully deposited into underlying pools and updates `lastTotalAssets` by the full amount of the deposit, even if some deposits fail.

### Internal pre-conditions

1. A user needs to call the `deposit` function to deposit assets into the SuperPool.
2. The underlying pool(s) need to have conditions that cause the deposit to fail (e.g., for any reason).


### External pre-conditions

None.

### Attack Path

1. User calls the `deposit` function with a certain amount of assets.
2. The `_deposit` function calls `_supplyToPools` to distribute the assets across the underlying pools.
3. One or more underlying pools fail to accept the deposit due to conditions like anything.
4. The `try-catch` block in `_supplyToPools` catches the exception and moves to the next pool without updating the accounting.
5. The `_deposit` function updates `lastTotalAssets` by the full amount of the deposit, assuming all assets were successfully deposited.

### Impact

The SuperPool users suffer from incorrect calculations of shares, fees, and other critical metrics due to the discrepancy between the actual assets held by the SuperPool and the recorded total assets. This can result in assets being stolen, lost, or compromised directly.


### PoC

1. A user deposits 1000 assets into the SuperPool.
2. The `_deposit` function calls `_supplyToPools` to distribute the assets across the underlying pools.
3. The first pool in the queue fails to accept the deposit due to any reason (fails to deposit).
4. The `try-catch` block in `_supplyToPools` catches the exception and moves to the next pool.
5. The `_deposit` function updates `lastTotalAssets` by 1000, assuming all assets were successfully deposited.
6. The actual assets held by the SuperPool are less than `lastTotalAssets`, leading to a discrepancy in accounting.


### Mitigation

## Mitigation
To fix this issue, the `_deposit` function should only update `lastTotalAssets` by the actual amount of assets successfully deposited into the underlying pools. Here is the suggested modification:

```diff
function _deposit(address receiver, uint256 assets, uint256 shares) internal {
    // ... (other checks and operations)
-   _supplyToPools(assets);
-   lastTotalAssets += assets;
+   uint256 actualDeposited = _supplyToPools(assets);
+   lastTotalAssets += actualDeposited;
    emit Deposit(msg.sender, receiver, actualDeposited, shares);
}

// return totalDeposited
function _supplyToPools(uint256 assets) internal returns (uint256) {
    uint256 depositQueueLength = depositQueue.length;
    uint256 totalDeposited = 0;
    for (uint256 i; i < depositQueueLength; ++i) {
        uint256 poolId = depositQueue[i];
        uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));

        if (assetsInPool < poolCapFor[poolId]) {
            uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
            if (assets < supplyAmt) supplyAmt = assets;
            ASSET.forceApprove(address(POOL), supplyAmt);

            // skip and move to the next pool in queue if deposit reverts
            try POOL.deposit(poolId, supplyAmt, address(this)) {
                assets -= supplyAmt;
                totalDeposited += supplyAmt;
            } catch { }

            if (assets == 0) return totalDeposited;
        }
    }
    return totalDeposited;
}
```