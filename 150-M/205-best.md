Sparkly Taffy Fly

High

# Lenders can deposit into full SuperPools, reducing yield for all lenders

### Summary

A missing revert statement in the [`_supplyToPools` function ](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L524-L543)will cause a reduction in yield for all lenders as new lenders can deposit into a full SuperPool and mint shares without corresponding asset allocation.

### Root Cause

In [`SuperPool.sol: _supplyToPools`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L524-L543) the function does not revert if all pool caps are reached and it is impossible to supply funds to any pool.


### Internal pre-conditions

1. The SuperPool must have all its underlying pools at their maximum cap.
2. A lender attempts to deposit assets into the Pool.


### External pre-conditions

None

### Attack Path

1. All underlying pools in the Pool reach their maximum cap.
2. A lender calls the `deposit` function on the SuperPool.
3. The `_supplyToPools` function attempts to allocate the assets but fails to do so as all pools are full.
4. The function does not revert, allowing the transaction to succeed.
5. The lender receives shares of the SuperPool without corresponding asset allocation.
6. The yield per share for all lenders is reduced as the new shares dilute the yield.


### Impact

The lenders suffer a reduction in yield as new lenders can deposit into a full SuperPool and mint shares without corresponding asset allocation. This reduces the overall APY for all lenders.


### PoC

1. Assume the SuperPool has three underlying pools, each with a cap of 1000 USDC.
2. All three pools have reached their cap of 1000 USDC.
3. A new lender attempts to deposit 500 USDC into the SuperPool.
4. The `_supplyToPools` function is called but cannot allocate the 500 USDC to any pool as all are full.
5. The function does not revert, and the lender receives shares of the Pool.
6. The yield per share for all lenders is reduced as the new shares dilute the yield.


### Mitigation

Add a revert statement at the end of the `_supplyToPools` function to ensure the transaction fails if assets cannot be allocated.

```diff
function _supplyToPools(uint256 assets) internal {
    uint256 depositQueueLength = depositQueue.length;
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
            } catch { }

            if (assets == 0) return;
        }
    }

+   // Revert if there are remaining assets that could not be allocated
+   if (assets > 0) {
+       revert Pool_PoolCapReached();
+   }
}
```