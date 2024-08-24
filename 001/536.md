Damaged Malachite Gibbon

Medium

# The `SuperPool._supplyToPools()` function only considers the state variable `poolCapFor` for the `SuperPool`'s `poolId`s, not the `poolCap` for the `Pool`'s `poolId`s

## Summary

In the `SuperPool._supplyToPools()` function, the deposit amount for each individual poolId is calculated as `supplyAmt = poolCapFor[poolId] - assetsInPool`. However, it does not check whether this `supplyAmt` exceeds the `poolCap` of the `poolId` in the `Pool` contract. If it does cause an overflow of the `poolCap`, the deposit to that `poolId` fails, and the flow moves on to the next `poolId`. Even if the previous `poolId` could accommodate some assets, the deposit flow skips it. This could lead to a suboptimal reordering of the `depositQueue`.

## Vulnerability Detail

Let's consider the following scenario:

1. The `SuperPool` has two `poolId`s in its `depositQueue`:
    - The first `poolId` has already received a significant amount of assets, leaving only $100 in deposit space due to its `poolCap`.
    - For the same reason, $200 in deposit space remains in the second `poolId`.
2. Alice deposits $200 into the `SuperPool`. The `_supplyToPools()` function is then invoked to allocate Alice's $200 to the two `poolId`s:
    - The `SuperPool` first attempts to deposit $200 into the first `poolId`, but this fails because the first `poolId` can only accommodate $100.
    - The `SuperPool` then tries to deposit the full $200 into the second `poolId`, which succeeds as it has enough capacity.

In fact, a more appropriate allocation would be to deposit $100 into the first `poolId` and $100 into the second `poolId`. The above scenario could lead to a suboptimal reordering of the `depositQueue`.

Additionally, in the worst-case scenario, if Alice deposits $300, no amount will be deposited into the base pools, as neither `poolId` can accommodate the full $300.

```solidity
    function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));

            if (assetsInPool < poolCapFor[poolId]) {
531             uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;
                ASSET.forceApprove(address(POOL), supplyAmt);

                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }

                if (assets == 0) return;
            }
        }
    }
```

## Impact

The current deposit mechanism may result in a suboptimal reordering of the `depositQueue`.

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L524-L543

## Tool used

Manual Review

## Recommendation

Ensure that the `supplyAmt` does not cause an overflow of the `poolCap` for the `poolId` in the `Pool` contract.

```diff
    function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));

            if (assetsInPool < poolCapFor[poolId]) {
                uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;

+               uint256 availabeAmt = POOL.poolDataFor[poolId].poolCap - POOL.getTotalAssets(poolId);
+               if (availabeAmt < supplyAmt) supplyAmt = availabeAmt;

                ASSET.forceApprove(address(POOL), supplyAmt);

                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }

                if (assets == 0) return;
            }
        }
    }
```