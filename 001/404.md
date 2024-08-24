Acidic Heather Goldfish

High

# Efficient Handling of Internal Pool Cap in `_supplyToPools` Function to Prevent Reverts and Optimize Asset Management

## Summary

The `_supplyToPools` function in the `SuperPool` contract attempts to deposit a specified amount of assets into multiple underlying pools. Each underlying pool has an internal cap(not SuperPool's), and if a deposit attempt would exceed this cap, the function reverts. This behavior can lead to inefficiencies and leave assets undeposited.

## Vulnerability Detail

When attempting to deposit assets into an underlying pool using the `POOL.deposit` function, the operation may revert if adding the assets would exceed the pool's internal cap (`pool.poolCap`). This can prevent the `_supplyToPools` function from successfully depositing the intended amount of assets, which might leave the `SuperPool` contract with residual assets that were meant to be deposited.

The current implementation does not handle scenarios where deposits partially fulfill the requested amount without exceeding the pool's internal cap. This can lead to unnecessary reverts and inefficient asset management.

## Impact

- **Inefficient Asset Management**: The inability to deposit the intended amount due to reverts can cause assets to remain undeposited, which impacts the efficiency of the asset allocation strategy.
- **Partial Deposits Not Handled**: The current implementation does not effectively handle partial deposits when the pool cap is reached, leading to potential underutilization of available pool capacity.
- **User Experience**: Users may experience unexpected failures and delayed asset allocation due to reverts, impacting trust and satisfaction with the protocol.

## Code Snippet

### Current `_supplyToPools` Function
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L524-L543
```solidity
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
@>            try POOL.deposit(poolId, supplyAmt, address(this)) {
                assets -= supplyAmt;
            } catch { }

            if (assets == 0) return;
        }
    }
}
```

#### Pool's `deposit` Function
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L309-L331
```solidity
function deposit(uint256 poolId, uint256 assets, address receiver) public returns (uint256 shares) {
    PoolData storage pool = poolDataFor[poolId];

    if (pool.isPaused) revert Pool_PoolPaused(poolId);

    // update state to accrue interest since the last time accrue() was called
    accrue(pool, poolId);

    // Need to transfer before or ERC777s could reenter, or bypass the pool cap
    IERC20(pool.asset).safeTransferFrom(msg.sender, address(this), assets);

@>    if (pool.totalDepositAssets + assets > pool.poolCap) revert Pool_PoolCapExceeded(poolId);

    shares = _convertToShares(assets, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Down);
    if (shares == 0) revert Pool_ZeroSharesDeposit(poolId, assets);

    pool.totalDepositAssets += assets;
    pool.totalDepositShares += shares;

    _mint(receiver, poolId, shares);

    emit Deposit(msg.sender, receiver, assets, shares);
}
```

## Tool Used

Manual Review

## Recommendation

Adjust the `_supplyToPools` function to handle deposits in a way that respects the internal pool caps and prevents reverts due to exceeding these caps. Here's an updated version of the `_supplyToPools` function that achieves this:

```diff
function _supplyToPools(uint256 assets) internal {
    uint256 depositQueueLength = depositQueue.length;
    for (uint256 i; i < depositQueueLength; ++i) {
        uint256 poolId = depositQueue[i];
        uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));
+        uint256 poolCap = POOL.getCapOf(poolId); // Assuming there's a method to get the pool cap
+        uint256 totalAssetsInPool = POOL.getTotalAssets(poolId);

        if (assetsInPool < poolCapFor[poolId]) {
            uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
            if (assets < supplyAmt) supplyAmt = assets;
+            uint256 availableAmt = poolCap - totalAssetsInPool;
+            if (availableAmt < supplyAmt) supplyAmt = availableAmt;
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