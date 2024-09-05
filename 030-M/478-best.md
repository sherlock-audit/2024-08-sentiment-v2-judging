Stale Cyan Fish

High

# No lender compensation on liquidating bad debt

### Summary

The current bad debt liquidation method will cause lenders to loose alot or even all their deposits in extreme cases without compensation.

### Root Cause

In the `Pool::rebalanceBadDebt` method 

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L547
```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        PoolData storage pool = poolDataFor[poolId];
        accrue(pool, poolId);

        // revert if the caller is not the position manager
        if (msg.sender != positionManager) revert Pool_OnlyPositionManager(poolId, msg.sender);

        // compute pool and position debt in shares and assets
        uint256 totalBorrowShares = pool.totalBorrowShares;
        uint256 totalBorrowAssets = pool.totalBorrowAssets;
        uint256 borrowShares = borrowSharesOf[poolId][position];
        // [ROUND] round up against lenders
        uint256 borrowAssets = _convertToAssets(borrowShares, totalBorrowAssets, totalBorrowShares, Math.Rounding.Up);

        // rebalance bad debt across lenders
        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
->      pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
    }
```

The bad debt is removed from the totalDepositAssets , meaning that lenders will suffer a loss of the whole debt.

Example
- pool has 100 assets
- Alice borrows all 100 assets
- Alice forfeits repayment,and she now has a bad debt of 100 assets
- pool lenders will also suffer a loss of 100 assets (the entire assets in the pool), the seized collateral form the bad debt liquidation is not used to compensate the lenders.


### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

significant losses for pool lenders when liquidating bad debt


### PoC

_No response_

### Mitigation

Seized collateral should be used to compensate pool lenders to reduce losses.