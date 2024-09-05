Sparkly Taffy Fly

High

# Rounding Errors will Prevent Full Debt Repayment for Users

### Summary

Rounding down in the [`repay` function](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L482-L527) will cause an inability to fully repay debt for users as the function will leave a small amount of debt due to rounding down borrow shares.

### Root Cause

In [`protocol-v2/src/Pool.sol::repay`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L482-L527) the function rounds down the borrow shares to burn, which can leave a small amount of debt.

### Internal pre-conditions

1. User needs to have an outstanding debt in the pool.
2. User needs to call the `repay` function with an amount intended to fully repay the debt.


### External pre-conditions

None.

### Attack Path

1. User calls `getBorrowsOf` to determine the total debt.
2. User calls `repay` with the amount returned by `getBorrowsOf`.
3. The `repay` function rounds down the borrow shares to burn, leaving a small amount of debt.
4. User is unable to fully repay the debt due to the remaining borrow shares.


### Impact

The users cannot fully repay their debt, which can cause issues with the minimum debt requirement and prevent the removal of the debt pool from the user's debtPools array.

### PoC

1. User has a debt of 100.5 units in the pool.
2. User calls `getBorrowsOf` and gets a debt amount of 100.5 units.
3. User calls `repay` with 100.5 units.
4. The `repay` function rounds down the borrow shares, leaving 0.5 units of debt.
5. User is unable to fully repay the debt, causing issues with the minimum debt requirement.


### Mitigation

To fix the issue, the `repay` function should round up the borrow shares to burn when the user is repaying the entire debt.

### Code Fix:
```diff
function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
    PoolData storage pool = poolDataFor[poolId];

    // ... existing code ...

    // compute borrow shares equivalent to notional asset amt
-   uint256 borrowShares = _convertToShares(amt, pool.totalBorrowAssets, pool.totalBorrowShares, Math.Rounding.Down);
+   uint256 borrowShares = _convertToShares(amt, pool.totalBorrowAssets, pool.totalBorrowShares, Math.Rounding.Up);

    // ... existing code ...
}
```

This change ensures that the `repay` function rounds up the borrow shares to burn, preventing the issue of leaving a small amount of debt due to rounding down. This will allow users to fully repay their debt without leaving any residual borrow shares.