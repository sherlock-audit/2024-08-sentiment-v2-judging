Damaged Malachite Gibbon

Medium

# Rounding Error in Calculating `newBorrowAssets` during borrow/repayment

## Summary
During the borrow/repayment operation in the pool, a rounding error arises when calculating `newBorrowAssets`, causing it to mismatch with the amount returned by `getBorrowsOf`, which I believe should align.

## Vulnerability Detail
`newBorrowAssets` is meant to indicate the entire debt associated with a position, capturing the total amount of assets required to fully repay the debt obligation.
I believe it should match the value given by getBorrowsOf, assuming that a repayment could occur immediately without any interest having accrued. Nevertheless, due to differences in the rounding directions used in these calculations, inconsistencies can occur.

As a consequence, even a small discrepancy might lead to `newBorrowAssets` falling below `minDebt`, which in turn can trigger the transaction to revert with the `Pool_DebtTooLow` error.

In `borrow` function, it used Math.Rounding.Down:
```solidity
    function borrow(uint256 poolId, address position, uint256 amt) external returns (uint256 borrowShares) {
        ...
        uint256 newBorrowAssets = _convertToAssets(
            borrowSharesOf[poolId][position] + borrowShares,
            pool.totalBorrowAssets + amt,
            pool.totalBorrowShares + borrowShares,
>           Math.Rounding.Down
        );
        if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
            revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
        }
```
In `getBorrowsOf` function, it used Math.Rounding.Up:
```solidity
    function getBorrowsOf(uint256 poolId, address position) public view returns (uint256) {
        PoolData storage pool = poolDataFor[poolId];
        (uint256 accruedInterest,) = simulateAccrue(pool);
        // [ROUND] round up to enable enable complete debt repayment
        return _convertToAssets(
            borrowSharesOf[poolId][position],
            pool.totalBorrowAssets + accruedInterest,
            pool.totalBorrowShares,
>            Math.Rounding.Up
        );
    }
```

Same happens in `repay` function:
```solidity
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        ...
        remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        if (remainingShares > 0) {
            uint256 newBorrowAssets = _convertToAssets(
>               remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Down
            );
            if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
                revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
            }
        }
```

## Impact
This represents a notable instance of a `rounding error`, and although it is not a frequent occurrence, it can cause borrow or repay operations to unjustly revert with the `Pool_DebtTooLow` error.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L450

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L238

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L509

## Tool used
Manual Review

## Recommendation
Adjust the rounding method to `Math.Rounding.Up` when calculating `newBorrowAssets`.

In `borrow` function:
```diff
    function borrow(uint256 poolId, address position, uint256 amt) external returns (uint256 borrowShares) {
        ...
        uint256 newBorrowAssets = _convertToAssets(
            borrowSharesOf[poolId][position] + borrowShares,
            pool.totalBorrowAssets + amt,
            pool.totalBorrowShares + borrowShares,
-           Math.Rounding.Down
+           Math.Rounding.Up
        );
        if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
            revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
        }
```

In `repay` function:
```diff
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        ...
        remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        if (remainingShares > 0) {
            uint256 newBorrowAssets = _convertToAssets(
-               remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Down
+               remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Up
            );
            if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
                revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
            }
        }
```