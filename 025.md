Genuine Lemonade Gerbil

Medium

# When bad debt arising, user may fail to repay position's all debt.

## Summary
When a user wants to repay position's all debt, he calls `PositionManager.repay()` by passing `type(uint256).max` as the repayment amount.
`PositionManager.repay()` function first calculates the repayment amount from positions's debt shares using round-up and then calls `Pool.repay()` function by passing repayment amount.
`Pool.repay()` function calculates again shares from repayment amount using round-down.
In the case that the calculated shares are larger than position's debt shares, `Pool.repay()` function will be reverted.

## Vulnerability Detail
`PositionManager.repay()` function is following.
```solidity
    function repay(address position, bytes calldata data) internal {
        // data -> abi.encodePacked(uint256, uint256)
        // poolId -> [0:32] pool that recieves the repaid debt
        // amt -> [32: 64] notional amount to be repaid
        uint256 poolId = uint256(bytes32(data[0:32]));
        uint256 amt = uint256(bytes32(data[32:64]));

        // if the passed amt is type(uint).max assume repayment of the entire debt
369:    if (amt == type(uint256).max) amt = pool.getBorrowsOf(poolId, position);

        // transfer assets to be repaid from the position to the given pool
        Position(payable(position)).transfer(address(pool), pool.getPoolAssetFor(poolId), amt);

        // trigger pool repayment which assumes successful transfer of repaid assets
375:    pool.repay(poolId, position, amt);

        // signals repayment to the position and removes the debt pool if completely paid off
        // any checks needed to validate repayment must be implemented in the position
        Position(payable(position)).repay(poolId, amt);
        emit Repay(position, msg.sender, poolId, amt);
    }
```
`PositionManager.repay()` function calls `Pool.getBorrowsOf()` function in `L369` to calculate repayment assets when `amt == type(uint256).max`. `Pool.getBorrowsOf()` function is following.
```solidity
    function getBorrowsOf(uint256 poolId, address position) public view returns (uint256) {
        PoolData storage pool = poolDataFor[poolId];
        (uint256 accruedInterest,) = simulateAccrue(pool);
        // [ROUND] round up to enable enable complete debt repayment
234:    return _convertToAssets(
            borrowSharesOf[poolId][position],
            pool.totalBorrowAssets + accruedInterest,
            pool.totalBorrowShares,
            Math.Rounding.Up
        );
    }
```
As can be seen, the above function rounds up the repayment assets when converting position's debt shares to repayment assets. And then `PositionManager.repay()` function calls the following `Pool.repay()` function by passing repayment assets in `L375`. 
```solidity
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        --- SKIP ---
500:    uint256 borrowShares = _convertToShares(amt, pool.totalBorrowAssets, pool.totalBorrowShares, Math.Rounding.Down);

        // revert if repaid amt is too small
        if (borrowShares == 0) revert Pool_ZeroSharesRepay(poolId, amt);

        // check that final debt amount is greater than min debt
506:    remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        --- SKIP ---
    }
```
As can be seen, the above function rounds down the `borrowShares` in `L500` when converting repayment assets to shares and then subtract it from the position's debt in `L506`.

Scenario:
1. Assume that pool's total borrow shares is `10` and pool's total borrow assets is `7`.
2. Assume that positions's debt shares is `6`.
3. Then position's repayment assets is calculated as `ceil(6 * 7 / 10) = 5` in `L234` of `Pool.getBorrowsOf()` function.
4. Positions's repayment shares (`borrowShares`) is calculated as `floor(5 * 10 / 7) = 7` in `L500` of `Pool.repay()` function.
5. Therefore `Pool.repay()` function will revert in `L506` because `borrowSharesOf[poolId][position] = 6` is less than `borrowShares = 7`.

Note:
The above scenario is available when pool's total borrow shares is larger than pool's total borrow assets.
Such case can be arised when there is bad debt in the pool due to the falling of collateral price and so admin calls `Pool.rebalanceBadDebt()` function.

## Impact
When bad debt arising, user may fail to repay position's all debt.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L361-L381

## Tool used

Manual Review

## Recommendation
Add `repayShares()` function to the `Pool.sol` which repay debt by passing shares instead of assets.
And then calls `repayShares()` instead of `repay()` in the `PositionManager.repay()` function.
