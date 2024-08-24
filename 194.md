Keen Jetblack Turtle

Medium

# The liquidation will revert if the left amount in `debt < MIN_DEBT`

## Summary
This bug was firstl discovered in the Guardian Audit report H-17:Users Can Avoid Liquidations. The sponsor have marked this issue as resolved, and have asked fellow watsons to also check if all the issues from the guardian report, that were marked as resolved, have been fully mitigated. In this case, the bug still exists.

## Vulnerability Detail
At the end of liquidation, the pool.repay() function will be called
```js
@>    pool.repay(poolId, position, amt);
    // update position to reflect repayment of debt by liquidator
    Position(payable(position)).repay(poolId, amt);
}
```
The `repay()` function however still implements the same `MIN_DEBT` check, which will lead to the exact same scenario intended to be mitigated. 

```solidity
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
---
        // revert if repaid amt is too small
        if (borrowShares == 0) revert Pool_ZeroSharesRepay(poolId, amt);

        // check that final debt amount is greater than min debt
        remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        if (remainingShares > 0) {
            uint256 newBorrowAssets = _convertToAssets(
                remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Down
            );
@>            if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
@>                revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
@>            }
        }
```

## Impact
As Mentioned in the guardian report, this issue exposes the protocol of risk the accumulation of bad debt and liquidation reverting.
Please also notice, that the likeablity of this scenario increases the more unhealthy the position, leading to profitable liquidation attempts reverting. Also noting that sentiment is a leveraged lending protocol, the risk of the accumulation of such positions is significant
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/Pool.sol#L482-L514
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L484-L500
3

## Tool used

Manual Review

## Recommendation
The simplest way to mitigate this, is to refactor the code in `repay()` to an internal `_repay()` function that recieves an extra force argument and to bypass this check if the this force value is set to true
```solidity
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        _repay(poolId,position,amt,false)
    }
```
```solidity
    function reduceDebt(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        _repay(poolId,position,amt,true)
    }
```
