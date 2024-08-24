Glamorous Blush Gecko

High

# Liquidation fee is incorrectly calculated, leading to unprofitable liquidations

### Summary

Incorrect liquidation fee calculation makes liquidations unprofitable, leading to insolvency.

### Root Cause

During `PositionManager.liquidate()` , two things happen:

1. An amount `x` of the position’s collateral is paid to the liquidator ([link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L438))
2. The liquidator pays off the debt of the position ([link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L439))

During step 1, the liquidation fee is effectively calculated as `liquidationFee.mulDiv(x, 1e18)`

This is incorrect- the correct way would be to take the liquidation fee from the profit of the liquidator, rather than from the entire amount `x`

Due to this inaccuracy, a large majority of liquidations will be unprofitable:

### Example scenario

Consider a situation where liquidation fee is 30% (as stated in the contest README)

Say LTV = 90%, Debt value = $90, Collateral value drops from $100 to $98

Now, since the position LTV (90/98) is greater than the set LTV (90/100), the position is liquidatable

A liquidator aims to pay off the debt and receive the $98 worth of collateral, effectively buying the collateral at a discount of ~8%

However, They will only receive 70% of the $98 (due to the 30% liquidation fee), so they can only receive $68.6

This is extremely unprofitable since they have to pay off $90 worth of debt, and only receive $68.6 as a reward.

### The correct approach to calculating fee would be the following:

1. Calculate liquidator profit = Reward - Cost = $98 - $90 = $8
2. Calculate liquidator fee = feePercentage*profit = 30% of $8  = $2.4

This ensures that liquidations are still incentivised

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Liquidations are unprofitable due to liquidation fee being calculated incorrectly.

This leads to bad debt and insolvency since there is no incentive to liquidate.

### PoC

_No response_

### Mitigation

Consider calculating the profit of the liquidation first, and take the fee based on that