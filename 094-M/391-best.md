Soaring Topaz Tuna

Medium

# No incentive to liquidate

## Summary

According to the README:

* The `LiquidationFee` could be as high as 30%.

* `LTV` ranges between 10% and 98%.

These two points combined may create scenarios where liquidating positions is not profitable.

## Vulnerability Detail

Since the `LiquidationFee` is shared among all positions and `LTV` is configurable by the pool owner, if the owner allows high LTV combined with a protocol-level LiquidationFee of up to 30%, it could **remove all incentives** for liquidating positions.

## Impact

This could result in the protocol accumulating bad debt positions, leading to losses for the protocol.

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L272

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L476

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L190-L210

## Tool used

Manual Review

## Recommendation

Reduce the LiquidationFee expectations or adjust the LTV threshold to prevent unprofitable liquidation scenarios.