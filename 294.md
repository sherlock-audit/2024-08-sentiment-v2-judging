Attractive Caramel Fox

High

# Partial liquidations are next to impossible to happen despite the code being supposed to allow them

## Summary
Partial liquidations are next to impossible to happen despite the code being supposed to allow them
## Vulnerability Detail
Upon a user becoming unhealthy, users can call `PositionManager::liquidate()` to liquidate a position and earn some profit in return. They provide `debtData` and `assetData` arrays, debt data is the debt he will repay and asset data is the collateral he is getting in return. After the liquidation, we have this check:
```solidity
if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
```
It requires that the position must be healthy. Before the liquidation, the position must be unhealthy, otherwise liquidations will be impossible, and after the liquidation the position must be healthy. For that to happen, the liquidator must make the collateral/debt ratio healthy. As it was unhealthy beforehand, this means that the liquidator must pay a larger value of debt than he is repaying collateral, otherwise there isn't really a way the position would become healthy. If he is liquidating the full position, the debt would become 0 which automatically makes the position healthy, however for partial liquidations where the debt is not becoming 0, it would have to be some edge case to turn the position from unhealthy to healthy. As no liquidator would pay more debt than the collateral he is receiving, partial liquidations will be next to impossible.

As partial liquidations are a healthy thing for the protocol to happen as not everyone can always fully liquidation a position, and the fact that partial liquidations are  __supposed__ to happen as there is no code actually disallowing that, this could pose a serious security issue and accrual of bad debt.
## Impact
Partial liquidations are next to impossible to happen despite the code being supposed to allow them
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L430-L444
## Tool used

Manual Review

## Recommendation
Consider changing the check to only revert if the health became worse