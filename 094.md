Large Misty Snake

Medium

# Borrower will be unfairly liquidated due to `isKnownAsset` obstruction in deposits for collateral

## Summary
User notices that a position of his may become unhealthy and try to deposit collateral assets through the position manager's `process` function, the same collateral they may have used to interact with the protocol before, only to find his transaction reverted and his position swiftly liquidated by bots because it became unhealthy due to price fluctuations.

## Vulnerability Detail
1. `alice` creates a `position` and borrows, with a knownAsset `A`
2. PositionManager `owner` calls `toggleKnownAsset` for asset `A`, this makes sure Asset `A` is no longer accepted by protocol for deposits
3. `alice` attempts to prevent Liquidation of position by adding collateral `A` via `deposit` before her position becomes unhealthy and liquidated due to market conditions
4. `asset` is not accepted and position get's swiftly liquidated by bots before she get's the chance  to retry the transaction.

users should be able to affect the health of their position and save positions how they can.

## Impact
Unfair Liquidation of users for issues they may not be aware of that caused an asset to no longer be accepted for collateral deposits. 

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L325-L335

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L521-L525

## Tool used
Manual Review

## Recommendation
since assets are specifically vetted before adding `oracles` for them(to become `known`), `isKnownAsset` will cause complications,
toggleKnownAssets should have extra checks or a time gap before borrowers are unfairly liquidated.