Attractive Caramel Fox

Medium

# No slippage protection upon liquidations

## Summary
No slippage protection upon liquidations
## Vulnerability Detail
Users can call `PositionManager::liquidate()` to liquidate a position that is not healthy. However, there is not any protection from slippage. Something that makes this issue even more significant is the 2 function inputs - `debtData` and `assetData`. The debt data is the debt that the liquidator will repay and the asset data is the collateral he will receive in return. As these 2 inputs are not sufficiently validated, they can be completely out of sync in terms of their current ETH value. The only check regarding them is whether the user is taking more collateral than possible based on the debt he is repaying but there isn't check for the vice versa scenario.

This makes it so that due to price changes between the user calling the function and the function actually being executed, he can take a much lower collateral value than the debt he is repaying causing a significant loss for him, even potentially liquidating a bad debt position.
## Impact
No slippage protection upon liquidations
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L430-L444
## Tool used

Manual Review

## Recommendation
Have some type of slippage protection