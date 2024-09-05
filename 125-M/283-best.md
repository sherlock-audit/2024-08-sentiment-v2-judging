Attractive Caramel Fox

Medium

# The implementation of how the discount is being applied upon the seized assets could cause liquidators to get less assets than expected

## Summary
The implementation of how the discount is being applied upon the seized assets could cause liquidators to get less assets than expected
## Vulnerability Detail
Upon liquidations, the liquidator can seize more assets than what he has paid for due to a discount being applied:
```solidity
        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
        if (assetSeizedValue > maxSeizedAssetValue) {
            revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
        }
```
The issue here is that the discount is not actually being "applied". It only checks whether the `assetSeizedValue` is at most the discounted debt. However, if the user has provided a lower value of assets to seize, he will only take that lower amount. In a way, if the user doesn't actually "ask" for the discount, he will not receive it. While every user would provide an amount of assets to seize such that they would be the maximum allowed, the issue is that a price oracle is used to calculate those values in ETH. At the time of the liquidator putting his transaction, the prices might be different than the price at the transaction execution, thus it is not possible to accurately determine how much assets he can seize and the discount might not be taken into account at all or only a fraction of the whole discount could be used up. Since the prices always move up or down, almost no user would actually be able to use up exactly `discount` amount of discount but some would be able to use just half, some 90% of the discount, some even 0 and some might even overpay.

Furthermore, there is no type of slippage to protect the user against that happening. The function can also revert in cases where the assets to seize he has provided become larger than the maximum allowed.
## Impact
The implementation of how the discount is being applied upon the seized assets could cause liquidators to get less assets than expected
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L129-L160
## Tool used

Manual Review

## Recommendation
Make it so the user always takes the maximum seized value instead of taking just the amount specified