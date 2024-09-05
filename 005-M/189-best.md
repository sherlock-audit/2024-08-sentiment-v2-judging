Keen Jetblack Turtle

High

# Incorrect Fee Calculation Leads to Potential Liquidator Losses and Protocol Instability

## Summary

The Sentiment protocol's `PositionManager` contract has a logical flaw in its liquidation fee calculation. The fee is applied to the entire seized asset amount instead of just the liquidation bonus, making liquidations unprofitable when the protocol fee exceeds ~9.091%. This undermines the economic incentives for liquidators, risking the accumulation of bad debt and the protocol's financial stability. The issue stems from the `_transferAssetsToLiquidator` function and conflicts with the protocol's intention of incentivizing liquidations.


## Vulnerability Detail


The Sentiment protocol implements a liquidation mechanism in the `PositionManager` contract to handle underwater positions. This mechanism is designed to incentivize liquidators to repay the debt of unhealthy positions in exchange for a portion of the position's collateral. According to the [readme](https://github.com/sherlock-audit/2024-08-sentiment-v2/tree/main?tab=readme-ov-file#q-are-there-any-limitations-on-values-set-by-admins-or-other-roles-in-the-codebase-including-restrictions-on-array-lengths), the liquidation bonus is `10%` and liquidation fee (protocol fees) can be set between `0%` and `30%`.

- The issue lies in the [_transferAssetsToLiquidator](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L476) function within the `PositionManager` contract. The function calculates the protocol fee based on *the entire seized asset amount*, rather than just the liquidation bonus. This calculation method lead to situations where liquidations become unprofitable for liquidators, undermining the economic incentives designed to maintain the protocol's health and lead to bad debts.
```js

    function _transferAssetsToLiquidator(address position, AssetData[] calldata assetData) internal {
        uint256 assetDataLength = assetData.length;
        for (uint256 i; i < assetDataLength; ++i) {
            if (Position(payable(position)).hasAsset(assetData[i].asset) == false) revert PositionManager_SeizeInvalidAsset(position, assetData[i].asset);
      >>    uint256 fee = liquidationFee.mulDiv(assetData[i].amt, 1e18);
      >>    Position(payable(position)).transfer(owner(), assetData[i].asset, fee);
            Position(payable(position)).transfer(msg.sender, assetData[i].asset, assetData[i].amt - fee);
        }
    }
```
- Mathematically, we can analyze when liquidations become unprofitable:

Let:
- **D** = Debt value
- **L** = Liquidation discount (10% or 0.1)
- **F** = Fee percentage (0% to 30% or 0 to 0.3)

For a liquidation to be profitable:
```math
D * (1 + L) - F * D * (1 + L) > D
```
Simplifying:
```math
(1 + L) * (1 - F) > 1
```
Given **L = 0.1**, we can solve for **F**:
```math
1.1 * (1 - F) > 1 \\
F < 1 - (1 / 1.1) \\
F < 0.0909  \\ or approximately \ 9.09\%
```

- This analysis shows that with the current `10%` liquidation discount, any fee percentage above `9.09%` will make all liquidations unprofitable. At exactly `9.091%`, liquidations break even.

> notice that we are assuming that liquidators will always take 10% discount , which is not always the case , in case of lower discount , liquidation will be  unprofitable at fee lower than 9.091% 

***Example:***
Consider a liquidation scenario where:
- Debt to be repaid: `10,000 USD`
- Liquidation discount: `10%`
- Protocol fee: `20%`

The liquidator repays `10,000$` of debt and should receive collateral worth `11,000$`(10,000 * 1.1).
- However, the protocol fee is calculated as: 11,000 * 0.2 = 2,200$

The liquidator receives: `11,000 - 2,200 =`**`8,800$`**

- In this case, the liquidator loses `1,200$ (10,000 - 8,800)` by performing the liquidation, contrary to the intended incentive structure of the protocol.

## Impact
- This is a high severity issue because:
  + It contradicts the protocol's design intention of incentivizing liquidations.
  + It results in economic loss for liquidators if the fee is within the  range of [9.09% to 30%] which is expected according to the readme.
  + It  lead to a lack of liquidations, leaving the protocol with bad debt and undermining its financial stability.

## Code Snippet
- https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L466-L482
## Tool used

Manual Review

## Recommendation

- To address this issue, the protocol should calculate the liquidation fee based on the liquidation bonus rather than the entire seized asset amount. This ensures that liquidators always receive a profit incentive for performing liquidations.

The correct calculation for the liquidation fee should be:
```math
fee = assetAmount * liquidationBonus * feePercentage
```
Here's the diff block showing the necessary changes in the _transferAssetsToLiquidator function:
```diff
function _transferAssetsToLiquidator(address position, AssetData[] calldata assetData) internal {
    uint256 assetDataLength = assetData.length;
    for (uint256 i; i < assetDataLength; ++i) {
        if (Position(payable(position)).hasAsset(assetData[i].asset) == false) revert PositionManager_SeizeInvalidAsset(position, assetData[i].asset);
-       uint256 fee = liquidationFee.mulDiv(assetData[i].amt, 1e18);
+       uint discount = riskEngine.riskModule().LIQUIDATION_DISCOUNT();
+       uint256 bonusAmount = assetData[i].amt.mulDiv(discount, 1e18);
+       uint256 fee = bonusAmount.mulDiv(liquidationFee, 1e18);
        Position(payable(position)).transfer(owner(), assetData[i].asset, fee);
        Position(payable(position)).transfer(msg.sender, assetData[i].asset, assetData[i].amt - fee);
    }
}
```
> Note that in this case, the liquidation fee is always based on the 10% discount, even if the liquidator seizes less than that (due to insufficient collateral in a position, etc.). This means that even with this suggestion, liquidations could potentially become unprofitable in rare cases for certain positions. If the team wants to address this, it would require additional changes. However, this is a trade-off decision for the protocol to consider based on their priorities and risk tolerance.
