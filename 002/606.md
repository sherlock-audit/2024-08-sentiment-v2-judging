Flat Navy Bee

Medium

# liquidators are not incentivized and liquidation may revert for high LTV pools

## Summary

liquidators are not incentivized and liquidation may revert for high LTV pools

## Vulnerability Detail
```solidity
    function liquidate(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData
    ) external nonReentrant {
        riskEngine.validateLiquidation(position, debtData, assetData);

        // liquidate
        _transferAssetsToLiquidator(position, assetData);
        _repayPositionDebt(position, debtData);

        // position should be within risk thresholds after liquidation
        if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
        emit Liquidation(position, msg.sender, ownerOf[position]);
    }
```
During the liquidation process, three limitations are guaranteed:
1. Liquidator is able to acquire no more assets than the balance of the position. 
2. Liquidator is responsible for repaying some/all of the debt on the position and receives assets equal to `debtRepaidValue/(1 - discount)`.
3. position must be healthy after liquidation.

For pools with `90% < LTV < 98%`, liquidation will revert when liquidator liquidates bad debts as specified by `LIQUIDATION_DISCOUNT`.
```solidity
    function validateLiquidation(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData
    ) external view {
        // position must breach risk thresholds before liquidation
        if (isPositionHealthy(position)) revert RiskModule_LiquidateHealthyPosition(position);

        _validateSeizedAssetValue(position, debtData, assetData, LIQUIDATION_DISCOUNT);
    }

    function _validateSeizedAssetValue(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData,
        uint256 discount
    ) internal view {
        ...
        // max asset value that can be seized by the liquidator
        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
        if (assetSeizedValue > maxSeizedAssetValue) {
            revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
        }
    }
```
Since there are not enough assets in the position that can satisfy `assetSeizedValue`, liquidation would simply fail.

To fix this issue, please refer to [Morpho blue](https://docs.morpho.org/morpho/concepts/liquidation) for a similar LLTV-LIF formula. 

## Impact

liquidators are not incentivized and liquidation may revert for high LTV pools

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L111

## Tool used

Manual Review

## Recommendation

Refer to [Morpho blue](https://docs.morpho.org/morpho/concepts/liquidation)