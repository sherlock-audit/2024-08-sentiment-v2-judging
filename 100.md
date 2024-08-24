Fast Graphite Aardvark

High

# validation to liquidation should include Liquidation fees as they are liable from customers

### Summary

When validation for liquidation is computed in the risk module, it computes the value for debt and collateral including the interest accrued, but the valuation does not include the liquidation fees that needs to be born by the customer. Hence liquidation fees should be accounted in the validation logic.

The liquidation fee is charged by the liquidator to liquidate positions that are below the collateral factor. If the valuation falls to the extent that liquidation fees cannot be covered, then liquidation may not go through in time leaving the position as bad debt.
 

### Root Cause

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L430-L444

`PositionManager::liquidate(...)` function checks with the risk Engine, if the position is validate for Liquidation. In the below code snippet, `riskEngine.validateLiquidation(...)` does not take into account the liquidation fee charged by the liquidator which needs to be born by the customer. Hence, the liable amount from the customer should include the borrowed amount + interest accrued  + liquidation fees. Since the `riskEngine.validateLiquidation(...)`  does not account for liquidation fees, if the valuation falls to the extent where liquidation fees cannot be covered, the liquidation process will revert.

```solidity
    function liquidate(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData
    ) external nonReentrant {
 ==>       riskEngine.validateLiquidation(position, debtData, assetData);
```



### Internal pre-conditions

1. Liquidation validation should check for the position by accounting for
    Borrowed amount
    Accrued Interest
    Liquidation fee

2. The liquidation should happen before the collateral falls short of the some of above 3 items.

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

When the valuation of the collateral falls below the sum of borrowed funds + accrued interest + liquidation fees, then there is a risk that liquidation will not go through as there may not be enough funds left in the position after liquidation to cover.

In such a case, since liquidator will not have the necessary motivation to liquidation such positions leading to bad debts for the protocol.


### PoC

_No response_

### Mitigation

Account for liquidation fees in the `riskEngine.validateLiquidation(...)` so that when the assessment for liquidation of a position is done, it is done with all the fees due. This will ensure that positions are liquidated timely and liquidators are motivated to execute the liquidation in a timely way.

