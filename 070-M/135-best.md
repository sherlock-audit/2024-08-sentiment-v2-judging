Mammoth Oily Tadpole

Medium

# Lack of Liquidation Buffer Allows Immediate Liquidations from Minor Price Fluctuations, Penalizing Borrowers

### Summary

 The protocol’s liquidation mechanism does not implement a safety buffer between the liquidation threshold and the maximum Loan-to-Value (LTV) ratio. As a result, borrowers who take out loans near the maximum LTV (e.g., 75%) can be immediately liquidated due to even minor market fluctuations.

### Root Cause

The root cause of this issue lies in how the `isPositionHealthy` function in the `RiskModule` is implemented. It uses the same LTV ratio to both validate new positions when they are created and to determine if a position is still healthy before liquidation. This can be seen in the following code:

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L84

This design flaw means that a position created with an LTV of 75%—for instance, 100 ETH collateral and 75 ETH debt—can be flagged for liquidation even with minimal changes in collateral or debt values , such as collateral drop to 99.99 ETH, resulting in an LTV of approximately 75.0075%. This happens because there is no buffer between the initial LTV ratio and the liquidation threshold.

*  `liquidate` function
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L435

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

* `validateLiquidation` function

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L117

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
```

The liquidation threshold should ideally be set higher (e.g., 80%) than the initial LTV ratio when creating a position (e.g., 75%) to provide a buffer that prevents liquidations from minor market fluctuations and allows borrowers some margin before liquidation occurs.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

* Unnecessary Liquidations: Due to the lack of a safety buffer between the LTV used for position creation and the liquidation threshold, positions can be liquidated for minor fluctuations in assets value.

* Increased Liquidation Risk: Borrowers taking loans near the maximum allowed LTV are at a higher risk of liquidation even with minimal market movements. This makes it difficult for users to maintain healthy positions, leading to more frequent and premature liquidations.

* User Experience: Borrowers can be unfairly liquidated and penalized due to minor market movement. 

### PoC

```solidity
// run in PositionManager.t.sol
function testLiquidationWithMinorCollateralDrop() public {
     // Set up initial conditions
    // Start with asset2 and asset1 at the same price (1 ether)
    // Deposit 100 ether worth of asset2 and borrow 75 ether worth of asset1
    testSimpleBorrow();

   
    // Update the price of asset2 to 0.9999 ether
    asset2Oracle = new FixedPriceOracle(0.9999 ether);
    vm.startPrank(protocolOwner);
    riskEngine.setOracle(address(asset2), address(asset2Oracle));

    // Now the position is at:
    // 99.99 ether of collateral (asset2)
    // 75 ether of debt (asset1)

    // Trigger liquidation
    DebtData;
    debtData[0] = DebtData({ poolId: linearRatePool, amt: 75 ether });
    
    AssetData;
    assetData[0] = AssetData({ asset: address(asset2), amt: 93 ether });

    address tom = vm.addr(12);
    asset1.mint(tom, 100 ether);
    vm.startPrank(tom);
    asset1.approve(address(positionManager), 100 ether);

    // Perform liquidation
    positionManager.liquidate(position, debtData, assetData);
}

```

### Mitigation

Introduce a separate `liquidationThreshold` variable higher than the LTV ratio to prevent unfair liquidations due to minor price changes and ensure positions are only liquidated if they breach this new, more conservative threshold.