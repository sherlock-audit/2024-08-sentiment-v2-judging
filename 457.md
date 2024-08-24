Massive Seafoam Eel

Medium

# Liquidator can revert changes made during `RiskEngine::setRiskModule()` to use a higher liquidation discount.

## Summary
Liquidator can rollback changes made in RiskEngine during the call to `setRiskModule()` function to use an old liquidation discount if it's higher than the new one.
## Vulnerability Detail
Position can be liquidated through invoking `liquidate()` function of the PositionManager.
[PositionManager.sol#L430-L435](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L430-L435)
```solidity
function liquidate(
    address position,
    DebtData[] calldata debtData,
    AssetData[] calldata assetData
) external nonReentrant {
    riskEngine.validateLiquidation(position, debtData, assetData);
```
As can be seen, `validateLiquidation()` is invoked on the RiskEngine, which calls `validateLiquidation()` on the underlying RiskModule set in the RiskEngine.
[RiskEngine.sol#L136-L142](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L136-L142)
```solidity
function validateLiquidation(
    address position,
    DebtData[] calldata debtData,
    AssetData[] calldata assetData
) external view {
    riskModule.validateLiquidation(position, debtData, assetData);
}
```
RiskModule ensures that the amount of assets seized does not exceed the maximum allowed amount determined by the RiskModule's liquidation discount. The higher the liquidation discount the more assets a liquidator can seize.
[RiskModule.sol#L111-L120](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L111-L120)
```solidity
function validateLiquidation(
    address position,
    DebtData[] calldata debtData,
    AssetData[] calldata assetData
) external view {
    // position must breach risk thresholds before liquidation
    if (isPositionHealthy(position))
        revert RiskModule_LiquidateHealthyPosition(position);
    _validateSeizedAssetValue(  <<@
        position,
        debtData,
        assetData,
        LIQUIDATION_DISCOUNT <<@
    );
}
```

There exist two ways in the RiskEngine to change the underlying RiskModule and subsequently the liquidation discount:
1. RiskModule can be changed in Registry and `RiskEngine::updateFromRegistry()` can be invoked to update the state of the RiskEngine.
2. The owner of the RiskEnginge can call `setRiskModule()` to update RiskEngine's underlying RiskModule without updating the value in the registry.

[RiskEngine.sol#L235-L239](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L235-L239)
```solidity
function setRiskModule(address _riskModule) external onlyOwner {
    riskModule = RiskModule(_riskModule);
    emit RiskModuleSet(_riskModule);
}
```

However, if the owner wishes to change the RiskModule only for a specific RiskEngine, without updating the value in the registry, those changes can be easily reverted by any of the users. This can be done because `updateFromRegistry()` function of the RiskEngine is not restricted and when calling it the RiskModule will be set to an old value stored in the registry.
[RiskEngine.sol#L114-L120](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L114-L120)
```solidity
function updateFromRegistry() external {
    pool = Pool(REGISTRY.addressFor(SENTIMENT_POOL_KEY));
    riskModule = RiskModule(REGISTRY.addressFor(SENTIMENT_RISK_MODULE_KEY));
    emit PoolSet(address(pool));
    emit RiskModuleSet(address(riskModule));
}
```

Imagine a scenario where the owner updates the RiskModule in the RiskEngine by calling `setRiskModule()` and changes the liquidation discount from 20% to 10%.
Bob wishes to liquidate a debt worth 100 ETH and he is allowed to seize `100 / (100% - 10%) = 111 ETH`.
[RiskModule.sol#L156](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L156)
```solidity
uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
```
Before calling `liquidate()` Bob calls `RiskEnginge::updateFromRegistry()`, which sets the RiskModule to the one stored in the registry with a liquidation discount of 20%. Because of that Bob now is allowed to seize `100 / (100% - 20%) = 125 ETH`.

The same issue is present in the PositionManager, where any user can easily revert changes made during a call to [setBeacon()](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L503-L506).
## Impact
A malicious user can easily revert changes made by the owner and seize more assets than allowed.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L503-L506
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L235-L239
## Tool used

Manual Review

## Recommendation
Restrict the `updateFromRegistry()` functions both in PositionManager and RiskEngine, so an owner will have an ability to selectively update `positionBeacon` and `riskModule` variables respectively without having to change their values in the registry.