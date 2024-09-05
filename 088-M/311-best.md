Bubbly Alabaster Rooster

Medium

# Protocol admin / Pool Owner will not be able to offboard/delist an asset without breaking liquidations and other core functionalities

### Summary

Once an asset has been whitelisted into the protocol, and is used as collateral, it can't be de-listed without breaking liquidations or core protocol functionalities. 

There would be multiple reasons as to why this might be the case:

- The underlying collateral has become too volatile (Luna scenario is an excellent case).
- Governance in charge of Sentiment protocol decides to remove it as a collateral due to X reason.
- There has been some kind of a change in the mechanics of how that token operates and Sentiment wants it removed (e.g. upgradeable tokens, most-popular examples include USDC/USDT, a token becomes a fee-on-transfer).
- The oracle for the token is no longer reliable due to an external reason. 

### Root Cause

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L123-L127

When a certain asset needs to be whitelisted so that it can be used as a collateral/borrow token, the protocol admin/governance will introduce it by setting a valid oracle for it, i.e. other than address(0). 

```solidity
    function setOracle(address asset, address oracle) external onlyOwner {
        oracleFor[asset] = oracle;

        emit OracleSet(asset, oracle);
    }
```

Once the oracle for the asset has been set in the protocol, it can be set as a collateral by the pool owner by setting a LTV for it.

```solidity
 function requestLtvUpdate(uint256 poolId, address asset, uint256 ltv) external {
        if (msg.sender != pool.ownerOf(poolId)) revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);

        // set oracle before ltv so risk modules don't have to explicitly check if an oracle exists
        if (oracleFor[asset] == address(0)) revert RiskEngine_NoOracleFound(asset);

        // ensure new ltv is within global limits. also enforces that an existing ltv cannot be updated to zero
        if (ltv < minLtv || ltv > maxLtv) revert RiskEngine_LtvLimitBreached(ltv);

        // Positions cannot borrow against the same asset that is being lent out
        if (pool.getPoolAssetFor(poolId) == asset) revert RiskEngine_CannotBorrowPoolAsset(poolId);

        LtvUpdate memory ltvUpdate;
        // only modification of previously set ltvs require a timelock
        if (ltvFor[poolId][asset] == 0) ltvUpdate = LtvUpdate({ ltv: ltv, validAfter: block.timestamp });
        else ltvUpdate = LtvUpdate({ ltv: ltv, validAfter: block.timestamp + TIMELOCK_DURATION });

        ltvUpdateFor[poolId][asset] = ltvUpdate;

        emit LtvUpdateRequested(poolId, asset, ltvUpdate);
    }
```

The problem arises once this token has been utilized as a collateral it can no longer be removed without breaking core functionalities.

As mentioned in the summary there could be numerous reasons as to why a collateral would need to be de-listed, and some popular examples can be: 

- The Luna scenario;
- MakerDAO delists WBTC as collateral due to controversies regarding the custodian change of the asset;
- The oracle(s) for the asset no longer work/has a valid price;
- The collateral has become too volatile;

The pool owner can't set the LTV to 0, nor can the LTV bound be set as 0: 

```solidity
        // ensure new ltv is within global limits. also enforces that an existing ltv cannot be updated to zero
        if (ltv < minLtv || ltv > maxLtv) revert RiskEngine_LtvLimitBreached(ltv);
```

Global settings:

```solidity
function setLtvBounds(uint256 _minLtv, uint256 _maxLtv) external onlyOwner {
        if (_minLtv == 0) revert RiskEngine_MinLtvTooLow();
```

In case the oracle address is set as address(0), this would break liquidations, since when the liquidation would need to be validated in the `validateLiquidation()` function:
```solidity
 function validateLiquidation(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData
    ) external view {
        // position must breach risk thresholds before liquidation
        if (isPositionHealthy(position)) revert RiskModule_LiquidateHealthyPosition(position);
```

 Subsequently the function `isPositionHealthy()` would be called:

```solidity
 function isPositionHealthy(address position) public view returns (bool) {
        // a position can have four states:
        // 1. (zero debt, zero assets) -> healthy
        // 2. (zero debt, non-zero assets) -> healthy
        // 3. (non-zero debt, zero assets) -> unhealthy
        // 4. (non-zero assets, non-zero debt) -> determined by weighted ltv

        (uint256 totalDebtValue, uint256[] memory debtPools, uint256[] memory debtValueForPool) =
            _getPositionDebtData(position);
        if (totalDebtValue == 0) return true; // (zero debt, zero assets) AND (zero debt, non-zero assets)

        (uint256 totalAssetValue, address[] memory positionAssets, uint256[] memory positionAssetWeight) =
            _getPositionAssetData(position);
        if (totalAssetValue == 0) return false; // (non-zero debt, zero assets)
```
The function above will fetch the asset and debt data of the position, so when the asset data is fetched via the `_getPositionAssetData()`: 

```solidity
 function _getPositionAssetData(
        address position
    ) internal view returns (uint256, address[] memory, uint256[] memory) {
        uint256 totalAssetValue;

        address[] memory positionAssets = Position(payable(position)).getPositionAssets();
        uint256 positionAssetsLength = positionAssets.length;
        uint256[] memory positionAssetData = new uint256[](positionAssetsLength);

        for (uint256 i; i < positionAssetsLength; ++i) {
            uint256 assets = getAssetValue(position, positionAssets[i]);
            // positionAssetData[i] stores value of positionAssets[i] in eth
            positionAssetData[i] = assets;
            totalAssetValue += assets;
        }
```

This would revert when `getAssetValue()` gets called: 

```solidity
function getAssetValue(address position, address asset) public view returns (uint256) {
        IOracle oracle = IOracle(riskEngine.getOracleFor(asset));
        uint256 amt = IERC20(asset).balanceOf(position);
        return oracle.getValueInEth(asset, amt);
    }

```
This is due to `getOracleFor()` reverting because of the oracle being set to address(0):

```solidity
    function getOracleFor(address asset) public view returns (address) {
        address oracle = oracleFor[asset];
        if (oracle == address(0)) revert RiskEngine_NoOracleFound(asset);
        return oracle;
    }
```

Not being able to remove a compromised asset as collateral could hurt the protocol and lead to bad debt.
The protocol would have to rely on the users to remove the asset from their positions, which isn't an effective method as malicious users could refuse to do this in order to avoid liquidations.

### Internal pre-conditions

1. Admin needs to set an already existing collateral asset's oracle to address(0) in order to delist it.
2. Other than the above which would break liquidations as well as other core functionalities, currently  there's no way to remove an asset as a collateral or un-whitelist / blacklist it. 

### External pre-conditions

1. Collateral becomes too volatile / token is upgraded / compromised / oracle becomes unresponsive and it would need to be removed as collateral. 

### Attack Path

1. Asset which is used as collateral is compromised (numerous examples as to why this might happen were included above), but popular examples include: The Luna scenario, WBTC, oracle for the asset is no longer responsive, token was upgraded etc.
2. Pool owners can't remove this asset as collateral due to its inability to set it as less than 10% LTV which would still cause value leaks if asset is compromised.
3. Admin can't remove the asset by setting its oracle to address(0), since if they do, it will break liquidations and other core functionalities.
4. It would be left to the discretion of users to remove the asset from the position, but they may refuse to do so in order to brick / prevent liquidations. 

### Impact

The inability of the protocol to remove an asset as collateral without breaking core functionalities could lead to the amounting of bad debt in the protocol if the asset in-question is compromised. 

### PoC

/

### Mitigation

Don't use the oracle setting as a way to determine whether an asset is accepted as collateral or not, implement an admin-controlled whitelisting mapping or allow for ltv to be set to 0 in special cases by protocol admin-only.