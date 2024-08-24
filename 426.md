Shambolic Cobalt Copperhead

High

# Protocol will treat unsupported assets, which were previously supported, as legit assets in health check and liquidation

### Summary

There is a case where assets used to be supported/ known were added into position assets before becoming unsupported. In this case, these assets will still be treated as known asset by risk engine .

### Root Cause

- In `RiskModule.sol:232`, the risk engine does not check if there is  unsupported asset in the position assets. There is the case where assets used to be supported, were being added into position, but later becoming unsupported.
- Similarly in `PositionManager.sol:469`, transferAssetsToLiquidator does not check if the asset is supported or not.

### Internal pre-conditions

1. Asset A was supported by the protocol and was added into the position.
2. Asset A becomes unknown/unsupported.

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

- Users could still use value of unsupported/unknown assets to borrow/backing up debts
- Protocol could give unsupported assets to liquidators.
### Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L466-L482

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L232-L237
### PoC

_No response_

### Mitigation

Consider adding a check to see if asset is supported:
```solidity
        for (uint256 i; i < positionAssetsLength; ++i) {
     >>>       if (!positionManager.isKnownAsset()[positionAssets[i]]) continue;
            uint256 assets = getAssetValue(position, positionAssets[i]);
            // positionAssetData[i] stores value of positionAssets[i] in eth
            positionAssetData[i] = assets;
            totalAssetValue += assets;
        }


```

```solidity
function _transferAssetsToLiquidator(address position, AssetData[] calldata assetData) internal {
        // transfer position assets to the liquidator and accrue protocol liquidation fees
        uint256 assetDataLength = assetData.length;
        for (uint256 i; i < assetDataLength; ++i) {
            // ensure assetData[i] is in the position asset list
           >>> if (Position(payable(position)).hasAsset(assetData[i].asset) == false && !isKnownAsset[assetData[i].asset]) {
                revert PositionManager_SeizeInvalidAsset(position, assetData[i].asset);
            }
            // compute fee amt
            // [ROUND] liquidation fee is rounded down, in favor of the liquidator
            uint256 fee = liquidationFee.mulDiv(assetData[i].amt, 1e18);
            // transfer fee amt to protocol
            Position(payable(position)).transfer(owner(), assetData[i].asset, fee);
            // transfer difference to the liquidator
            Position(payable(position)).transfer(msg.sender, assetData[i].asset, assetData[i].amt - fee);
        }
    }
```