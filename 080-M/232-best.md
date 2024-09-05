Narrow Mustard Hyena

High

# Inclusion of Unrecognized Assets in Position Health Checks Leads to Inaccurate Assessments and Potential DoS

## Summary
Unrecognized assets are incorrectly included during the position's health checks, even after they have been marked as unacceptable by the protocol. This flaw can lead to inaccurate health assessments, making unhealthy positions appear healthy, or cause a denial of service if the oracle for such assets is removed.
## Vulnerability Detail
In `PositionManager`, after every process, either via, [PositionManager::process](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L229-L232) or [processBatch](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L238-L246) function, the position health is checked.
Down the logic in [RiskModule::isPositionHealthy](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L67-L85) function, the internal function, _getPositionAssetData is called, this function further queries the position getPositionAssets function to return the position added assets, the position balance of these assets are then queried and later used to determine the position's health.
The problem here is, if USDC is among this position's assets and for some reason USDC becomes no longer acceptable as an asset in the protocol, via an admin call to P[ositionManager::toggleKnownAsset](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L522-L525) function, though the asset is now no longer recognized by the protocol, all position health checks still include the position's USDC balance as a collateral.

## Impact
There are two possible impacts here:
+ Unhealthy positions will appear healthy, due to the inflated collateral amount.

+ Given that USDC is no longer a known asset in the protocol, If the set oracle for USDC in RiskEngine is removed, all health checks for this position will result in a revert, down the logic at R[iskModule::isPositionHealthy](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L67-L85) --> [_getPositionAssetData](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L221-L248) --> [getAssetValue](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L183-L187) --> [riskEngine::getOracleFor](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L123-L128):
```solidity
    function getOracleFor(address asset) public view returns (address) {
        address oracle = oracleFor[asset];
        if (oracle == address(0)) revert RiskEngine_NoOracleFound(asset); //  <-- @
        return oracle;
    }
```
This will thus result in a complete Denial of service for all positions with USDC as an asset, as all [positionManager::process](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L229-L232) and [ProcessBatch](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L238-L246) calls will result in a revert, due to the health checks. 
Also, liquidating such positions will be impossible.
## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L221-L248

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L67-L85


## Tool used

Manual Review

## Recommendation
Update `RiskModule` contract to store `positionManager`, then update [_getPositionAssetData](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L221-L248) function to only compute values for known assets:
```solidity
    function _getPositionAssetData(
        address position
    ) internal view returns (uint256, address[] memory, uint256[] memory) {
          ##############

        for (uint256 i; i < positionAssetsLength; ++i) {
++            if (positionManager.isKnownAsset(positionAssets[i])) {
                uint256 assets = getAssetValue(position, positionAssets[i]);
                // positionAssetData[i] stores value of positionAssets[i] in eth
                positionAssetData[i] = assets;
                totalAssetValue += assets;
            }
        }

                    ####################

        return (totalAssetValue, positionAssets, positionAssetData);
    }
```
