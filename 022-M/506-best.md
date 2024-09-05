Generous Navy Bear

Medium

# User can revert the `positionBeacon`  value set by  the ADMIN.

## Summary
User can revert the `positionBeacon`  value set by  the ADMIN.

## Vulnerability Detail
Using  the `setBeacon()` , owner can change the value of `positionBeacon` to a  new Address.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L503-L506

At the same time we have `updateRegistry()` which is a public function where the positionBeacon is set from the values of Registr contract.
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L204-L208

    function updateFromRegistry() public {
        pool = Pool(registry.addressFor(SENTIMENT_POOL_KEY));
        riskEngine = RiskEngine(registry.addressFor(SENTIMENT_RISK_ENGINE_KEY));
        positionBeacon = registry.addressFor(SENTIMENT_POSITION_BEACON_KEY);
    }
## Impact
Any User can revert the `positionBeacon`  value set by  the ADMIN.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L204-L208

## Tool used

Manual Review

## Recommendation

positionBeacon update can be omiited from the updateRegistry.