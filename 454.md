Bitter Sandstone Worm

Medium

# If new `registry` contract is deployed, `RiskEngine` cannot be updated, which will DoS current debts.

### Summary

The current scope provides functions to [update](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L677-L681) the `registry` contract:
Example in Pool:
```solidity
    function setRegistry(address _registry) external onlyOwner { //@ok
        registry = _registry;
        updateFromRegistry();
        emit RegistrySet(_registry);
    }
```
But [RiskEngine has the registry as immutable](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L50) variable, which means that in case of deployment of a new registry, the team will also have to deploy new `RiskEngine`, which will nullify all [ltvFor](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L60) for the debts, which means that all current debts actions will revert on isPositionHealthy of the following line inside RiskModule:
```solidity
                uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);
                // See if this asset is valid for the debtPool
                // revert with pool id and the asset that is not supported by the pool
                if (ltv == 0) revert RiskModule_UnsupportedAsset(position, debtPools[i], positionAssets[j]);
```

### Root Cause

- `registry` being immutable in `RiskEngine`
- Having the ability to change the registry contract in `Pool`

### Internal pre-conditions

- New registry is deployed and set inside `Pool` and all other contracts

### External pre-conditions

None

### Attack Path

- Protocol team decides that new `Registry` should be deployed and they do so, set all addresses and set the registry in the `pool` and `positionManager`
- The current `riskModule` still uses the old registry as immutable var and protocol has no other choice, but to deploy new `riskModule` contract and set the new registry
- All `ltvFor` from the old contract are deleted in the current context, which will lead to a major impact in `!riskEngine.isPositionHealthy(position)` check in `PositionManager`
- User may be unable to repay or be liquidated

### Impact

- DoS repay/liquidate functionalities 

### PoC

_No response_

### Mitigation

Make `registry` variable storage var in `RiskEngine` and introduce a setter.