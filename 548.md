Faithful Teal Cuckoo

Medium

# Lack of oracle validation in `acceptLtvUpdate` can result in a DoS for the Pool-Asset pair

## Summary
The `RiskEngine.sol` allows pool owners to request LTV updates with a 72-hour timelock. However, while the `requestLtvUpdate` function checks for a valid oracle, the `acceptLtvUpdate` function does not. This could lead to a situation where an LTV update is accepted after the oracle has been removed or invalidated, resulting in DoS for the Pool-Asset pair.

## Vulnerability Detail
Pool owners can [update LTV parameters](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L167-L187) using the `requestLtvUpdate` function, which employs a 72-hour timelock before the LTV change takes effect. During the request phase, the function [ensures a valid oracle is set](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L171) for the asset:
```solidity
        // set oracle before ltv so risk modules don't have to explicitly check if an oracle exists
        if (oracleFor[asset] == address(0)) revert RiskEngine_NoOracleFound(asset);
```

After the timelock, the pool owner [can accept this request via the `acceptLtvUpdate`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L190-L210) function. However, given the 72-hour delay, there is a possibility that the protocol's admin could remove or change the oracle for the asset. The `acceptLtvUpdate` function does not re-check the oracle's validity before updating the LTV:
```solidity
    function acceptLtvUpdate(uint256 poolId, address asset) external {
        if (msg.sender != pool.ownerOf(poolId)) revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);

        LtvUpdate memory ltvUpdate = ltvUpdateFor[poolId][asset];

        // revert if there is no pending update
        if (ltvUpdate.validAfter == 0) revert RiskEngine_NoLtvUpdate(poolId, asset);

        // revert if called before timelock delay has passed
        if (ltvUpdate.validAfter > block.timestamp) revert RiskEngine_LtvUpdateTimelocked(poolId, asset);

        // revert if timelock deadline has passed
        if (block.timestamp > ltvUpdate.validAfter + TIMELOCK_DEADLINE) {
            revert RiskEngine_LtvUpdateExpired(poolId, asset);
        }

        // apply changes
        ltvFor[poolId][asset] = ltvUpdate.ltv;
        delete ltvUpdateFor[poolId][asset];
        emit LtvUpdateAccepted(poolId, asset, ltvUpdate.ltv);
    }
```

If the LTV is updated for an asset without an oracle, the `getAssetValue` function, which [fetches the asset's price from the oracle](https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/RiskModule.sol#L183-L187), will always revert, resulting in a DoS for the given Pool-Asset pair.

## Impact
If the LTV is updated for an asset without an oracle, it will cause a DoS for the affected Pool-Asset pair, as any attempts to fetch the asset's value will revert.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L167-L187
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L190-L210
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L183-L187

## Tool used

Manual Review

## Recommendation
Re-check the validity of the oracle for the asset upon accepting the ltv update:
```diff
    function acceptLtvUpdate(uint256 poolId, address asset) external {
        if (msg.sender != pool.ownerOf(poolId)) revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);

+       if (oracleFor[asset] == address(0)) revert RiskEngine_NoOracleFound(asset);
+
        LtvUpdate memory ltvUpdate = ltvUpdateFor[poolId][asset];

        // revert if there is no pending update
        if (ltvUpdate.validAfter == 0) revert RiskEngine_NoLtvUpdate(poolId, asset);

        // revert if called before timelock delay has passed
        if (ltvUpdate.validAfter > block.timestamp) revert RiskEngine_LtvUpdateTimelocked(poolId, asset);

        // revert if timelock deadline has passed
        if (block.timestamp > ltvUpdate.validAfter + TIMELOCK_DEADLINE) {
            revert RiskEngine_LtvUpdateExpired(poolId, asset);
        }

        // apply changes
        ltvFor[poolId][asset] = ltvUpdate.ltv;
        delete ltvUpdateFor[poolId][asset];
        emit LtvUpdateAccepted(poolId, asset, ltvUpdate.ltv);
    }
```