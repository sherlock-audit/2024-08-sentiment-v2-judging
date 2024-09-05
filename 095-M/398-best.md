Overt Wintergreen Rabbit

Medium

# Unnecessary read from an oracle will cause the liquidation unavailable when the oracle is down/stale

### Summary

Unnecessary read from an oracle will cause the liquidation unavailable when the oracle is down/stale.

### Root Cause

In `RiskModule.sol`, `isPositionHealthy => _getPositionAssetData => getAssetValue` 

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L183-L187

```solidity
    function getAssetValue(address position, address asset) public view returns (uint256) {
        IOracle oracle = IOracle(riskEngine.getOracleFor(asset));
        uint256 amt = IERC20(asset).balanceOf(position);
        return oracle.getValueInEth(asset, amt);
    }
```

There is a read from oracle even when `amt` is zero.

### Internal pre-conditions

1. A base pool supports more than one collateral asset. Let's call these assets: `asset1`, `asset2`,... Meaning `ltvFor[poolId][asset1], ltvFor[poolId][asset2],...` is set.
2. A position has an asset `assetX` in its `positionAssets` (before the oracle is down/stale). But the balance of the position in `assetX` is zero.

### External pre-conditions

1. The oracle for `assetX` is down/stale.

### Attack Path

From the above pre-conditions, the function `RiskModule#isPositionHealthy` will revert, because the orcale of `assetX` is down/stale. But the correct behavior is `RiskModule#isPositionHealthy` should not revert, because the position has zero balance in `assetX`. The read from the oracle of `assetX` is unnecessary.

When `RiskModule#isPositionHealthy` reverts, the liquidation is unavailable.

### Impact

A user can game the system by adding as many as possible supported assets to their position by using `PositionManager#process` with `action.op == Operation.AddToken`. But, they have balance in only one of these assets. When the oracle of one of the other assets is down/stale, they can avoid liquidation in that period.

### PoC

_No response_

### Mitigation

Do not read from oracle when a balance of a position is zero

```solidity
    function getAssetValue(address position, address asset) public view returns (uint256) {
        uint256 amt = IERC20(asset).balanceOf(position);
	if (amt == 0) return 0;
	IOracle oracle = IOracle(riskEngine.getOracleFor(asset));
        return oracle.getValueInEth(asset, amt);
    }
```