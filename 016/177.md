Sharp Sapphire Ferret

Medium

# Pool owners cannot remove collateral assets

## Summary
Pool owners may need to reset/remove the LTV for some collateral assets, however that will be impossible, since the system prevent setting the LTV to 0. This can lead to potentially too risky assets being used as collateral.

## Vulnerability Detail
Pool owners can set LTVs for assets they want to use as collateral against their pool asset (aka. borrowing token). This is done by setting a LTV for that asset using [requestLtvUpdate](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L167-L187) and [acceptLtvUpdate](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L167-L187).

```solidity
    function requestLtvUpdate(uint256 poolId, address asset, uint256 ltv) external {
        if (msg.sender != pool.ownerOf(poolId)) revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);
        if (oracleFor[asset] == address(0)) revert RiskEngine_NoOracleFound(asset);

        if (ltv < minLtv || ltv > maxLtv) revert RiskEngine_LtvLimitBreached(ltv);
        if (pool.getPoolAssetFor(poolId) == asset) revert RiskEngine_CannotBorrowPoolAsset(poolId);

        LtvUpdate memory ltvUpdate;
        if (ltvFor[poolId][asset] == 0) ltvUpdate = LtvUpdate({ ltv: ltv, validAfter: block.timestamp });
        else ltvUpdate = LtvUpdate({ ltv: ltv, validAfter: block.timestamp + TIMELOCK_DURATION });

        ltvUpdateFor[poolId][asset] = ltvUpdate;
        emit LtvUpdateRequested(poolId, asset, ltvUpdate);
    }
```

However once the asset is set, there is no way to remove it, even if the pool owner and his LPs don't want this asset used as collateral anymore. 

Example:
1. Pool owner adds a new quite risky asset, but sets his LTV at 20%
2. The pool works fine for some time, but that asset is too risky and accrues some bad debt, even at that low LTV

The pool owner has no way to remove it. His only option is to set it to the min LTV at 10%, however that will not make much of a difference.

## Impact
Loss of funds for LPs.

## Code Snippet
```solidity
    function requestLtvUpdate(uint256 poolId, address asset, uint256 ltv) external {
        if (msg.sender != pool.ownerOf(poolId)) revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);
        if (oracleFor[asset] == address(0)) revert RiskEngine_NoOracleFound(asset);

        if (ltv < minLtv || ltv > maxLtv) revert RiskEngine_LtvLimitBreached(ltv);
        if (pool.getPoolAssetFor(poolId) == asset) revert RiskEngine_CannotBorrowPoolAsset(poolId);

        LtvUpdate memory ltvUpdate;
        if (ltvFor[poolId][asset] == 0) ltvUpdate = LtvUpdate({ ltv: ltv, validAfter: block.timestamp });
        else ltvUpdate = LtvUpdate({ ltv: ltv, validAfter: block.timestamp + TIMELOCK_DURATION });

        ltvUpdateFor[poolId][asset] = ltvUpdate;
        emit LtvUpdateRequested(poolId, asset, ltvUpdate);
    }
```
## Tool used
Manual Review

## Recommendation
A good suggestion can be to make a separate map for assets that can be used to open new positions or borrow more. This way risky assets are not gonna be used for borrowing anymore, but old positions which still have them will not be liquidated in an instant.