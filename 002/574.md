Generous Navy Bear

High

# `_getMinReqAssetValue` will always revert for debtPool if the positionAssets contain a different asset from different pool.

## Summary
The protocol is not considering that the `position` can borrow from different pools having different `collateral` assets and hence the `positionAsset` array can contain any collateral assets that borrower wishes to be put as collateral for those pools.
this results in The `minRequired` asset will always revert.

## Vulnerability Detail

In the `_getMinReqAssetValue()` the function is using a double loop to find all the `LTV` values for calculation by checking all the `debtpools` with all the  assets in the `{positionAsset[]}`. 

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L250-L275

```solidity
    function _getMinReqAssetValue(
    ) internal view returns (uint256) {
        uint256 minReqAssetValue;

        uint256 debtPoolsLength = debtPools.length;
        uint256 positionAssetsLength = positionAssets.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
            for (uint256 j; j < positionAssetsLength; ++j) {
=>                uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]); @1


                // revert with pool id and the asset that is not supported by the pool
=>                if (ltv == 0) revert RiskModule_UnsupportedAsset(position, debtPools[i], positionAssets[j]);@2

                // debt is weighted in proportion to value of position assets. if your position
                // consists of 60% A and 40% B, then 60% of the debt is assigned to be backed by A
                // and 40% by B. this is iteratively computed for each pool the position borrows from
                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
            }
        }

```

@1 - checking the ltv value for the 'debtPool and the asset' which can be 0 if the asset is not mentioned by the current poolId owner,

@2 reverting if the LTV is 0.

But a positionAsset can contain collateral assets of differentPools that the position borrows from.
These assets need not be same accross pools  as these are specified the individual pool Owners.


## Impact
The `minRequiredAsset` will always revert if the `positionAsset` contain an asset which has an LTV sepcified by  `pool A` owner but not by `pool B` owner considering both the `position holds debt from both pools A and B`.


## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L250-L275

## Tool usedAC

Manual Review

## Recommendation

needs a thorough evaluation since it can effect the weight calculation for the pools also.