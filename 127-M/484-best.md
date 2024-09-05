Generous Navy Bear

High

# The position will become completely useless when a pool is added, due to the absence of a necessary check in borrow()

## Summary
When a position borrows an asset A from a pool X , `borrow()` is not checking whether the asset A is not contained in the positionAssets.
Since the owner of pool X cannot add the pool.asset for collateral , the LTV for [pool X][asset A] remains 0.

Hence when the minReqAssetValue is calculated for pool X , it will always revert when the innerloop for the positionAssets reaches the Asset A.

## Vulnerability Detail

User can add an `asset` in positionAssets as a collateral to make their position healthy.

In the `borrow()` , we are not checking whether the borrowed asset of the pool is already contained in the `positionAsset`.
[code](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L384-L403)

We also know that `poolOwner` of a `poolId` cannot add its own Asset for the `collateral`.
[code](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L177)
```solidity
    function requestLtvUpdate(uint256 poolId, address asset, uint256 ltv) external {
       ....
         // Positions cannot borrow against the same asset that is being lent out
 =>     if (pool.getPoolAssetFor(poolId) == asset) revert RiskEngine_CannotBorrowPoolAsset(poolId);


        emit LtvUpdateRequested(poolId, asset, ltvUpdate);
    }
```

But later when we calculate minReqAsset we are looping through each of the positionAssets for each debtPools added.
[code](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L262-L274)

```solidity
        for (uint256 i; i < debtPoolsLength; ++i) {
            for (uint256 j; j < positionAssetsLength; ++j) {
                uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);


                // revert with pool id and the asset that is not supported by the pool
=>               if (ltv == 0) revert RiskModule_UnsupportedAsset(position, debtPools[i], positionAssets[j]);


                // debt is weighted in proportion to value of position assets. if your position
                // consists of 60% A and 40% B, then 60% of the debt is assigned to be backed by A
                // and 40% by B. this is iteratively computed for each pool the position borrows from
                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
            }
        }
```

Hence the `minReqAsset` will always revert and can never validate a position.No more operation can be done for that postion.


## Impact

No operations can be done for the position by positionholder nor the liquidator.Assets will get locked forever.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L384-L403
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L177
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L262-L274
## Tool used

Manual Review

## Recommendation
Check whether the asset has already added in the positionAsset when a new debtPool is added.Also check whether the debtPool lending that asset has already added while an asset is added to the positionToken.