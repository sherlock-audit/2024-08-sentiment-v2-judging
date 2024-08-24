Damaged Malachite Gibbon

Medium

# Inability to Utilize Preferred Collateral Due to Limitations in Position Health Check Function

## Summary
Position can't utilize an asset as collateral if it's one of the borrowing asset.

## Vulnerability Detail
It's well understood that an asset can serve as its own collateral for a position. However, a position should also be capable of holding that asset to support the borrowing of other assets. With the current implementation of the position health check, this isn't feasible. The `isPositionHealthy` function compares the actual asset value of the position (`totalAssetValue`) against the minimum required asset value needed to secure the debt (`minReqAssetValue` as calculated by `_getMinReqAssetValue`).

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

>       uint256 minReqAssetValue =
            _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);
        return totalAssetValue >= minReqAssetValue; // (non-zero debt, non-zero assets)
    }
```

We can't ensure a flexible collateral comparison in the specified cases. Instead, it will fail even if the asset balance is zero.
In `_getMinReqAssetValue`, the following line causes a revert because the LTV is set to 0.

```solidity
    function _getMinReqAssetValue(
        uint256[] memory debtPools,
        uint256[] memory debtValuleForPool,
        address[] memory positionAssets,
        uint256[] memory wt,
        address position
    ) internal view returns (uint256) {
        uint256 minReqAssetValue;

        // O(pools.len * positionAssets.len)
        uint256 debtPoolsLength = debtPools.length;
        uint256 positionAssetsLength = positionAssets.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
            for (uint256 j; j < positionAssetsLength; ++j) {
                uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);

                // revert with pool id and the asset that is not supported by the pool
>               if (ltv == 0) revert RiskModule_UnsupportedAsset(position, debtPools[i], positionAssets[j]);

                // debt is weighted in proportion to value of position assets. if your position
                // consists of 60% A and 40% B, then 60% of the debt is assigned to be backed by A
                // and 40% by B. this is iteratively computed for each pool the position borrows from
                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
            }
        }

        if (minReqAssetValue == 0) revert RiskModule_ZeroMinReqAssets();
        return minReqAssetValue;
    }
```

This presents a challenge for position owners seeking to combine multiple assets and employ leverage for more advanced borrowing strategies.

## Impact
This reduces the sophistication and scope of position activities, restricting the use of collateral assets, which in turn can influence market movements.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L84

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L250-L279

## Tool used
Manual Review

## Recommendation
Create a more advanced strategy to ensure debts are adequately backed. This can be achieved by excluding the corresponding asset from the collateral calculation for each specific debt. Additionally, care must be taken when liquidating positions, especially while reallocating assets.