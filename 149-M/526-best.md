Damaged Malachite Gibbon

Medium

# Incorrect Calculation of Pool's Total Liquidity

## Summary
There is a miscalculation when determining the total liquidity of the `POOL` (BasePool). If the actual asset balance of `POOL` (`Asset.balanceOf(POOL)`) is less than the asset difference of any individual pool (`pool.totalDepositAssets - pool.totalBorrowAssets`), the total liquidity does not accurately reflect the aggregate liquidity of all pools.

## Vulnerability Detail
In the `SuperPool` contract, there's a function designed to return the maximum amount of assets a user can withdraw. During this process, it calculates the `totalLiquidity` of the BasePool to get the actual available amount. This calculation involves summing up the liquidities of all deposit pools, which can lead to inaccuracies in certain scenarios. We observe similar considerations within the `getLiquidityOf` function:

```solidity
    function getLiquidityOf(uint256 poolId) public view returns (uint256) {
        PoolData storage pool = poolDataFor[poolId];
        uint256 assetsInPool = pool.totalDepositAssets - pool.totalBorrowAssets;
>       uint256 totalBalance = IERC20(pool.asset).balanceOf(address(this));
        return (totalBalance > assetsInPool) ? assetsInPool : totalBalance;
    }
```

Since they all originate from a single base pool, it would be incorrect if the basePoolBalance is less than that of any individual pool.

```solidity
    function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
>           totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool

        // return the minimum of totalLiquidity and _owner balance
        uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
        return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
```

## Impact
As the `_maxWithdraw` function returns an inaccurate amount, the `maxWithdraw` and `maxRedeem` functions will also yield incorrect values. Consequently, any subsequent withdrawal or redemption attempts are likely to fail.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L210-L215

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L474-L485

## Tool used
Manual Review

## Recommendation
The totalLiquidity of the BasePool should ultimately be compared with the actual asset balance which is `ASSET.balanceOf(address(POOL))`.

```diff
    function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
        }
+       uint256 basePoolBalance = ASSET.balanceOf(address(POOL));
+       totalLiquidity = basePoolBalance > totalLiquidity ? totalLiquidity : basePoolBalance;

        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool

        // return the minimum of totalLiquidity and _owner balance
        uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
        return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
```