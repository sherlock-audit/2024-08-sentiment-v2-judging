Genuine Lemonade Gerbil

Medium

# SuperPool doesn't strictly comply with ERC-4626.

## Summary
`SuperPool.maxWithdraw()` and `SuperPool.maxRedeem()` functions returns incorrect values.
This means `SuperPool` doesn't strictly comply with ERC-4626.

## Vulnerability Detail
`SuperPool.maxWithdraw()` and `SuperPool.maxRedeem()` functions calls the following `_maxWithdraw()` function.
```solidity
    function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
478:        totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool

        // return the minimum of totalLiquidity and _owner balance
483:    uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
484:    return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
```
As can be seen, the above function use liquidity of pool as withdrawable maximum assets in `L478`.

On the other hand, `SuperPool.withdraw()` and `SuperPool.redeem()` function calls `_withdraw()` function and `_withdraw()` function calls in turn the following `_withdrawFromPools()` function to withdraw assets from deposited pools.
```solidity
548:function _withdrawFromPools(uint256 assets) internal {
        uint256 assetsInSuperpool = ASSET.balanceOf(address(this));

        if (assetsInSuperpool >= assets) return;
        else assets -= assetsInSuperpool;

        uint256 withdrawQueueLength = withdrawQueue.length;
        for (uint256 i; i < withdrawQueueLength; ++i) {
            uint256 poolId = withdrawQueue[i];
            // withdrawAmt -> max assets that can be withdrawn from the underlying pool
            // optimistically try to withdraw all assets from this pool
            uint256 withdrawAmt = assets;

            // withdrawAmt cannot be greater than the assets deposited by the pool in the underlying pool
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));
563:        if (assetsInPool < withdrawAmt) withdrawAmt = assetsInPool;

            // withdrawAmt cannot be greater than the underlying pool liquidity
            uint256 poolLiquidity = POOL.getLiquidityOf(poolId);
567:        if (poolLiquidity < withdrawAmt) withdrawAmt = poolLiquidity;

            if (withdrawAmt > 0) {
                try POOL.withdraw(poolId, withdrawAmt, address(this), address(this)) {
                    assets -= withdrawAmt;
                } catch { }
            }

            if (assets == 0) return;
        }

        // We explicitly check assets == 0, and if so return, otherwise we revert directly here
        revert SuperPool_NotEnoughLiquidity(address(this));
    }
```
As can be seen, the above function use minimum of `assetsInPool` and `poolLiquidity` as withdrawable maximum assets (`L563` and `L567`) which is less than the value of `_maxWithdraw()` function.

PoC:
1. `pool1` has `100` total deposited shares, `1000` total deposited assets and `500` total borrowed assets. So `pool1` has `1000 - 500` liquidity.
2. `pool2` has `100` total deposited shares, `1000` total deposited assets and `1000` total borrowed assets. So `pool2` has `1000 - 1000 = 0` liquidity.
3. `SuperPool` has `10` shares in the `pool1` and `10` shares in the `pool2`.
4. `SuperPool` has `100` total supply(total shares) and a user has `100` shares in `SuperPool` which means that the user has `100%` shares of `SuperPool`.
5. Therefore the user and `SuperPool` has `10 * 1000 / 100 + 10 * 1000 / 100 = 200` total assets in the underlying pools which is equal to `userAssets` of `L483` and `assets` of `L548`.
6. `totalLiquidity` of `L484` is `0 + 500 = 500` and `_maxWithdraw()` returns `min(200, 500) = 200`.
7. `withdrawAmt` of `L567` is `min(500, 100) = 100` for `pool1` and `min(0, 100) = 0` for `pool2`. Therefore `_withdrawFromPools()` function withdraw totally `100` assets from underlying pools which is smaller than `200` of `_maxWithdraw()` function.

## Impact
The `README.md#L161` stated as follows.
```md
SuperPool.sol is strictly ERC4626 compliant
```
However SuperPool doesn't strictly comply with ERC-4626.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L478

## Tool used

Manual Review

## Recommendation
Modify `SuperPool._maxWithdraw()` function as follows.
```solidity
    function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
--          totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
++          totalLiquidity += Math.min(POOL.getLiquidityOf(depositQueue[i]), POOL.getAssetsOf(depositQueue[i], address(this)));
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool

        // return the minimum of totalLiquidity and _owner balance
        uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
        return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
```