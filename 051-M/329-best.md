Large Misty Snake

High

# An illiquid pool will DOS all superPool withdrawals

## Summary
The `getLiquidityOf()` function will revert for illiquid pools (pools where `totalBorrowAssets` exceed `totalDepositAssets`, this revert will DOS the `withdraw()` function in SuperPools which checks for liquidity of pools added to it before withdrawing from them.

## Vulnerability Detail
Users can withdraw from a superPool by calling the `withdraw` function with the amount of `assets` they want to withdraw, this calls the internal `_withdraw` function which  subsequently calls `_withdrawFromPools` with the desired assets, if the assets in the pool are not enough to fulfil this request, the children pools are looped through and used
There is however a check for pool Liquidity which will revert from underflow
1. `withdraw` --> `_withdraw` --> `_withdrawFromPools`
```solidity
    function _withdrawFromPools(uint256 assets) internal {
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
            if (assetsInPool < withdrawAmt) withdrawAmt = assetsInPool;

            // withdrawAmt cannot be greater than the underlying pool liquidity
            uint256 poolLiquidity = POOL.getLiquidityOf(poolId); //@audit <= will revert here
            if (poolLiquidity < withdrawAmt) withdrawAmt = poolLiquidity; 
            
```



the calculation of this from the pool is 

```solidity
    /// @notice Fetch amount of liquid assets currently held in a given pool
    function getLiquidityOf(uint256 poolId) public view returns (uint256) {
        PoolData storage pool = poolDataFor[poolId];
        uint256 assetsInPool = pool.totalDepositAssets - pool.totalBorrowAssets; 
        uint256 totalBalance = IERC20(pool.asset).balanceOf(address(this)); 
        return (totalBalance > assetsInPool) ? assetsInPool : totalBalance; 
    }
```


in a situation where a pool becomes illiquid due to (pool.totalBorrowAssets > pool.totalDepositAssets) all calls to this function will revert.

## Impact
Users will be unable to withdraw their assets from a superPool

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L548-L573

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L210-L215

## Tool used
Manual Review

## Recommendation
Modify the `getLiquidityOf` function to prevent underflow(revert) in any circumstance or add the liquidity check to the `try-catch` incase it reverts.