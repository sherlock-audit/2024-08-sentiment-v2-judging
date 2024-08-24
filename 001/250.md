Expert Nylon Leopard

Medium

# Incorrect Asset Check in SuperPool whenever we want to Deposit into Any POOL Contract.

## Summary
The SuperPool contract contains an error in its asset-checking logic during deposit operations. Instead of querying the total assets in the pool, it incorrectly checks only the assets deposited by the SuperPool itself. This can result in multiple failed attempts to deposit because exceeding the pool cap is highly possible. 

## Vulnerability Detail
The SuperPool contract currently uses the wrong method to check the total assets available in the underlying pool before performing a deposit. The function `getAssetsOf(poolId, address(this))` is used to query the assets deposited by the SuperPool itself, rather than querying the total assets in the pool (`getTotalAssets`). This leads to an incorrect comparison when checking if the total deposit exceeds the pool cap, potentially allowing deposits that should be reverted.


## Impact
### Impact

The incorrect asset check can result in the SuperPool incorrectly determining that a deposit is within the pool cap when it is not. As a result, the SuperPool might attempt to deposit funds into the underlying pool, but the pool will reject the transaction because the cap has actually been exceeded. 

### Problematic Code:

The following is a summary of the incorrect checks:

1. **Rebalance Check:**
 
```solidity

@audit >>>>>    uint256 assetsInPool = POOL.getAssetsOf(deposits[i].poolId, address(this));
 
  if (assetsInPool + deposits[i].assets < poolCap) {
       ASSET.approve(address(POOL), deposits[i].assets);
       POOL.deposit(deposits[i].poolId, deposits[i].assets, address(this));
   }
 ```

2. **Deposit Check:**

```solidity

@audit >>>>>      uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));
@audit >>>>>        if (assetsInPool < poolCapFor[poolId]) {

       uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
       if (assets < supplyAmt) supplyAmt = assets;
   }
 ```

These checks incorrectly compare the amount of assets deposited by the SuperPool with the pool's cap, rather than considering the entire pool's total assets.

 ```solidity

  @audit >> SEE >>>         /// @notice Fetch pool asset balance for depositor to a pool
                                       function getAssetsOf(uint256 poolId, address guy) public view returns (uint256) {
                                            PoolData storage pool = poolDataFor[poolId];
                                             (uint256 accruedInterest, uint256 feeShares) = simulateAccrue(pool);
                                              return _convertToAssets(
                                              balanceOf[guy][poolId],
                                             pool.totalDepositAssets + accruedInterest,
                                              pool.totalDepositShares + feeShares,
                                                  Math.Rounding.Down
        );
    }

   ```

**Ideal Check in Pool contract deposit function** 

  ```solidity   

     function deposit(uint256 poolId, uint256 assets, address receiver) public returns (uint256 shares) {
        PoolData storage pool = poolDataFor[poolId];

        if (pool.isPaused) revert Pool_PoolPaused(poolId);

        // update state to accrue interest since the last time accrue() was called
        accrue(pool, poolId);

        // Need to transfer before or ERC777s could reenter, or bypass the pool cap
        IERC20(pool.asset).safeTransferFrom(msg.sender, address(this), assets);

@audit >> Check >>>            if (pool.totalDepositAssets + assets > pool.poolCap) revert Pool_PoolCapExceeded(poolId);
  
```

**totalDepositAssets + assets should be compared not borrowed asset for superpool and asset to cap .**


   ```solidity
  /// @notice Fetch the total amount of assets currently deposited in a pool
    function getTotalAssets(uint256 poolId) public view returns (uint256) {
        PoolData storage pool = poolDataFor[poolId];
        (uint256 accruedInterest,) = simulateAccrue(pool);
        return pool.totalDepositAssets + accruedInterest;
    }
   ```

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L320

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L528

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L448



https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L217-L226

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L242-L247

## Tool used

Manual Review

## Recommendation

To accurately enforce the pool cap, you should query the total assets in the pool by using the `getTotalAssets` function, which returns the correct value after accounting for all deposits and accrued interest. This ensures the check is performed against the actual total assets in the pool, not just those deposited by the SuperPool.

Replace the incorrect checks with queries to `getTotalAssets`:

1. **Corrected Rebalance Check:**

   ```solidity
   uint256 totalAssetsInPool = POOL.getTotalAssets(deposits[i].poolId);
   if (totalAssetsInPool + deposits[i].assets < poolCap) {
       ASSET.approve(address(POOL), deposits[i].assets);
       POOL.deposit(deposits[i].poolId, deposits[i].assets, address(this));
   }
   ```

2. **Corrected Deposit Check:**

 ```solidity
   uint256 totalAssetsInPool = POOL.getTotalAssets(poolId);
   if (totalAssetsInPool < poolCapFor[poolId]) {
       uint256 supplyAmt = poolCapFor[poolId] - totalAssetsInPool;
       if (assets < supplyAmt) supplyAmt = assets;
   }
 ```
