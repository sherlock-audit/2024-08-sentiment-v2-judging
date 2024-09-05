Massive Seafoam Eel

Medium

# Lack of slippage protection during withdrawal in SuperPool and Pool contracts.

## Summary
Lack of slippage protection in the SuperPool and Pool could lead to loss of user funds in an event of bad debt liquidation.
## Vulnerability Detail
When a user who has deposited assets in one of the pools of the Pool.sol contract wishes to withdraw them, they can do so by calling `withdraw()`. Under normal conditions, user expects to receive the full deposited amount back or more if the interest accrues in the underlying pool. However, if the pool experiences bad debt liquidation, the totalAssets of the pool are reduced by the amount of bad debt liquidated and the exchange rate worsens.
[Pool.sol#L542-L547](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L542-L547)
```solidity
// rebalance bad debt across lenders
pool.totalBorrowShares = totalBorrowShares - borrowShares;
// handle borrowAssets being rounded up to be greater than totalBorrowAssets
pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets)
    ? totalBorrowAssets - borrowAssets
    : 0;
uint256 totalDepositAssets = pool.totalDepositAssets;
pool.totalDepositAssets = (totalDepositAssets > borrowAssets)   <<@
    ? totalDepositAssets - borrowAssets  <<@
    : 0;
```
When a user withdraws, if the pool experiences bad debt liquidation, while the transaction is pending in the mempool, they will burn more shares than they expected.

Consider the following scenario:
* pool.totalAssets = 2000.
* pool.totalShares = 2000.
* Bob wants to withdraw 500 assets, expecting to burn 500 shares.
* While Bob's transaction is pending in the mempool, the pool experiences a bad debt liquidation and `totalAssets` drops to 1500.
* When Bob's transaction goes through, he will burn `500 * 2000 / 1500 = 666.66` shares.

The same issue is present in the SuperPool contract, as the `totalAssets()` of the SuperPool is dependant on the total amount of assets in the underlying pools a SuperPool has deposited into.

[SuperPool.sol#L180-L189](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L180-L189)
```solidity
function totalAssets() public view returns (uint256) {
    uint256 assets = ASSET.balanceOf(address(this));
    uint256 depositQueueLength = depositQueue.length;
    for (uint256 i; i < depositQueueLength; ++i) {
        assets += POOL.getAssetsOf(depositQueue[i], address(this));
    }
    return assets;
}
```
[Pool.sol#L218-L227](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L218-L227)
```solidity
function getAssetsOf(
    uint256 poolId,
    address guy
) public view returns (uint256) {
    PoolData storage pool = poolDataFor[poolId];
    (uint256 accruedInterest, uint256 feeShares) = simulateAccrue(pool);
    return
        _convertToAssets(
            balanceOf[guy][poolId],
            pool.totalDepositAssets + accruedInterest,
            pool.totalDepositShares + feeShares,
            Math.Rounding.Down
        );
}
```
When redeeming in the SuperPool, a user will either burn more shares when using `withdraw()` or receive less assets when using `redeem()`.
## Impact
`withdraw()` in the Pool.sol and both `redeem`/`withdraw` in the SuperPool lack slippage protection, which can lead to users loosing funds in the even of bad debt liquidation.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L339-L372
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L281-L286
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L293-L298
## Tool used

Manual Review

## Recommendation
Introduce minimum amount out for `redeem()` function and maximum shares in for `withdraw()` function as means for slippage protection.