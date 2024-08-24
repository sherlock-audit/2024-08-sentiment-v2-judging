Crazy Sapphire Mandrill

Medium

# `maxWithdraw` does not actually returns the maximum amount of assets that can be withdrawn by a depositor Due to Stale Pool State

## Summary

## Vulnerability Detail

The `maxWithdraw` function in` SuperPool.sol` is intended to return the maximum amount of assets that can be withdrawn by a depositor.
```solidity
/// @notice Fetch the maximum amount of assets that can be withdrawn by a depositor
    function maxWithdraw(address owner) public view returns (uint256) {
        (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();//@audit-this does not update pool.totalDepositAssets and pool.totalBorrowAssets
        return _maxWithdraw(owner, newTotalAssets, totalSupply() + feeShares);
    }
```

 However, it does not actually return the maximum amount because it relies on the `getLiquidityOf` function in Pool.sol,
 which does not call the `accrue` function to update the pool state before calculating liquidity.
 ```solidity
 function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);//@audit-returns stale value
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool

        // return the minimum of totalLiquidity and _owner balance
        uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
        return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
 ``` 
As a result, the pool's `totalDepositAssets` and `totalBorrowAssets` may be outdated, leading to an incorrect calculation of available liquidity. basically `getLiquidityOf()` function Fetchs amount of liquid assets currently held in a given pool,but it does not call the `accrue` function, which updates the `totalDepositAssets` and `totalBorrowAssets`. 
```solidity
/// @dev update pool state to accrue interest since the last time accrue() was called
function accrue(PoolData storage pool, uint256 id) internal {
    (uint256 interestAccrued, uint256 feeShares) = simulateAccrue(pool);

    if (feeShares != 0) _mint(feeRecipient, id, feeShares);

    // update pool state
    pool.totalDepositShares += feeShares;
    pool.totalBorrowAssets += interestAccrued;
    pool.totalDepositAssets += interestAccrued;

    // store a timestamp for this accrue() call
    // used to compute the pending interest next time accrue() is called
    pool.lastUpdated = uint128(block.timestamp);
}
```
let's understand with example
```solidity
Example Scenario
Consider a scenario where a pool has the following state:

totalDepositAssets: 1000
totalBorrowAssets: 200
If the pool has accrued interest since the last update, the actual values might be:

totalDepositAssets: 1100 (1000 + 100 interest)
totalBorrowAssets: 220 (200 + 20 interest)
However, since getLiquidityOf does not call accrue, it will use the outdated values:

totalDepositAssets: 1000
totalBorrowAssets: 200
This results in an incorrect calculation of available liquidity:

assetsInPool = 1000 - 200 = 800
The correct calculation should be:

assetsInPool = 1100 - 220 = 880
Thus, the maxWithdraw function will return a lower value than the actual maximum withdrawable amount.
```


## Impact

`maxWithdraw` function underestimates the maximum amount of assets that can be withdrawn by a depositor. This can lead to users being unable to withdraw the full amount of assets they are entitled to

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L219C4-L223C6

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L474C4-L486C1

## Tool used

Manual Review

## Recommendation
ensure that the pool state is updated by calling the `accrue` function in `getLiquidityOf` which updates the `pool.totalDepositAssets` and `pool.totalBorrowAssets`