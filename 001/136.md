Spicy Amethyst Ram

Medium

# Unallocated assets can lead to inflated shares

## Summary

The _deposit function in the SuperPool contract updates lastTotalAssets based on the assumption that all deposited assets are successfully allocated to underlying pools. However, if some assets remain unallocated due to pool caps being reached, the current implementation still increments lastTotalAssets by the total deposit amount, leading to a mismatch between reported and actual asset utilization.

## Vulnerability Detail

In the _deposit function:

`function _deposit(address receiver, uint256 assets, uint256 shares) internal {
    // ... other checks ...
    ERC20._mint(receiver, shares);
    _supplyToPools(assets);
    lastTotalAssets += assets; 
    emit Deposit(msg.sender, receiver, assets, shares);
}`

The `_supplyToPools` function attempts to allocate the assets across multiple pools. If deposits fail or pools are full, it continues to try subsequent pools. However, if it can't allocate all assets after trying all pools, the remaining assets will be left unallocated. The _deposit function doesn't check how many assets were actually allocated before incrementing lastTotalAssets, potentially leading to an overstatement of actively deployed assets.


Here is an example; 

Assume there are only 10 pools in the deposit queue, each with a cap of 100 assets.

User tries to deposit 500 assets 

`_supplyToPools(assets);` attempts to allocate deposits across these pools.


| **Pool** | **Cap** | **Current Assets** | **Allocated Assets** | **Remaining Deposit** |
|----------|---------|--------------------|----------------------|------------------------|
| Pool 1   | 100     | 90                 | 10                   | 490                    |
| Pool 2   | 100     | 80                 | 20                   | 470                    |
| Pool 3   | 100     | Full                | -                    | 470                    |
| Pool 4   | 100     | Full                | -                    | 470                    |
| Pool 5   | 100     | Full                | -                    | 470                    |
| Pool 6   | 100     | 95                 | 5                    | 465                    |
| Pool 7   | 100     | Full                | -                    | 465                    |
| Pool 8   | 100     | 90                 | 10                   | 455                    |
| Pool 9   | 100     | 70                 | 30                   | 425                    |
| Pool 10  | 100     | 85                 | 15                   | 410                    |


The total cap across all pools: 10×100 = 1000 assets

Initial lastTotalAssets: 910 assets (sum of all assets currently in pools).


After Allocation:

Total Allocated: 10 + 20 + 5 +10 + 30 + 15 = 90 assets. 

Remaining Unallocated Assets: 500 − 90 = 410 assets

lastTotalAssets is incremented by the full deposit amount: 910 + 500 = 1410 assets

lastTotalAssets = 1410 


Reality Check:

Only 90 of the deposited 500 assets were allocated to the pools.

The unallocated 410 assets are sitting idle in the contract

The actual active assets in Pools:  910 + 90 = 1000 assets

lastTotalAssets should be = 1000 

but the current implementation makes it: 1400 

Discrepancy:  1410 − 1000 = 410  assets

This shows how about 410 assets will be sitting idle in the contract without being utilised for anything (not in any of the pool)

Now, here is the problem, since the shares are minted before the _supplyToPools function attempts to allocate the assets, they will be minted based on the assumption that the user assets are actively deployed to the pool.


## Impact

The protocol incorrectly reports lastTotalAssets as the total amount of actively deployed assets, as it doesn't catch idle assets, which will lead to an overestimation of lastTotalAssets

Also shares are minted based on the full deposit amount, including these idle assets, which do not generate returns, this may lead to dilution of the shares


## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L503C9-L503C23

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L524

## Tool used

Manual Review

## Recommendation

Introduce a check after the _supplyToPools function to determine if all assets have been successfully allocated. If any assets remain unallocated, revert the transaction to ensure that lastTotalAssets only reflects assets that are actively deployed to the pools

