Flat Tawny Haddock

Medium

# Depositors unfairly pay fees for the unaccrued interest during bad debt

## Summary
Depositors unfairly pay fees for the unaccrued interest for bad debt position as feeShares is minted earlier

## Vulnerability Detail
Fees are collected from depositors on each interest accrual inside the `accrue` function. But this fees is minted even for a position in bad debt although it doesn't actually earn any interest and that part if going to be cleared within the call
```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        PoolData storage pool = poolDataFor[poolId];
        // @audit feeShares minted here itself considering interest accrual for the bad debt position too
=>      accrue(pool, poolId);

        ....
        // @audit no interest is actually accrued since the position is in bad debt and its balance is simply cleared
        uint256 borrowAssets = _convertToAssets(borrowShares, totalBorrowAssets, totalBorrowShares, Math.Rounding.Up);


        // rebalance bad debt across lenders
        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
```

Example Scenario:
Total assets = 200, bad debt to be cleared = 100, total debt = 100
let the interest gained be 5 in the timeperiod and corresponding fees be 1
if the initial shares were 200, inside the accrue, it will result in the minting of 1 * (200/204) == 0.980392157 shares as fees so as to correspond to 1 amount of asset. but since this intereset is not actually accrued (because it is corresponding to the bad debt), the depositors will end up having 200 - 100 units of assets with an additional lose in share value because the feeShares have been minted
so if the feeShares have not been minted earlier, then each depositor would get 100/200 == 0.5, while now the depositors would be getting 100/(200 + 0.980392157) == 0.497560976
 
## Impact
Depositors will be charged unfair amount of assets as fees

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L528-L547

## Tool used
Manual Review

## Recommendation
Perform the bad debt adjustment before the interest accrual is calculated. For this the accrual function would have to modified if the interest accrued for the other positions should be according to the utlization ratio including the bad debt borrow 