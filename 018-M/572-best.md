Flat Tawny Haddock

Medium

# Setting `minDebt` and `minBorrow` to low values can cause protocol to accrue bad debt

## Summary
Setting `minDebt` and `minBorrow` to low values can cause protocol to accrue bad debt as liquidators won't find enough incentive in clearing the low debt and also depending on the price, users may be able to borrow dust without providing collateral

## Vulnerability Detail
`minDebt` and `minBorrow` are supposed to be settable from 0

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/tree/main?tab=readme-ov-file#q-are-there-any-limitations-on-values-set-by-admins-or-other-roles-in-the-codebase-including-restrictions-on-array-lengths)
```solidity
Min Debt = from 0 to 0.05 ETH = from 0 to 50000000000000000
Min Borrow = from 0 to 0.05 ETH = from 0 to 50000000000000000
```

Setting these to low values will allow positions to be created with low debts and liquidations won't happen on small positions due to it not generating enough profit to cover the costs of the liquidator. This will cause the protocol to accure bad debt. 
Also if both are set to dust, the roundings will become significant and allows one to borrow dust amounts without proper collateral. Eg, if both are set to 0 and the price of assets is less than that of eth, the borrowing 1 wei of the assets will require no collateral as the value in eth will be rounded to 0  

## Impact
Protocol can accrue bad debt leading to depositors loosing their assets in case the values are set low

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/tree/main?tab=readme-ov-file#q-are-there-any-limitations-on-values-set-by-admins-or-other-roles-in-the-codebase-including-restrictions-on-array-lengths

## Tool used
Manual Review

## Recommendation
Ensure the `minDebt`,`minBorrow` values are not decreased below a certain threshold