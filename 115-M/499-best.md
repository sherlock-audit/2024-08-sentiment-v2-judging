Soaring Malachite Trout

High

# Incorrect Implementation of Kinked Interest Rate Model Leading to Overestimated Borrowing Costs which can also lead to early liquidations

## Summary
The current implementation of the `getInterestRate` function may produce interest rates significantly higher than intended according to standard kinked interest rate models. 

## Vulnerability Detail
Issue:  the implementation of this function might not accurately follow the kinked rate model as described in the references. Specifically, the function may overestimate the interest rates due to incorrect application of the formula or parameters.

Reference: According to the kinked interest rate model from Compound Protocol and related documentation, the interest rate calculation involves distinct base rates

Potential Impact: Borrowers may be charged excessively high rates compared to the intended design

check out the kinked rate model section: https://arxiv.org/pdf/2006.13922

Explanation:
here i am comparing the intrest rate of both the compound implementation and sentiment implementation

`when the utilization ratio is less than Borrow Kinked rate`
Sentiment forumla:
```solidity 
return MIN_RATE_1 + SLOPE_1.mulDiv(util, OPTIMAL_UTIL, Math.Rounding.Down)
```
 `totalBorrows = 50`
- `totalAssets = 100`
- `MIN_RATE_1 = 0.01` (as a percentage, converted to `1e16` when scaled by `1e18`)
- `SLOPE_1 = 0.1` (as a percentage, converted to `1e17` when scaled by `1e18`)
- `OPTIMAL_UTIL = 80%` (as a percentage, converted to `8e17` when scaled by `1e18`)

``` 1e16 + 1e17 × 5/8 => 1e16+6.25e16=7.25e16 ```
so rate is 7.25% 

compound forumla:
- `util = 0.5` (as a percentage, converted to `5e17` when scaled by `1e18`)
- `multiplierPerBlock = 0.1` (as a percentage, converted to `1e17` when scaled by `1e18`)
- `BASE = 1e18`
- `baseRatePerBlock = 0.01` (as a percentage, converted to `1e16` when scaled by `1e18`)
- `kink = 80%` (as a percentage, converted to `8e17` when scaled by `1e18`)

``` (5e34/1e18) + 1e16 => 5e16 + 1e16 = 6e16 ```

so rate is 6%

so for the utlization rate is under `Borrow kink` then it is calculating 1.25% extra

`when the utilization ratio is more than Borrow Kinked rate`
sentiment formula:
- `totalBorrows = 90`
- `totalAssets = 100`
- `MIN_RATE_1 = 0.01` (as a percentage, converted to `1e16` when scaled by `1e18`)
- `MIN_RATE_2 = 0.01` (as a percentage, converted to `1e16` when scaled by `1e18`)
- `SLOPE_1 = 0.1` (as a percentage, converted to `1e17` when scaled by `1e18`)
- `SLOPE_2 = 0.4` (as a percentage, converted to `4e17` when scaled by `1e18`)
- `OPTIMAL_UTIL = 80%` (as a percentage, converted to `8e17` when scaled by `1e18`)
- `MAX_EXCESS_UTIL = 1e18 - OPTIMAL_UTIL = 2e17` (which corresponds to `20%` when scaled by `1e18`)

``` 1e16+4e17 X 1e17/2e17 = 1e16+4e17×0.5=1e16+2e17=2.1e17 ```
 rate is 2.1e17, which corresponds to 0.21 or 21%

compound forumla:
- `util = 0.9` (as a percentage, converted to `9e17` when scaled by `1e18`)
- `multiplierPerBlock = 0.1` (as a percentage, converted to `1e17` when scaled by `1e18`)
- `BASE = 1e18`
- `baseRatePerBlock = 0.01` (as a percentage, converted to `1e16` when scaled by `1e18`)
- `kink = 80%` (as a percentage, converted to `8e17` when scaled by `1e18`)
- `jumpMultiplierPerBlock = 0.4` (as a percentage, converted to `4e17` when scaled by `1e18`)

``` (1e17 X 4e17/1e18) + 9e16 => 4e16+9e16=1.3e17 ```

, which corresponds to 0.13 or 13%.
so for the utlization rate is above `Borrow kink` then it is calculating 8% extra

## Impact
- Overestimated Borrowing Costs: Users may experience higher borrowing costs than anticipated due to inflated interest rates.
- if rate increase much faster there is high chances of positions to get liquidate fast as the debt amount + interest acquired will be much higher, then value of collateral deposited by position will pass the threshold(the loan accrues interest and has a larger notional value)
- https://www.rareskills.io/post/defi-liquidations-collateral 

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/irm/KinkedRateModel.sol#L58
```solidity
function getBorrowRateInternal(uint cash, uint borrows, uint reserves) internal view returns (uint) {
    uint util = utilizationRate(cash, borrows, reserves);

    if (util <= kink) {
        return ((util * multiplierPerBlock) / BASE) + baseRatePerBlock;
    } else {
        uint normalRate = ((kink * multiplierPerBlock) / BASE) + baseRatePerBlock;
        uint excessUtil = util - kink;
        return ((excessUtil * jumpMultiplierPerBlock) / BASE) + normalRate;
    }
}
```
## Tool used

Manual Review

## Recommendation
Review and Align with Expected kinked rate Model