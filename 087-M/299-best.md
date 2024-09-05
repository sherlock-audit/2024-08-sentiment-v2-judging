Bitter Sandstone Worm

High

# Exploiter can force user into unhealthy condition and liquidate him

### Summary

Protocol implements a flexible cross-margin portfolio managment with the help of `Position` smart contract, which should hold borrower's collateral and debt positions. 
Anyone can open a pool in the singleton `Pool` contract and chose valid collateral assets with corresponding LTV values by calling `RiskEngine#requestLtvUpdate -> acceptLtvUpdate`. In the README it is stated that the bound for valid LTVs would be in the range 10%-98%
There is a flaw in the way risk module calculates whether a position is healthy. 

### Root Cause

The problem roots is that `_getPositionAssetData` uses [getAssetValue](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L183-L185), which uses `IERC20(asset).balanceOf(position)` to obtain the tokens for the given asset in user's position:
```solidity
    function getAssetValue(address position, address asset) public view returns (uint256) {
        IOracle oracle = IOracle(riskEngine.getOracleFor(asset));
        uint256 amt = IERC20(asset).balanceOf(position);
        return oracle.getValueInEth(asset, amt);
    }
```
Later, when we calculate the `minRequired` collateral for given debt, we use a wighted average tvl based on the weights in the user position:
```solidity
                // debt is weighted in proportion to value of position assets. if your position
                // consists of 60% A and 40% B, then 60% of the debt is assigned to be backed by A
                // and 40% by B. this is iteratively computed for each pool the position borrows from
                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up)
```
The problem is that expoiter may donate funds to user position with the collateral asset with the lowest LTV, which will manipulate [_getMinReqAssetValue](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L250) calculation and may force the user into liquidation, where the expoiter will collect the donated funds + user collateral + discount.

### Internal pre-conditions

1. Borrower should have an asset portfolio with one asset with low LTV and other with large LTV.
2. Borrower should have most of his portfolio value in the asset with higher LTV 
3. Borrower should have an active loan and be close to liquidation, but still healthy

### External pre-conditions

Nothing special

### Attack Path

Imagine the following scenario:
We use $ based calculations for simplicity, but this does not matter for the exploit.
We also have simplified calculations to simple decimals (100% = 100) to remove unnececarry for this case complexity.

Precondition state:
Victim Position Asset Porfolio: [USDC = $1000; WBTC = $10]
Pool 1: [Leding Asset = DAI] [USDC tvl = 95%; WBTC tvl = 30%]

1. Victim borrows $940 DAI from pool 1 against his portfolio from above (`minReqAssetValue = (940 * 99 / 95) + (940 * 1 / 30) = 979 + 31 ~= $1 010`)
2. User position is healthy and collateral value is exactly the `minReqAssetValue`
Attack beggins:
3. Attacker take a flashloan of $990 WBTC and transfer it to the victim's position (WBTC has 30% ltv for this debt pool)
4. When he calls `liquidate`, we enter `validateLiquidation` -> `isPositionHealthy`, where we get each asset value and weight:
- We have  `totalAssetValue = $2000` `positinAssets = [USDC; WBTC]` , `positionAssetWeight = [50; 50]`
- We  pass those params to `_getMinReqAssetValue` and we iterate two times for the single $940 debt and here is the result
-  - 1st iteration (USDC): `minReqAssetValue += 940 * 50 / 95 = 494`
-  - 2nd iteration (WBTC) `minReqAssetValue += 940 * 50 / 30 = 1 566`
-  Result ~= `494 + 1 566 = $2 060` , which is `$60 > totalAssetValue`, which means that position is not healthy.
5. Liquidator has provided to repay all 940 against all collateral + the donated WBTC = $1000 USDC + $1000
6. His transaction passes and he has made profit, he rapays the flash loan

## Recommendation

Introduce virtual balance inside `position`, which is updated on deposit/withdraw actions. This will prevent manipulations of the weighted average tvl due to donations.

### Impact

Unfair liquidations, which in normal situations may never occur, result in the theft of user collateral.

### PoC

_No response_

### Mitigation

Introduce virtual balance inside position, which is updated on deposit/withdraw actions. This will prevent manipulations of the weighted average tvl due to donations. 
