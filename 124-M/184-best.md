Keen Jetblack Turtle

High

# Incorrect Calculation of `_minRequestedValue` Exposes Healthy Positions to Liquidation and Prevents Full Borrowing/Withdrawal

## Summary
The `_getMinReqAssetValue` function incorrectly calculates the minimum required asset value, leading to an overestimation of `minReqAssetValue`.

## Vulnerability Detail
- The protocol allows positions to use  multiple type of tokens (up to 5) as collateral. each collateral/pool have different **LTV** which is a percentage of the collateral value that can be borrowed.
- after each action done by a position we should check that the position is  healthy which is crucial check. 
- for a positon to be healthy we should check that the `minReqAssetValue` is less then the collateral value of that position.

```solidity
    function isPositionHealthy(address position) public view returns (bool) {
        // some code ... 
   >>   uint256 minReqAssetValue = _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);
   >>   return totalAssetValue >= minReqAssetValue;
    }
```
```js

    function _getMinReqAssetValue(
        uint256[] memory debtPools,
        uint256[] memory debtValuleForPool,
        address[] memory positionAssets,
        uint256[] memory wt,
        address position
    ) internal view returns (uint256) {
        uint256 minReqAssetValue;

        // O(pools.len * positionAssets.len)
        uint256 debtPoolsLength = debtPools.length;
        uint256 positionAssetsLength = positionAssets.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
            for (uint256 j; j < positionAssetsLength; ++j) {
                uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);

                // revert with pool id and the asset that is not supported by the pool
                if (ltv == 0) revert RiskModule_UnsupportedAsset(position, debtPools[i], positionAssets[j]);

                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
            }
        }
    }
```
- To compute the `minReqAssetValue` for a debt to be healthy. If we convert the function into its mathematical representation. It will be the equivalent to this (we are simplifing it by only taking the formula for a single debt pool)
Let:
- $DV = \text{debtValuleForPool}[0]$

- $DP = \text{debtPools}[0]$

- $\text{PAL} = \text{length of } \text{positionAssets}$

- $\text{positionAssets}[j] = PA_j$

- $wt[j] = w_j$

- $\text{ltvFor}(DP, PA_j) = ltv_j$

- $\text{minReqAssetValue} = \text{MAV}$

- $\lceil x \rceil$ denotes the ceiling function, rounding $x$ up to the nearest integer.

The function calculates $\text{MAV}$ as follows:

$$
\text{MAV} = \sum_{j=0}^{\text{PAL}-1} \left( \left\lceil \frac{DV \cdot w_j}{ltv_j} \right\rceil \right)
$$

1. First equation (how the code is currently implemented) could be simplified to this:
```math
   $$
   \text{MAV} = DV \times {\sum_{j=0}^{n} \frac{w_j}  {\text{ltv}_j}}
   $$
```
2. The above expression is not equal to the total value divided by the weighted average ltv (how it should be calculated):
```math
   $$
   \text{MAV} = \text{DV} \times \sum_{j=0}^{n} \frac{1}{ (\text{ltv}_j \times w_j)}
   $$
```
3. The summation:
```math
   $$
   \sum_{j=0}^{n} \frac{w_j}{\text{ltv}_j} = \frac{w_0}{\text{ltv}_0} + \cdots + \frac{w_n}{\text{ltv}_n}
   $$
```
4. This expression is not equal to:
```math
   $$
   \frac{1}{\text{ltv}_0 \times w_0 + \cdots + \text{ltv}_n \times w_n}
   $$
```
### Example : 
- let's explain the issue from an easy and logical perspective with the followign example : 
- Consider a user's position with the following characteristics:

  - Pool: `poolId-A`
  - Assets: 
    - asset-1: `100$ (LTV 90%)`
    - asset-2: `100$ (LTV 50%)`
  - Total collateral value: `200$`


- Logically,The maximum debt this user should be able to take from `poolId-A` is:

`(100$ * 90%) + (100$ * 50%) = 90$ + 50$ = 140$`

- If the user has borrowed 140$, the minimum required asset value to keep the position healthy should remain 200$.

- Now, let's see how the current implementation calculates this:
```js
for (uint256 j; j < positionAssetsLength; ++j) {
    uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);
    minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
}
```
- for our case:

    - For asset-1: `140$ * 0.5 / 0.9 = 77.78$`
    - For asset-2: `140$ * 0.5 / 0.5 = 140$`
    - Total minReqAssetValue: `77.78$ + 140$ =` **`217.78$`**

-  The function calculates a minimum required asset value of `217.78$`, which is significantly higher than the actual minimum collateral required of `200$` for a position that should be considered healthy.

## Impact
- Position will be liquidated eventhough they are healthy which cause lose of funds for users unfairely.
- Users won't be able to borrow/withdraw funds to the maximum they are allowed to. Knowing that sentiment is a leveraged lending protocol by design, this represents a big issue
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L250
## Tool used

Manual Review

## Recommendation
To fix this, the protocol needs to implement the correct formula by dividing the pool debt value by the weighted-averaged ltv

```diff
function _getMinReqAssetValue(
    uint256[] memory debtPools,
    uint256[] memory debtValuleForPool,
    address[] memory positionAssets,
    uint256[] memory wt,
    address position
) internal view returns (uint256) {
    uint256 minReqAssetValue;
-   uint256 weigtedAvgLtv;

    // O(pools.len * positionAssets.len)
    uint256 debtPoolsLength = debtPools.length;
    uint256 positionAssetsLength = positionAssets.length;
    for (uint256 i; i < debtPoolsLength; ++i) {
-       weigtedAvgLtv = 0;
+       uint256 weightedAvgLtv = 0;
        for (uint256 j; j < positionAssetsLength; ++j) {
            uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);

            // revert with pool id and the asset that is not supported by the pool
            if (ltv == 0) revert RiskModule_UnsupportedAsset(position, debtPools[i], positionAssets[j]);

-           minReqAssetValue += wt[j].mulDiv(ltv,1e18, Math.Rounding.Up);
+           weightedAvgLtv += wt[j].mulDiv(ltv, 1e18, Math.Rounding.Down);
        }
-       minReqAssetValue += debtValuleForPool[i].mulDiv(1e18,weigtedAvgLtv,Math.Rounding.Up);
+       minReqAssetValue += debtValuleForPool[i].mulDiv(1e18, weightedAvgLtv, Math.Rounding.Up);
    }

    if (minReqAssetValue == 0) revert RiskModule_ZeroMinReqAssets();
    return minReqAssetValue;
}
```
Using this corrected implementation with the example:

For `poolId-A` with `140$` debt:
  - `weightedAvgLtv = (0.5 * 90%) + (0.5 * 50%) = 70%`
  - `minReqAssetValue = 140$ * (1 / 70%) = 200$`
  
This calculation correctly results in the expected minRequiredAssetValue of 200$.
