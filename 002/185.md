Keen Jetblack Turtle

Medium

# Incorrect Calculation of `maxSeizedAssetValue` Allows Excessive Collateral Seizure During Liquidations

## Summary

The `RiskModule` contract's `_validateSeizedAssetValue` function contains a calculation error in determining the `maxSeizedAssetValue`. This miscalculation results in an incorrect implementation of the liquidation discount, allowing liquidators to seize more collateral than the protocol design intends. The issue becomes more pronounced with larger discount values, leading to excessive asset seizures from users' positions during liquidations.

## Vulnerability Detail

- The Sentiment protocol's liquidation mechanism in the `RiskModule` contract contains a logical flaw in calculating the maximum seizable asset value during liquidations. This error allows liquidators to claim more collateral than intended, harming users whose positions are being liquidated.

Let's examine the problematic code:
```solidity
 function _validateSeizedAssetValue(address position, DebtData[] calldata debtData, AssetData[] calldata assetData, uint256 
 discount) internal view {
    // ... (code for calculating debtRepaidValue and assetSeizedValue)

    // max asset value that can be seized by the liquidator
    uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
    if (assetSeizedValue > maxSeizedAssetValue) revert RiskModule_SeizedTooMuch(assetSeizedValue, 
  maxSeizedAssetValue);
  }
```

- The issue lies in the calculation of `maxSeizedAssetValue`. Let's break down why this is incorrect:

 - **Intended Behavior**: The protocol aims to allow liquidators to seize collateral worth `(100 + X)%` of the debt, where *X* is the discount percentage. For example, with a **10%** discount, they should be able to seize at max **110%** of the debt value they repaying.

 - **Current Implementation**: The formula ` debtRepaidValue.mulDiv(1e18, (1e18 - discount))` ,does not achieve this. Instead, it allows for seizing more than intended.

**Detailed Explanation:**

- Let's say the debt being repaid when liquidating is `1000 DAI` and the discount is `10%` (0.1e18 in fixed-point representation).
Intended max seizable value: 1000 * (1 + 0.1) = 1100 DAI
- *Current calculation*:
 ```math
    maxSeizedAssetValue = 1000 * 1e18 / (1e18 - 0.1e18)
                        = 1000 * 1e18 / 0.9e18
                        ≈ 1111.11 DAI
 ```


**Percentage Analysis:**

 - Intended increase: `10%`
 - Actual increase: 
 ```math
  (1111.11 - 1000) / 1000 * 100 ≈ 11.111%
 ```
- Excess percentage: `11.111% - 10%` = **`1.111%`**

---
- **Scaling Effect**: This error becomes more pronounced with larger discounts:
  - `20% discount:` Intended 120%, Actual ≈ 125%
  - `30% discount:` Intended 130%, Actual ≈ 142.86%

- **Root Cause**: The formula inverts the discount effect. Instead of multiplying by **`(1 + discount)`**, it divides by **`(1 - discount)`**, which always results in a larger value.

This miscalculation consistently allows liquidators to seize more collateral than the protocol design intends. It's not just a small rounding error, but a fundamental misrepresentation of the discount mechanism. This leads to users losing more collateral than necessary during liquidations, undermining the fairness and predictability of the protocol's risk management system.

## Impact
- This calculation error allows liquidators to seize more collateral than they should, directly impacting users' positions during liquidations. Borrowers face increased risk of losing excess collateral, while liquidators gain an unintended advantage. 

## Code Snippet
- https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L156
## Tool used

Manual Review

## Recommendation

To correct the calculation of `maxSeizedAssetValue`, the formula should be adjusted to properly apply the liquidation discount.:
```diff
function _validateSeizedAssetValue(address position, DebtData[] calldata debtData, AssetData[] calldata assetData, uint256 discount) internal view {
    // ... (previous code remains unchanged)

    // max asset value that can be seized by the liquidator
-   uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
+   uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18 + discount, 1e18);
    if (assetSeizedValue > maxSeizedAssetValue) revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
}
