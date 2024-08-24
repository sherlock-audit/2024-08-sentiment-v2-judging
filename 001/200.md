Sparkly Taffy Fly

Medium

# Incorrect Calculation of Max Deposit Limits Can Lead to Exceeding SuperPool Cap

### Summary

The failure to account for accrued interest in the [`maxDeposit` function](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L208-L210) will cause an inaccurate calculation of the maximum depositable amount for users as the function does not call [`simulateAccrue`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L653-L663) to get the most up-to-date total assets.

### Root Cause

In [`protocol-v2/src/SuperPool.sol: maxDeposit`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L208-L210) the function does not call `simulateAccrue`, leading to an outdated `totalAssets` value that does not include accrued interest.

### Internal pre-conditions

1. The `superPoolCap` is set to a specific value.
2. Interest has accrued in the SuperPool since the last update of `lastTotalAssets`.

### External pre-conditions

1. Users are attempting to deposit assets into the SuperPool.

### Attack Path

1. User calls `maxDeposit` to check the maximum amount of assets they can deposit.
2. The `maxDeposit` function returns a value based on an outdated `totalAssets` that does not include accrued interest.
3. User deposits assets up to the returned limit.
4. The actual total assets in the SuperPool exceed the `superPoolCap` due to the unaccounted accrued interest.

### Impact

The protocol suffers from exceeding the intended `superPoolCap`, potentially leading to over-depositing and mismanagement of assets. The users might deposit more assets than intended, causing operational and financial discrepancies.

### PoC

1. Assume `superPoolCap` is set to 1,000,000 units.
2. `lastTotalAssets` is 900,000 units, but with accrued interest, the actual total assets are 950,000 units.
3. User calls `maxDeposit` and receives a value of 100,000 units (1,000,000 - 900,000).
4. User deposits 100,000 units.
5. The actual total assets in the SuperPool become 1,050,000 units, exceeding the `superPoolCap`.


### Mitigation

To fix this issue, the `maxDeposit` function should call `simulateAccrue` to ensure it uses the most up-to-date total assets, including accrued interest. Here is the diff for the fix:

```diff
function maxDeposit(address) public view returns (uint256) {
-    return _maxDeposit(totalAssets());
+    (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
+    return _maxDeposit(newTotalAssets);
}
```