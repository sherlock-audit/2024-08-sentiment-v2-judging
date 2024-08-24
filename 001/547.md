Abundant Cobalt Gazelle

Medium

# `SuperPool.maxDeposit()` is not EIP-4626 complaint

## Summary
The `maxDeposit()` function in the SuperPool contract does not account for accrued interest when calculating the maximum depositable assets, potentially leading to an inaccurate assessment of available capacity.

## Vulnerability Detail
The `maxDeposit()` function calculates the maximum amount of assets that can be deposited into the vault based on the `superPoolCap` and the current total assets. However, it does not consider any accrued interest that might have increased the total assets since the last update. This oversight could result in an underestimation of the vault's capacity to accept new deposits, as the function does not reflect the actual state of managed assets, including any interest earned.

## Impact
By not including accrued interest in its calculation, the `maxDeposit()` function may inaccurately limit the amount of assets that can be deposited into the vault. This can lead to missed opportunities for depositors to add more assets, potentially affecting the vault's growth and the overall user experience.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L208

## Tool used

Manual Review

## Recommendation
Modify the `maxDeposit()` function to include accrued interest in its calculation. This could involve using logic similar to `simulateAccrue()` to ensure that any interest accrued since the last update is considered when determining the maximum depositable assets. This change will provide a more accurate representation of the vault's capacity and align with ERC4626 requirements.

