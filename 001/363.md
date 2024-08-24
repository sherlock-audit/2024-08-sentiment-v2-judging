Sparkly Taffy Fly

Medium

# `SuperPool.sol` is not ERC4626 compliant.

### Summary

The inclusion of fee handling and the [`accrue` function](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L311-L315) will cause non-compliance with the ERC4626 standard for integrators and users as the `SuperPool` contract includes non-standard logic in several methods.


### Root Cause

In `protocol-v2/src/SuperPool.sol`, the functions `convertToShares()`, `convertToAssets()`, `maxMint()`, `maxWithdraw()`, `maxRedeem()`, `previewDeposit()`, `previewMint()`, `previewWithdraw()`, `previewRedeem()`, `deposit()`, `mint()`, `withdraw()`, and `redeem()` include fee handling logic (`simulateAccrue`) and call the `accrue` function, which deviates from the ERC4626 standard. For details [ERC-4626: Tokenized Vaults](https://eips.ethereum.org/EIPS/eip-4626)

### Internal pre-conditions

1. The contract includes the `simulateAccrue` function within the relevant methods.
2. The contract calls the `accrue` function within the `deposit()`, `mint()`, `withdraw()`, and `redeem()` methods.


### External pre-conditions

None.

### Attack Path

1. A user calls the `convertToShares()` function with a specified amount of assets.
2. The function internally calls `simulateAccrue()`, which handles fees and adjusts the total assets.
3. The returned share amount includes the effects of fee handling, which is not compliant with the ERC4626 standard.


### Impact

The integrators and users suffer from non-compliance with the ERC4626 standard, leading to unexpected behavior and inconsistencies in the conversion between assets and shares. This affects the accuracy and predictability of the vault's operations.


### PoC

1. A user calls the `convertToShares()` function with 1000 assets.
2. The function internally calls `simulateAccrue()`, adjusting the total assets and including fee handling.
3. The returned share amount is affected by the fee handling, deviating from the expected behavior as per the ERC4626 standard.

Relevant code:
```solidity

function convertToShares(uint256 assets) public view virtual returns (uint256 shares) {
    (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
    return _convertToShares(assets, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
}
```

### Mitigation

To ensure compliance with the ERC4626 standard, the `SuperPool` contract should be modified to remove the `simulateAccrue` and `accrue` functions from the relevant methods. Additionally, fee handling logic should be reviewed and adjusted to align with the ERC4626 standard.

For `convertToShares()`:
```solidity
function convertToShares(uint256 assets) public view virtual returns (uint256 shares) {
    // Remove fee handling logic
    uint256 newTotalAssets = totalAssets();
    return _convertToShares(assets, newTotalAssets, totalSupply(), Math.Rounding.Down);
}
```

Similar changes should be applied to other affected functions (`convertToAssets()`, `maxMint()`, `maxWithdraw()`, `maxRedeem()`, `previewDeposit()`, `previewMint()`, `previewWithdraw()`, `previewRedeem()`, `deposit()`, `mint()`, `withdraw()`, `redeem()`).