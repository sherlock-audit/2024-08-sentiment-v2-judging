Orbiting Bronze Mustang

Medium

# The `SuperPool` vault is not strictly ERC4626 compliant as it should be

### Summary

The contest [README](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/README.md?plain=1#L49) file clearly states that:

> Q: Is the codebase expected to comply with any EIPs? Can there be/are there any deviations from the specification?

> `SuperPool.sol` is strictly ERC4626 compliant

No deviations from the specification mentioned. The `SuperPool.sol` contract is not strictly ERC4626 compliant according to the [EIP docs](https://eips.ethereum.org/EIPS/eip-4626).

### Root Cause

The [EIP docs](https://eips.ethereum.org/EIPS/eip-4626) for the `convertToShares` and `convertToAssets` functions state:

> MUST NOT be inclusive of any fees that are charged against assets in the Vault.

and later also state:

> The `convertTo` functions serve as rough estimates that do not account for operation specific details like withdrawal fees, etc. They were included for frontends and applications that need an average value of shares or assets, not an exact value possibly including slippage or _**other fees.**_ For applications that need an exact value that attempts to account for fees and slippage we have included a corresponding preview function to match each mutable function. These functions must not account for deposit or withdrawal limits, to ensure they are easily composable, the max functions are provided for that purpose.

However, `SuperPool`'s [`convertToShares`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L194) and [`convertToAssets`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L202) also calculate and include any new fees accrued.

```solidity
    /// @notice Converts an asset amount to a share amount, as defined by ERC4626
    /// @param assets The amount of assets
    /// @return shares The equivalent amount of shares
    function convertToShares(uint256 assets) public view virtual returns (uint256 shares) {
 @>     (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
 @>     return _convertToShares(assets, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
    }

    /// @notice Converts a share amount to an asset amount, as defined by ERC4626
    /// @param shares The amount of shares
    /// @return assets The equivalent amount of assets
    function convertToAssets(uint256 shares) public view virtual returns (uint256 assets) {
@>      (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
@>      return _convertToAssets(shares, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
    }
```

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

The `SuperPool` is not strictly EIP-4626 compliant as the README file states it should be.

### PoC

_No response_

### Mitigation

Don't calculate any new fees accrued in the `external convertTo` functions:

```diff
    function convertToShares(uint256 assets) public view virtual returns (uint256 shares) {
-       (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
-       return _convertToShares(assets, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
+       return _convertToShares(assets, totalAssets(), totalSupply(), Math.Rounding.Down);
    }

    function convertToAssets(uint256 shares) public view virtual returns (uint256 assets) {
-       (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
-       return _convertToAssets(shares, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
+       return _convertToAssets(shares, totalAssets(), totalSupply(), Math.Rounding.Down);
    }
```