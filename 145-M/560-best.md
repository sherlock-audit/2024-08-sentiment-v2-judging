Glamorous Blush Gecko

Medium

# The `totalAssets()` function is not ERC 4626 compliant

### Summary

[ERC-4626](https://eips.ethereum.org/EIPS/eip-4626) clearly states the following about the `totalAssets()` function:

>MUST be inclusive of any fees that are charged against assets in the Vault.

The issue is that the protocol's [implementation](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L180) of the function does not account for the fact that some of the assets are the accumulated interest fee.

The protocol accumulates the interest fee by minting shares to the `feeRecipient()` every time the `accrue` function is called.

The `totalAssets()` function should subtract the accumulated interest fee from the currently calculated amount of total assets to return a value that is including the fees charged on interest.

### Root Cause

`totalAssets()` does not subtract the accumulated interest fees

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

SuperPool is not ERC-4626 compliant, this can pose issues with external integrations that expect strict compliance

### PoC

_No response_

### Mitigation

Implement a variable to track the fee amount, subtract it from `totalAssets()`

This may require redesigning functions that implement `totalAssets()`