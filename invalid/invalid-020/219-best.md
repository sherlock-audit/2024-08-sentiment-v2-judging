Acidic Heather Goldfish

High

# Incorrect Fee Validation in Constructor of SuperPool Contract

## Summary
The constructor of the `SuperPool` contract contains a faulty comparison of the `fee` member variable instead of the `fee_` parameter, which can lead to improper validation of the initial fee setting during contract deployment.

## Vulnerability Detail
Within the constructor, the contract incorrectly compares the `fee` member variable against the maximum allowable fee (`1e18`). At this point, `fee` is uninitialized and should have been compared to `fee_`, the parameter representing the fee being passed during the deployment.

## Impact
Due to this incorrect comparison, the contract may be deployed with an invalid initial fee percentage. This can result in the contract being deployed with an overwhelming fee rate or other unintended behaviors, undermining the security and proper operation of the fee mechanism.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L157
```solidity
    constructor(
        address pool_,
        address asset_,
        address feeRecipient_,
        uint256 fee_,
        uint256 superPoolCap_,
        string memory name_,
        string memory symbol_
    ) Ownable() ERC20(name_, symbol_) {
        POOL = Pool(pool_);
        ASSET = IERC20(asset_);
        DECIMALS = _tryGetAssetDecimals(ASSET);

@>        if (fee > 1e18) revert SuperPool_FeeTooHigh();
        fee = fee_;
        feeRecipient = feeRecipient_;
        superPoolCap = superPoolCap_;
    }
```

## Tool used
Manual Review

## Recommendation
Modify the constructor to compare the `fee_` parameter with `1e18` for proper validation during the contract deployment phase. Ensure that all fee-related validations reference the appropriate variables to avoid potential logical errors. Here is the corrected constructor:

```diff
    constructor(
        address pool_,
        address asset_,
        address feeRecipient_,
        uint256 fee_,
        uint256 superPoolCap_,
        string memory name_,
        string memory symbol_
    ) Ownable() ERC20(name_, symbol_) {
        POOL = Pool(pool_);
        ASSET = IERC20(asset_);
        DECIMALS = _tryGetAssetDecimals(ASSET);

-        if (fee > 1e18) revert SuperPool_FeeTooHigh();
+        if (fee_ > 1e18) revert SuperPool_FeeTooHigh();
        fee = fee_;
        feeRecipient = feeRecipient_;
        superPoolCap = superPoolCap_;
    }
```
