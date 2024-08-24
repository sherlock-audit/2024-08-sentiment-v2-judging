Mammoth Slate Caterpillar

Medium

# Missing SuperPool Cap Validation in Accrual and Deposit Logic

## Summary
The current design of the `accrue` and `_deposit` functions in the `SuperPool` contract presents a potential flaw where `lastTotalAssets` can exceed the defined `superPoolCap.` This occurs because `lastTotalAssets` is updated based on deposits without ensuring that the cap is respected. Additionally, accrued interest added to `lastTotalAssets` can further push it beyond the cap, impacting the handling of new deposits
## Vulnerability Detail
The vulnerability is primarily rooted in two areas. First, the `accrue` function is responsible for simulating the accrual of fees and interest and updating `lastTotalAssets` accordingly. However, this function lacks a critical validation step to confirm that the updated `lastTotalAssets` value does not exceed the defined `superPoolCap`. As a result, when interest accrues, `lastTotalAssets` may inflate beyond the intended cap, leading to inaccurate state management and potentially causing the system to mismanage future deposits.

Second, while the `_deposit` function does perform a check to determine if the total assets (calculated as `lastTotalAssets` plus the new deposit) exceed the `superPoolCap`, this check is performed only after accrued interest has already been factored into `lastTotalAssets`. This creates a scenario where, if interest has already caused `lastTotalAssets` to approach the cap, the system may incorrectly allow further deposits, ultimately pushing the total assets over the limit. The inconsistency in how the cap is enforced across different functions can lead to operational disruptions and security risks.

## Impact
The primary concern is that the `SuperPool` may end up holding more assets than intended if `lastTotalAssets` exceeds the `superPoolCap`. This could cause issues with deposit processing, potentially allowing more deposits than the contract is designed to handle. Additionally, exceeding the cap compromises the integrity of asset management within the `SuperPool`, leading to scenarios where the contract’s intended limitations are bypassed.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L314
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L499
```solidity
function accrue() public {
    (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
    if (feeShares != 0) ERC20._mint(feeRecipient, feeShares);
    lastTotalAssets = newTotalAssets;
}

function simulateAccrue() internal view returns (uint256, uint256) {
    uint256 newTotalAssets = totalAssets();
    uint256 interestAccrued = (newTotalAssets > lastTotalAssets) ? newTotalAssets - lastTotalAssets : 0;
    if (interestAccrued == 0 or fee == 0) return (0, newTotalAssets);

    uint256 feeAssets = interestAccrued.mulDiv(fee, WAD);
    uint256 feeShares = _convertToShares(feeAssets, newTotalAssets - feeAssets, totalSupply(), Math.Rounding.Down);

    return (feeShares, newTotalAssets);
}

function _deposit(address receiver, uint256 assets, uint256 shares) internal {
    if (lastTotalAssets + assets > superPoolCap) revert SuperPool_SuperPoolCapReached();
    ASSET.safeTransferFrom(msg.sender, address(this), assets);
    ERC20._mint(receiver, shares);
    _supplyToPools(assets);
    lastTotalAssets += assets; // lastTotalAsset is total asset in super pool
    emit Deposit(msg.sender, receiver, assets, shares);
}
```

## Tool used

Manual Review

## Recommendation

To address this issue, it is essential to introduce a cap validation check within the `accrue` function. This check should ensure that after incorporating accrued interest, `lastTotalAssets` does not surpass the defined `superPoolCap`. By enforcing this validation, the risk of exceeding the cap due to interest accrual will be mitigated, ensuring the integrity of the contract’s asset management and deposit processing. 