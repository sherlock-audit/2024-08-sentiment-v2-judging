Spicy Amethyst Ram

Medium

# Incorrect check in validateBadDebt function

## Summary

The validateBadDebt functions allows positions where assets equal debt to be classified as not in bad debt. This behavior affects the liquidateBadDebt function, which relies on this validation to determine whether a position should be liquidated.

## Vulnerability Detail

The validateBadDebt function only reverts when totalAssetValue exceeds totalDebtValue depicting no bad debt

`  function validateBadDebt(address position) external view {
       // ......Existing codes.....
        if (totalAssetValue > totalDebtValue) revert RiskModule_NoBadDebt(position);
    }`

However, if totalAssetValue = totalDebtValue, the function does not revert and incorrectly considers the position as being in bad debt. 

This can lead to case where totalAssetValue = totalDebtValue is being considered as bad debt which is technically not. The owner can go ahead to liquidate the position thinking its bad debt because of the incorrect check. 

## Impact

The implementation could lead to unfair liquidations of positions that are technically not in bad debt (case of totalAssetValue = totalDebtValue )

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L126

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L447

## Tool used

Manual Review

## Recommendation

Adjust the validateBadDebt function to handle the scenario where totalAssetValue is equal to totalDebtValue more accurately.