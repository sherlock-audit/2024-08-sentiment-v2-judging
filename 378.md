Lucky Cornflower Porcupine

Medium

# SuperPool doesn't take bad debt into account

### Summary

The pools can encounter bad debt that can be socialized by the protocol owner. In that case the SuperPool will not take it into account resulting in possible race to exit from users and the last users not able to withdraw a part of their shares.

### Root Cause

The `pool` contract has a function [`rebalanceBadDebt()`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/src/Pool.sol#L528-L528) that can be called by the protocol owner to socialize the bad debt amongst depositors in the pool.

In the `SuperPool` contract most functions uses `lastTotalAssets` variable to determine how many assets belongs to the contract. This variable is updated on every call through the [`accrue()`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/src/SuperPool.sol#L311-L311) function that calls the [`simulateAccrue()`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/src/SuperPool.sol#L653-L653) internal function.

This function will only increases the `lastTotalAssets` variable. if the assets belonging to the SuperPool reduced because of bad debt socialization the `lastTotalAssets` will not be updated and thus not reflect the loss and users will keep depositing and withdrawing at an invalid share rate.

This could create a rush to exit the SuperPool as only the last users to withdraw will be affected by the debt socialization and will not be able to withdraw.

### Internal pre-conditions

- Debt socialization on one of the pool by the protocol owner

### External pre-conditions

- Market volatility creating bad debt on one of the pool used by the SuperPool

### Attack Path

_No response_

### Impact

- Users won't be affected the same, some will be able to withdraw at full rate while some users won't be able to withdraw from the SuperPool.
- Invalid share rate returned by the SuperPool.

### PoC

_No response_

### Mitigation

Consider updating the `lastTotalAssets` even when it's to a lower value in the `accrue()` function to reflect bad debt socialization.