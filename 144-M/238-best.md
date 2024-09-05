Sparkly Taffy Fly

High

# Attacker will Dilute Depositors' Shares and Enable Exploitation

### Summary

A mismatch in interest accrual will cause dilution of depositors' shares and enable exploitation for depositors as an attacker will exploit the discrepancy between `totalDepositShares` and `totalDepositAssets`.

### Root Cause

In [`protocol-v2/src/Pool.sol:accrue`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L401-L414) the function increases `totalDepositShares` by `feeShares` but increases `totalDepositAssets` by the full `interestAccrued` amount, creating a mismatch.


### Internal pre-conditions

1. The `accrue` function is called, calculating `interestAccrued` and `feeShares`.
2. `feeShares` are minted to the `feeRecipient`.
3. `totalDepositShares` is increased by `feeShares`.
4. `totalDepositAssets` is increased by the full `interestAccrued` amount.


### External pre-conditions

1. The attacker needs to have deposited assets into the pool.
2. The pool needs to have accrued interest.


### Attack Path

1. Attacker deposits assets into the pool.
2. Interest accrues in the pool, and the `accrue` function is called.
3. `feeShares` are minted to the `feeRecipient`.
4. `totalDepositShares` is increased by `feeShares`.
5. `totalDepositAssets` is increased by the full `interestAccrued` amount.
6. The attacker withdraws more value from the pool than they should be entitled to due to the mismatch.


### Impact

The depositors suffer a dilution of their shares, leading to a potential significant financial loss. The attacker gains more value from the pool than they should be entitled to.


### PoC

1. Attacker deposits 1000 units of an asset into the pool.
2. Interest accrues, and the `accrue` function is called, calculating `interestAccrued` as 100 units and `feeShares` as 10 shares.
3. `feeShares` are minted to the `feeRecipient`.
4. `totalDepositShares` is increased by 10 shares.
5. `totalDepositAssets` is increased by 100 units.
6. The attacker withdraws their assets, exploiting the mismatch to extract more value than they should be entitled to.


### Mitigation

To fix this issue, ensure that the relationship between `totalDepositShares` and `totalDepositAssets` remains consistent. Update the `accrue()` function as follows:

```diff
function accrue(PoolData storage pool, uint256 id) internal {
    (uint256 interestAccrued, uint256 feeShares) = simulateAccrue(pool);

    if (feeShares != 0) _mint(feeRecipient, id, feeShares);

+   // Calculate the interest minus fees in terms of assets
+   uint256 interestMinusFees = interestAccrued - _convertToAssets(feeShares, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Down);

    // update pool state
    pool.totalDepositShares += feeShares;
    pool.totalBorrowAssets += interestAccrued;
-   pool.totalDepositAssets += interestAccrued;
+   pool.totalDepositAssets += interestMinusFees; // Only increase by interest minus fees

    pool.lastUpdated = uint128(block.timestamp);
}
```
