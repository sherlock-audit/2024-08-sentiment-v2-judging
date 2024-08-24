Plain Clay Condor

High

# When `totalAssets` is zero, utilization is set to zero, resulting in the interest rate being set to `MIN_RATE_1`

### Summary

```solidity
uint256 util = (totalAssets == 0) ? 0 : totalBorrows.mulDiv(1e18, totalAssets, Math.Rounding.Up);
```
- When `totalAssets` is zero, the code sets util to zero. This results in the interest rate being calculated as `MIN_RATE_1`, regardless of the actual borrowing situation.


The handling of zero `totalAssets` by defaulting utilization to zero and setting the interest rate to `MIN_RATE_1` will cause an unintended economic advantage for borrowers as they can exploit the system by depleting assets to maintain a low interest rate; 
this results in potential financial losses for lenders due to the inability of the model to dynamically adjust rates based on actual utilization.

### Root Cause

In [KinkedRateModel.sol#L56](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/irm/KinkedRateModel.sol#L56)
When `totalAssets` is zero, utilization is set to zero, resulting in the interest rate being set to `MIN_RATE_1`.

- This logic likely aims to prevent division by zero but fails to align with the dynamic model's goal of adjusting rates based on utilization.

### Internal pre-conditions

1. The system is designed to penalize low asset scenarios.
2. Borrowers deplete assets, triggering zero utilization.
3. Interest rate remains at `MIN_RATE_1`, contrary to the intended penalty mechanism, allowing borrowers to exploit the system.

### External pre-conditions

see attack path below!

### Attack Path

1. A borrower could strategically deplete the pool, ensuring `totalAssets` is zero, thus locking in the lowest interest rate `(MIN_RATE_1)`, regardless of the borrowing situation.

Outcome: This could lead to a situation where the pool is unable to incentivize lenders or manage risk effectively, potentially destabilizing the lending protocol.

### Impact

Borrowers benefit from artificially low interest rates, while lenders face potential losses due to non-responsive interest rate adjustments.


### Mitigation

- ensure the model reflects its dynamic nature and prevents exploitation.
- Consider using a minimum non-zero value for `totalAssets` in calculations to avoid division by zero while still reflecting the dynamic nature of the model.