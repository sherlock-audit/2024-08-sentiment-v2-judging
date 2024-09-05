Sparkly Taffy Fly

High

# Malicious users can exploit multi-pool borrowing to bypass collateral checks, leading to protocol insolvency

### Summary

The lack of a global debt tracking mechanism will cause a significant risk of insolvency for the protocol as malicious users can exploit multi-pool borrowing to bypass collateral checks.


### Root Cause

In [`PositionManager.sol:borrow`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L383-L402), the protocol tracks debt independently for each pool without aggregating the total debt across all pools for a single position.


### Internal pre-conditions

1. A user needs to create a position with collateral (e.g., 100 ETH).
2. The user needs to borrow from multiple pools (e.g., 60 ETH from Pool A and 60 ETH from Pool B).


### External pre-conditions

1. The protocol must allow borrowing from multiple pools without a global debt check.


### Attack Path

1. User creates a position with 100 ETH as collateral.
2. User borrows 60 ETH from Pool A.
3. User borrows another 60 ETH from Pool B.
4. Each pool sees the position as healthy (60% LTV), but the total debt (120 ETH) exceeds the collateral (100 ETH).
5. User defaults on the loans, leaving the protocol with bad debt.


### Impact

The protocol suffers a significant loss as the total debt (120 ETH) exceeds the collateral (100 ETH), leading to potential insolvency. The attacker gains the borrowed assets (120 ETH) while the protocol is left with bad debt.


### PoC

1. Alice creates a position with 100 ETH as collateral.
2. Alice borrows 60 ETH from Pool A.
3. Alice borrows another 60 ETH from Pool B.
4. Each pool sees Alice's position as healthy because the debt in each pool is only 60% of the collateral.
5. However, Alice's total debt (120 ETH) exceeds the total collateral (100 ETH), making the position unhealthy overall.
6. Alice defaults on her loans, leaving the protocol with 120 ETH of bad debt and only 100 ETH of collateral to cover it.


### Mitigation

Implement a global debt tracking mechanism in the `PositionManager` or `RiskEngine` contract that aggregates the total debt of a position across all pools and performs a comprehensive health check.

### Example Fix

#### In `RiskEngine.sol`:

```diff
function getTotalDebt(address position) public view returns (uint256) {
    uint256 totalDebt = 0;
    uint256[] memory debtPools = Position(payable(position)).getDebtPools();
    for (uint256 i = 0; i < debtPools.length; i++) {
        totalDebt += pool.getBorrowsOf(debtPools[i], position);
    }
    return totalDebt;
}

function isPositionHealthy(address position) public view returns (bool) {
    uint256 totalDebt = getTotalDebt(position);
    uint256 totalCollateral = riskModule.getTotalAssetValue(position);
    return totalCollateral >= totalDebt;
}
```


#### In `PositionManager.sol`:

```diff
function borrow(uint256 poolId, address position, uint256 amt) external {
+   require(riskEngine.isPositionHealthy(position), "Unhealthy position");
    // ... existing code ...
}
```


This fix ensures that the total debt across all pools is considered when evaluating the health of a position, preventing the exploit scenario described.