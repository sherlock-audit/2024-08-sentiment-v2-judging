Recumbent Blush Koala

High

# Inequitable Impact on Depositors Post Bad Debt Rebalance

## Summary

The `rebalanceBadDebt` function in the `Pool` contract processes bad debt by reducing the pool’s total borrow and deposit assets. However, it does not correctly handle cases where a depositor withdraws their funds after a rebalance event, which disproportionately affects remaining depositors by not evenly distributing the financial impact of the bad debt. This creates an inequitable situation where the remaining depositors bear an undue burden.

## Vulnerability Detail

### Current Behavior:
- The `rebalanceBadDebt` function adjusts the pool's total borrow and deposit assets based on the bad debt of a given position and sets the `borrowShares` of that position to 0.
- It does not account for the scenario where depositors withdraw their funds post-rebalance, leaving remaining depositors to disproportionately absorb the impact of the rebalance event.
- Lack of a mechanism to ensure equitable distribution of the financial burden arising from bad debt across all depositors.

### Issue:
- Deposit withdrawals post-rebalance can lead to an uneven spread of the bad debt burden among remaining depositors.
- Uneven impact on depositors can undermine trust and stability in the protocol, as some users may feel penalized while others can exit the system unduly at their expense.

## Impact

### Without a fix:
- Remaining depositors bear a disproportionate share of the financial burden caused by bad debt.
- Potential erosion of trust and stability in the protocol.
- Unintended financial imbalances and inequitable treatment of depositors, which may lead to user dissatisfaction or withdrawal of funds from the protocol.

### With the fix:
- Ensures equitable distribution of the financial burden among all depositors.
- Enhances trust and stability in the protocol by providing fair treatment to all users.
- Maintains a balanced and sustainable economic model within the pool.

## Code Snippet

### Current `rebalanceBadDebt` function:
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Position.sol#L528-549
```solidity
function rebalanceBadDebt(uint256 poolId, address position) external {
    PoolData storage pool = poolDataFor[poolId];
    accrue(pool, poolId);

    // revert if the caller is not the position manager
    if (msg.sender != positionManager) revert Pool_OnlyPositionManager(poolId, msg.sender);

    // compute pool and position debt in shares and assets
    uint256 totalBorrowShares = pool.totalBorrowShares;
    uint256 totalBorrowAssets = pool.totalBorrowAssets;
    uint256 borrowShares = borrowSharesOf[poolId][position];
    // [ROUND] round up against lenders
    uint256 borrowAssets = _convertToAssets(borrowShares, totalBorrowAssets, totalBorrowShares, Math.Rounding.Up);

    // rebalance bad debt across lenders
    pool.totalBorrowShares = totalBorrowShares - borrowShares;
    // handle borrowAssets being rounded up to be greater than totalBorrowAssets
    pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
    uint256 totalDepositAssets = pool.totalDepositAssets;
    pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
    borrowSharesOf[poolId][position] = 0;
}
```

### Suggested Improvements:
- Introduce a mechanism for ensuring that the financial impact of bad debt is distributed equitably among all depositors.
- Implement an adjustment to the withdraw functionality to take into account the implications of any past rebalance events.

Here’s a proposed approach leveraging a continuous recalibration of each depositor’s shares:

```solidity
struct PoolData {
    // Original members
    // Add required new fields here if any
    uint256 lastAccruedRebalance;
}

function rebalanceBadDebt(uint256 poolId, address position, address recipient) external {
    PoolData storage pool = poolDataFor[poolId];
    accrue(pool, poolId);

    if (msg.sender != positionManager) revert Pool_OnlyPositionManager(poolId, msg.sender);

    uint256 totalBorrowShares = pool.totalBorrowShares;
    uint256 totalBorrowAssets = pool.totalBorrowAssets;
    uint256 borrowShares = borrowSharesOf[poolId][position];
    uint256 borrowAssets = _convertToAssets(borrowShares, totalBorrowAssets, totalBorrowShares, Math.Rounding.Up);

    pool.totalBorrowShares = totalBorrowShares - borrowShares;
    pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
    uint256 totalDepositAssets = pool.totalDepositAssets;
    pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
    borrowSharesOf[poolId][position] = 0;

    // Update the time of last rebalance
    pool.lastAccruedRebalance = block.timestamp;

    // Transfer any remaining balance to the recipient
    uint256 remainingBalance = totalDepositAssets > borrowAssets ? totalDepositAssets - borrowAssets : 0;
    if (remainingBalance > 0) {
        IERC20(pool.asset).safeTransfer(recipient, remainingBalance);
    }
}

function withdraw(uint256 poolId, uint256 amount) external {
    PoolData storage pool = poolDataFor[poolId];
    // accrue interest before withdrawal
    accrue(pool, poolId);

    // Adjust deposit shares based on any recent rebalance impact
    uint256 shares = calculateWithdrawalShares(pool, msg.sender, amount);

    // Update total deposit assets before actual withdrawal
    pool.totalDepositAssets = pool.totalDepositAssets > amount ? pool.totalDepositAssets - amount : 0;

    // Perform the withdrawal
    _withdraw(pool, msg.sender, amount, shares);
}

function calculateWithdrawalShares(PoolData storage pool, address account, uint256 amount) internal view returns (uint256) {
    // Calculate appropriate shares to withdraw considering the last rebalance
    // Adjust shares proportionally based on the time elapsed since the last rebalance or add necessary logic
    // to ensure fair share distribution
    // Example logic:
    uint256 sharesPercentage = amount * 1e18 / pool.totalDepositAssets;
    uint256 shares = sharesPercentage * pool.totalBorrowShares / 1e18;
    return shares;
}

function _withdraw(PoolData storage pool, address account, uint256 amount, uint256 shares) internal {
    // Implement the withdrawal logic
    // Consider updating the borrowSharesOf as well
}
```

### Note:
- This example extends the `PoolData` struct and includes a basic implementation of a recalibration mechanism during withdrawals to ensure fair impact distribution. A more nuanced approach might be needed based on your specific economic model and requirements.

## Tool Used

Manual Review


## Recommendation

Introduce a recalibration mechanism within the `rebalanceBadDebt` function and withdrawal process to ensure that the impact of bad debt is fairly distributed among all depositors. 

### Recommendations:
- Add a timestamp to the `PoolData` struct to track the last rebalance event.
- Adjust the withdrawal calculations to account for the implications of the bad debt rebalance.
- Ensure any new logic is thoroughly tested and audited for security and economic soundness.
