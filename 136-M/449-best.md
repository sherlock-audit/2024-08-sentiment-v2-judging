Recumbent Blush Koala

High

# Handling "Misdeposited Amounts" Post Bad Debt Rebalance

## Summary

The `rebalanceBadDebt` function in the `Pool` contract lacks a mechanism to transfer any leftover assets or "misdeposited amounts" back to the pool owner or another designated entity after the debt has been rebalanced. This can lead to unintentional retention of excess assets within the pool, which may not align with the intended functionality and asset management policies of the protocol.

## Vulnerability Detail

### Current Behavior:
- The function `rebalanceBadDebt` rebalances total borrow shares, borrow assets, and deposit assets based on a bad debt position.
- After converting borrow shares to borrow assets and reducing the total borrow and deposit assets, any remaining balance is left unmanaged within the pool.
- There is no explicit mechanism to transfer these leftover amounts to a designated recipient.

### Issue:
- Absence of a mechanism to handle "misdeposited amounts" could result in excess assets staying in the pool, which might lead to unequal allocation of resources and potential inaccuracies in the pool’s asset management.

## Impact

### Without a fix:
- Potential leftover assets may remain unmanaged within the pool.
- Could lead to unintended financial imbalances and resource misallocation.
- Lack of clarity and transparency in asset management post-rebalance.

### With the fix:
- Clear mechanism to handle and transfer any leftover balance to a specified recipient (generally the pool owner), ensuring proper finalization of asset management.
- Maintains the pool's financial integrity and equitable resource allocation.
- Enhanced transparency and adherence to the protocol's intended asset management policies.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Position.sol#L528-L549
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
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L446-L464
```solidity
function liquidateBadDebt(address position) external onlyOwner {
    riskEngine.validateBadDebt(position);

    // transfer any remaining position assets to the PositionManager owner
    address[] memory positionAssets = Position(payable(position)).getPositionAssets();
    uint256 positionAssetsLength = positionAssets.length;
    for (uint256 i; i < positionAssetsLength; ++i) {
        uint256 amt = IERC20(positionAssets[i]).balanceOf(position);
        try Position(payable(position)).transfer(owner(), positionAssets[i], amt) { } catch { }
    }

    // clear all debt associated with the given position
    uint256[] memory debtPools = Position(payable(position)).getDebtPools();
    uint256 debtPoolsLength = debtPools.length;
    for (uint256 i; i < debtPoolsLength; ++i) {
        pool.rebalanceBadDebt(debtPools[i], position);
        Position(payable(position)).repay(debtPools[i], type(uint256).max);
    }
}
```
## Tool Used

Manual Review

## Recommendation

Introduce a mechanism within the `rebalanceBadDebt` function to handle any remaining balance. Specifically:

- Include an additional transfer step after rebalancing the debts and total assets.
- Transfer any remaining balance to a recipient address, typically the pool owner or a designated entity.
