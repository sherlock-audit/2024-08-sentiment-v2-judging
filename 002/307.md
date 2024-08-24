Mammoth Rosewood Okapi

High

# In liquidateBadDebt, transferring all the assets from the position to the protocol’s owner is unfair to the lender, as it increases the lender’s losses.

## Summary
In liquidateBadDebt, all the assets from the position are transferred to the protocol’s owner, while the lender bears the full loss of the entire borrowed amount, not just the under-collateralized portion (i.e., debtValue - assetValue). This results in an unfair outcome for the lender.

## Vulnerability Detail
```javascript
function liquidateBadDebt(address position) external onlyOwner {
        riskEngine.validateBadDebt(position);

        // transfer any remaining position assets to the PositionManager owner
        address[] memory positionAssets = Position(payable(position)).getPositionAssets();
        uint256 positionAssetsLength = positionAssets.length;
        for (uint256 i; i < positionAssetsLength; ++i) {
            uint256 amt = IERC20(positionAssets[i]).balanceOf(position);
@>>            try Position(payable(position)).transfer(owner(), positionAssets[i], amt) { } catch { }
        }

        // clear all debt associated with the given position
        uint256[] memory debtPools = Position(payable(position)).getDebtPools();
        uint256 debtPoolsLength = debtPools.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
@>>            pool.rebalanceBadDebt(debtPools[i], position);
@>>            Position(payable(position)).repay(debtPools[i], type(uint256).max);
        }
    }
```
We can see in the liquidateBadDebt function that all of the position’s assets are transferred to the owner, but none of the debt is actually repaid.
```javascript
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
@>>        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
@>>        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
@>>        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
    }
```
In the rebalanceBadDebt function, the debt is only cleared at the accounting level, without transferring the actual funds needed to repay the debt. Directly reducing borrowAssets from totalDepositAssets forces all lenders to bear the loss of the borrowed funds.

```javascript
 function repay(uint256 poolId, uint256) external onlyPositionManager {
        if (POOL.getBorrowsOf(poolId, address(this)) == 0) debtPools.remove(poolId);
    }
```
We can see that in the position.repay() function, there is also no actual transfer of funds to repay the debt.
## Impact
The lender bears the full loss of the borrowed funds, not just the under-collateralized portion (i.e., debtValue - assetValue), while the owner profits. This is extremely unfair to the lender.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L446

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L528
## Tool used

Manual Review

## Recommendation
The protocol should either repay all of the debt or sell the position’s collateral (assets) into the debt token to cover the outstanding debt.