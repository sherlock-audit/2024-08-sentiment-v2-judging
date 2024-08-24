Curly Topaz Whale

Medium

# Depositors can withdraw to avoid taking bad debt via frontrun liquidateBadDebt()

## Summary
If some bad debt occurs, all borrowed assets will be marked as the loss for the underlying pools. This may cause underlying pools' share price drop rapidly. Depositors in the underlying pool can withdraw asset to avoid taking the loss via frontrun liquidateBadDebt()

## Vulnerability Detail
In PositionManager, when the collateral asset price drops or borrowing assets' price increase rapidly, bad debt may occur. The owner will clear the bad debt via `liquidateBadDebt()`. 
In `rebalanceBadDebt()`, we clear the position's debt and `totalDepositAssets` will decrease because of this debt. This may cause share's price drop rapidly if this position borrows a lot of assets. One depositor in this underlying pool monitors this clear bad debt, and withdraw his assets via frontrun liquidateBadDebt(). The left depositors will take the loss because of the bad debt. This is unfair.

```solidity
    function liquidateBadDebt(address position) external onlyOwner {
        // Make sure there are some bad debt in this position.
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
            // Clear position
            Position(payable(position)).repay(debtPools[i], type(uint256).max);
        }
    }
```
```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
       ...
        // rebalance bad debt across lenders
        // Clear the debt from borrowShares and borrowAssets
        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
        // TotalDepositAssets decrease, it means that depositors share's price will drop.
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
    }
```
## Impact
The depositor can withdraw asset in the underlying pool to avoid taking the bad debt loss via frontrun liquidateBadDebt(), and the left depositors(share holders) will take more loss than expected.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L446-L464

## Tool used

Manual Review

## Recommendation
In order to avoid frontrun liquidateBadDebt(), we can consider depositors need to request withdraw, wait for a period of time, and then execute the withdrawal action.