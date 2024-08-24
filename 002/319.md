Bitter Sandstone Worm

Medium

# Under certain circumstances bad debt will cause first depositor to lose funds

### Summary
The protocol handles bad debt through [`PositionManager::liquidateBadDebt()`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L446)

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

The function is used to handle bad debt if it occurs for a specific `position`.

Let's examine `pool.rebalanceBadDebt`:

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

Wen ca see that `totalBorrowShares,  totalBorrowAssets  and totalDepositAssets` decremented by their respective values (shares and assets).

When bad debt occurs and is liquidated, it's basically written off the protocol and the losses are socialized between all the depositors of that pool.

There is 1 problem with this, if a `position` has borrowed the entire assets of the `pool` and is liquidated due to bad debt. This is realistic if the pool is unpopular for some reason (niche token, high fees, etc...). Note that this can also occur when all positions incur bad debt and their debt gets socialized, but it's a rarer for this to happen.

The problem will be the fact that `totalDepositAssets` will equal 0. When it's 0, when a user deposits into the pool, his shares are minted 1:1 to the assets he is providing, which is a problem, because there are other shares in the pool at this time, the shares of the depositors that got socialized the bad debt.

Example:
- We assume that there are no fees just to simplify the math.

1. Alice deposits 100 tokens in the pool and she gets 100 shares, due to her being the first depositor the shares are minted 1:1.
2. Bob borrows all 100 tokens. Now, `totalDepositAssets == totalBorrowAssets`.
3. Time passes and 50 interest is accrued, now `totalDepositAssets = 150` and `totalBorrowAssets = 150`.
4. Bob is eligible to be liquidated, but he isn't. This can happen due to lack of incentive for liquidators, Bob's collateral plummets in price very quickly, Bob's loan goes up in price very quickly.
5. Bob has now accumulated bad debt and the debt is liquidated through `liquidateBadDebt`.
6. When `rebalanceBadDebt` is called both `totalDepositAssets` and `totalBorrowAssets` equal 0.
7. At this point, `totalDepositAssets = 0`, but `totalDepositShares = 100`.
8. Charlie deposits another 100 assets into the pool and his shares are minted 1:1 again, due to this:
```solidity
 function _convertToShares(
        uint256 assets,
        uint256 totalAssets,
        uint256 totalShares,
        Math.Rounding rounding
    ) internal pure returns (uint256 shares) {
        if (totalAssets == 0) return assets;
        shares = assets.mulDiv(totalShares, totalAssets, rounding);
    }
```
9. Charlie receives 100 shares, but Alice also has 100 shares and there are only 100 assets in the pool, so Charlie actually received the penalties of the debt being socialized, even though he deposited after the liquidation of bad debt.

### Root Cause
Allowing for 100% utilization of assets.

Note that only 1 of the 3 bellow have to happen in order for the issue to occur.
### Internal pre-conditions
Optional:
1. The interest becomes to high.

### External pre-conditions
Optional:
1. The price of the collateral drops
2. The price of the debt goes up

### Attack Path

None

### Impact
Loss of funds

### PoC
None

### Mitigation
Don't allow for pools to reach 100% utilization.