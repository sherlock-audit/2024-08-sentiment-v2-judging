Sharp Sapphire Ferret

Medium

# Small loans can extend the TVL of any position up to 90%

## Summary
Users can exploit the `minDebt` feature to extend their LTV up to 90% for risky assets.

## Vulnerability Detail
The system uses a `minDebt` threshold to ensure that positions are profitable for liquidation. Loans below this amount may not be profitable to liquidate, as liquidators would incur gas fees, increasing their costs.

The [repay](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L506-L514) function checks if the borrowed amount is below `minDebt` and reverts the TX if it is.

```solidity
        remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        if (remainingShares > 0) {
            uint256 newBorrowAssets = _convertToAssets(
                remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Down
            );
            if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
                revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
            }
        }
```

Liquidators also cannot seize the entire position. They are limited to a maximum of `debt repaid * 1e18 / 0.9e18`, which is 11% more than what they have to repay. That's their profit.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L156-L159

```solidity
        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
        if (assetSeizedValue > maxSeizedAssetValue) {
            revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
        }
```

Users combine the above 2 mechanics and game the system by taking small loans that prevent liquidators from fully liquidating their position due to the `minDebt` limit, while also making partial liquidation unprofitable.

**Example:**
1. A WETH pool has risky collateral - token X with an LTV of 50%.
2. Alice opens a position with collateral X valued at 0.05 ETH (equal to `minDebt`).
3. She borrows 0.25 WETH from the pool.
4. The asset’s price drops, increasing her LTV to 55%.

Alice won’t be liquidated because any liquidation attempt would leave her position below `minDebt`, causing the transaction to revert. Liquidators must wait until her LTV reaches 90% to perform a full liquidation (~0.045 debt, for 0.05 col). 

Alice can also avoid paying her debt, as the risky asset might very well quickly cross the gap between 90% and 100% and make her position insolvent, causing bad debt. She can abuse this on chains with low fees (ARB, BASE, OP) and create multiple position borrowing from the pool.

## Impact
The core LTV mechanism is broken. Users can leverage risky assets with high LTV, increasing the system’s exposure to bad debt.

## Code Snippet
```solidity
        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
        if (assetSeizedValue > maxSeizedAssetValue) {
            revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
        }
```

## Tool Used
Manual Review

## Recommendation
Allow liquidators to fully liquidate a position if the remaining value is less than `minDebt`.