Sparkly Taffy Fly

Medium

# Liquidator will incur losses during liquidation leading to bad debt accumulation

### Summary

The lack of handling for bad debt in `PositionManager.sol` will cause an economic disincentive for liquidators, leading to potential bad debt accumulation for the protocol as liquidators will avoid liquidating positions with insufficient collateral.


### Root Cause

In [`PositionManager.sol: _repayPositionDebt`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L484-L500) the function assumes full debt repayment by the liquidator without considering the available collateral.


### Internal pre-conditions

1. A position must have debt exceeding its collateral value.
2. The liquidator must attempt to liquidate the position.

### External pre-conditions

1. The value of the collateral must drop significantly, causing the debt to exceed the collateral value.

### Attack Path

1. A position's collateral value drops below its debt value.
2. A liquidator attempts to liquidate the position.
3. The liquidator is required to repay the full debt amount, which exceeds the collateral value.
4. The liquidator incurs a loss, making it economically unfeasible to proceed with the liquidation.
5. Liquidators avoid liquidating such positions, leading to bad debt accumulation in the protocol.


### Impact

The protocol suffers from bad debt accumulation as liquidators avoid liquidating positions with insufficient collateral, leading to potential financial instability.

### PoC

1. Assume a position has a debt of 1000 USDC and collateral worth 800 USDC.
2. The liquidator attempts to liquidate the position.
3. The liquidator is required to repay the full 1000 USDC debt.
4. The liquidator incurs a loss of 200 USDC (1000 USDC debt - 800 USDC collateral).
5. Liquidators avoid such liquidations, leading to bad debt accumulation.

### Mitigation

Modify the [`_repayPositionDebt` function](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L484-L500) to handle partial debt repayment based on available collateral. This ensures liquidators only repay what is economically feasible, preventing bad debt accumulation.

```diff
function _repayPositionDebt(address position, DebtData[] calldata debtData) internal {
    // sequentially repay position debts
    // assumes the position manager is approved to pull assets from the liquidator
    uint256 debtDataLength = debtData.length;
    for (uint256 i; i < debtDataLength; ++i) {
        uint256 poolId = debtData[i].poolId;
        address poolAsset = pool.getPoolAssetFor(poolId);
        uint256 amt = debtData[i].amt;
        uint256 positionDebt = pool.getBorrowsOf(poolId, position);

        // if the passed amt is type(uint256).max assume repayment of the entire debt
        if (amt == type(uint256).max) amt = positionDebt;

+       // calculate the maximum repayable amount based on the liquidator's balance
+       uint256 liquidatorBalance = IERC20(poolAsset).balanceOf(msg.sender);
+       uint256 repayAmount = amt > liquidatorBalance ? liquidatorBalance : amt;

-       // transfer debt asset from the liquidator to the pool
-       IERC20(poolAsset).safeTransferFrom(msg.sender, address(pool), amt);
-       // trigger pool repayment which assumes successful transfer of repaid assets
-       pool.repay(poolId, position, amt);
-       // update position to reflect repayment of debt by liquidator
-       Position(payable(position)).repay(poolId, amt);

+       // transfer debt asset from the liquidator to the pool
+       IERC20(poolAsset).safeTransferFrom(msg.sender, address(pool), repayAmount);
+       // trigger pool repayment which assumes successful transfer of repaid assets
+       pool.repay(poolId, position, repayAmount);
+       // update position to reflect repayment of debt by liquidator
+       Position(payable(position)).repay(poolId, repayAmount);

+       // handle remaining debt if any
+       if (repayAmount < positionDebt) {
+           // logic to handle remaining debt, e.g., updating records, notifying stakeholders, etc.
+       }
    }
}
```