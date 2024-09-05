Bitter Sandstone Worm

Medium

# Pool::liquidate() - There are several situations where there will be no incentive for the liquidator to liquidate a unhealthy position

### Summary
In lending/borrowing protocols, [liquidations](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L430) are done by liquidators who are users (or bots) that liquidate positions based of an incentive. For example repaying 100$ debt and receiving 110$ in return, so they turn a 10$ profit.

If there are no incentives to liquidate someone, then liquidators won't liquidate them, so it's very important to always have an incentive otherwise the protocol can incur bad debt.

In Sentiment there are several ways for liquidators to not have an incentive to liquidate an unhealthy position.

1. Dust positions: A user can have a position with up to 5 dust loans. In this situation the gas that the liquidator has to pay (especially on mainnet) will outweigh the amount of collateral they will receive in return for repaying the loan.
2. User gets his collateral blacklisted: If position has collateral which supports blacklisting like USDC/USDT, which are both supported by the protocol. If the position is blacklisted, then the collateral cannot be transferred, so the liquidator won't be able to receive it, thus tanking his incentive significantly.
3. Liquidation fee: The protocol implements a liquidation fee, which is a % of the collateral that goes to the `owner()` when a position gets liquidated. When the fee is applied, there might not be enough tokens as an incentive for the liquidator, in extreme cases he might even lose money if he liquidates a position.
4. Very high LTV assets: The protocol has provided [these example values](https://gist.github.com/ruvaag/58c9fc2e5c139451c83c21fda27b77a2). We can see that WETH has 95% LTV. This means that the liquidator can get a max discount of 5%, trying to get the full 10% discount is impossible since there won't be enough tokens in the position. This combined with a smaller loan and higher gas costs diminish the incentive for liquidations.

Example of point 3:
I'll be using $ values to simplify the example:

1. Liquidation fee is 20%.
2. Position has USDC as collateral with 90% LTV.
3. The position has 100$ collateral and their debt is 92$ so they can be liquidated.
4. The liquidator is expecting to pay 92$ of debt and retrieve 100$ worth of collateral, netting a 8$ profit.
5. But because of the 20% liquidation fee, he will actually receive 80$ worth of collateral, since 20$ (20%) go to the owner as part of the liquidation fee. In this case he will actually lose 12$ for repaying the debt, which he obviously won't do.


### Root Cause
There are several causes:
1. Allowing `minDebt` and `minBorrow` to be 0 or a very small value. The README of the contest states:
> Min Debt = from 0 to 0.05 ETH = from 0 to 50000000000000000 Min Borrow = from 0 to 0.05 ETH
2. Collateral with high LTV (~90% and up) and higher liquidation fee diminish the incentive for liquidations substantially and can even cause loses.
> Min LTV = 10% = 100000000000000000 Max LTV = 98% = 980000000000000000
> Liquidation Fee = 0 (Might be increased to 20-30% in the future)
3. Higher liquidation fees.

### Internal pre-conditions
One or all of the following, they can all cause the lack of incentive:
1. `minDebt` and `minBorrow` equal 0 or a very small number.
2. High LTV assets.
3. Liquidation fee combined with a relative LTV.

### External pre-conditions
None

### Attack Path
None

### Impact
No incentive to liquidate positions, which can lead to bad debt and loss of funds for users in the long run.

### PoC
None

### Mitigation
Enforce a higher `minDebt` and `minBorrow`. Enforce a smaller or no liquidation fee. Decrease max allowed LTV.