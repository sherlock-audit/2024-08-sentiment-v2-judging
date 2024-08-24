Sharp Sapphire Ferret

Medium

# Users can front-run oracle price changes and force bad debt into the system

## Summary
Users can front-run oracle price changes and force bad debt into the system.

## Vulnerability Detail
Using oracles allows users to front-run price changes on any network with a mempool. Users can exploit these price changes combined with leveraged positions to manipulate the system and its liquidity providers, leaving massive amounts of bad debt behind.

To open leveraged positions, a user needs to deposit collateral X, borrow asset Y, and then swap Y for X. This approach allows the user to have an exponential impact. The formula to calculate leverage is:

$$
\frac{1}{1 - \text{LTV}} = \text{leverage}
$$

For example, if we have a 95% LTV, we can achieve 10x leverage:

$$
\frac{1}{1 - 0.95} = 10
$$

With such leverage, even a small change in price will have a massive impact. With 95% LTV, a 5% change in price is enough to cause bad debt, and only a 2% change with 98% LTV. This leverage also determines the extent to which the pool is affected, for instance, 1 ETH at 10x leverage will cause 10 ETH worth of bad debt.

Example:
| *Prerequisites*               | *Values* |
|-------------------------------|----------|
| TokenX : TokenY LTV           | 95%      |
| TokenX Price                  | 1000 USD |
| TokenY Price                  | 100 USD  |

1. Alice observes a 5% change in the price of TokenX.
2. She front-runs the price change, deposits 1 X as collateral into her position, and borrows Y at 95% LTV.
3. She swaps or converts Y to X and continues borrowing until she has 20 X as collateral (valued at 20,000 USD) and has borrowed 19,000 USD worth of Y.
4. The price change occurs, and Alice's collateral is now valued at 19,000 USD, while her debt remains at 19,000 USD.

Since Alice's position is now unhealthy, any liquidator can liquidate her. However, no one will, as liquidating her would result in a loss for the liquidator. Alice's position then needs to be liquidated as bad debt using [liquidateBadDebt](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L446-L464), causing 19,000 USD of bad debt to all of the lenders.

## Impact
Users can gain massive profits from price changes, leading the system to accrue bad debt.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L384-L402
```solidity
    function borrow(address position, bytes calldata data) internal {
        uint256 poolId = uint256(bytes32(data[0:32]));
        uint256 amt = uint256(bytes32(data[32:64]));


        if (pool.ownerOf(poolId) == address(0)) revert PositionManager_UnknownPool(poolId);

        pool.borrow(poolId, position, amt);

        Position(payable(position)).borrow(poolId, amt);
        emit Borrow(position, msg.sender, poolId, amt);
    }
```
## Tool Used
Manual Review

## Recommendation
Implement a deposit/borrow window that prevents users from depositing and borrowing in the same transaction. For example, this window could be 1 hour or 1 day.