Flat Tawny Haddock

High

# User's can create non-liquidateable positions by leveraging `rebalanceBadDebt` to decrease share price

## Summary
User's can create non-liquidateable positions by leveraging `rebalanceBadDebt` to decrease share price

## Vulnerability Detail
The `rebalanceBadDebt` function decreases the deposit assets while the deposit shares are kept the same

```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        
        ....

        // rebalance bad debt across lenders
        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
```

The deflates the value of a depositors share and hence a deposit afterwards will lead to a massive amount of shares being minted. An attacker can leverage this to create pools such that the total share amount will become ~type(uint.max). After this any query to many of the pool's functions including `getBorrowsOf` will revert due to the overflow. This can be used to create positions that borrow from other pools and cannot be liquidated

Eg:
attacker creates a pool for with with 1e18 assets and 1e18 shares
attacker borrows 1e18 - 1. the position goes into bad debt and `rebalanceBadDebt` is invoked
now assets left = 1 and shares = 1e18
attacker deposits 1e18 tokens and gets 1e36 tokens in return
attacker repeates the process by borrowing 1e18 tokens, being in bad debt, getting `rebalanceBadDebt` invoked and delfating the share value

since the attacker has full control over the increase by choosing the deposit amount, they can make it reach a value near type(uint).max
followed by a borrow from this infected pool and from other pools from which they attacker really wanted to borrow
after some time, the interest increase will make the corresponding fee share cause overflow for the pool shares and hence the `getBorrowsOf` and `isPositionHealthy` functions to revert preventing liquidations of the attackers position

## Impact
User's can create unliquidateable positions and make protocol accrue bad debt/depositors from other pools loose assets

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L547

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L212-L213

## Tool used
Manual Review

## Recommendation
Can't think of any good solution if a position has to have the ability to borrow from multiple pools using the same collateral backing