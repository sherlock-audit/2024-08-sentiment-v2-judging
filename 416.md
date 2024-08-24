Flat Navy Bee

Medium

# Deviation in oracle price could lead to arbitrage in high ltv markets

## Summary

Since there is no borrow/withdraw fee in current pool implementation, arbitrageurs can always take advantage of liquidation discounts in high LTV markets to arbitrage.

## Vulnerability Detail

In sentiment v2, Positions remain healthy when `totalAssetValue >= minReqAssetValue`:
```solidity
function isPositionHealthy(address position) public view returns (bool) {
        // a position can have four states:
        // 1. (zero debt, zero assets) -> healthy
        // 2. (zero debt, non-zero assets) -> healthy
        // 3. (non-zero debt, zero assets) -> unhealthy
        // 4. (non-zero assets, non-zero debt) -> determined by weighted ltv

        (uint256 totalDebtValue, uint256[] memory debtPools, uint256[] memory debtValueForPool) =
            _getPositionDebtData(position);
        if (totalDebtValue == 0) return true; // (zero debt, zero assets) AND (zero debt, non-zero assets)

        (uint256 totalAssetValue, address[] memory positionAssets, uint256[] memory positionAssetWeight) =
            _getPositionAssetData(position);
        if (totalAssetValue == 0) return false; // (non-zero debt, zero assets)

        uint256 minReqAssetValue =
            _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);
        return totalAssetValue >= minReqAssetValue; // (non-zero debt, non-zero assets)
    }
```

When we consider positions that use only one type of collateral Token(asset1) and borrow only one type of debt Token(asset2), The constraints can be simplified as: 

    oracle.getValueInEth(asset1, asset1.balanceOf(position)) >= oracle.getValueInEth(asset2, pool.getBorrowsOf(poolId, position)) / LTV

This means the maximum amount a user can borrow is calculated with the conversion rate between debt Token and collateral Token returned by oracle:

    maxBorrow = collateral * collateralPriceInETH * ltv / debtPriceInETH

(We ignore rounding directions here because they only make up a small percentage)

However, Chainlink oracles are updated after the change in price crosses a deviation threshold, (eg. 0.5% in ETH / USD), which means a price feed could return a value slightly smaller/larger than an asset's actual price under normal conditions. So Chainlink oracles are susceptible to front-running as their prices tend to lag behind an asset's real-time price.

An attacker could exploit the difference between the price reported by an oracle and the asset's actual price to gain a profit by front-running the oracle's price update.

For Sentiment v2, this becomes profitable when the price deviation is sufficiently large for an attacker to open positions that become bad debt. Mathematically, arbitrage is possible when:

    price deviation * 1 / (1 - Liquidation Discount) - LTV > 0.

As seen from above, the conversion rate between loan Token and collateral Token is calculated with two price feeds, with each of them having their own deviation threshold. This amplifies the maximum possible price deviation returned by `getValueInEth`.

For example:

• Assume arbitrager uses FTM as collateral Token and LDO as loan Token.
• Assume the following prices:
  – 1 FTM = 0.0002 ETH
  – 1 LDO = 0.0005 ETH
• ChainlinkOracle will be set up as such:
https://data.chain.link/feeds/ethereum/mainnet/ftm-eth
https://data.chain.link/feeds/ethereum/mainnet/ldo-eth
  – priceFeedFor[FTM] - FTM / ETH, 3% deviation threshold.
  – priceFeedFor[LDO] - LDO / ETH, 0.5% deviation threshold.
  – QUOTE_FEED_1 - FTM / ETH, 3% deviation threshold.
  – QUOTE_FEED_2 - ETH / USD, 2% deviation threshold.
• Assume that all price feeds are at their deviation threshold:
  – FTM / ETH returns 97% of 0.0002, which is 0.000194.
  – LDO / ETH returns 102% of 0.0005, which is 0.00051.
• The actual conversion rate of FTM to LDO is: 
  – 0.00051 / 0.000194 = 2.628866
  – i.e. 1 LDO = 2.628866 FTM.
• Compared to 1 LDO = 2.5 FTM, the maximum price deviation is 4.8%.

To demonstrate how a such a deviation in price could lead to arbitrage:
• Assume the following:
  – A pool has 96% LTV, with FTM as loanToken.
  – 1 LDO is currently worth 2.5 FTM.
• The price of LDO drops while FTM increases in value, such that 1 LDO = 2.628866 FTM.
• Both Chainlink price feeds happen to be at their respective deviation thresholds as described above, which means the oracle's price is not updated in real time.
• An attacker sees the price discrepancy and front-runs the oracle price update to do the following:
  – Deposit 10000 LDO as collateral.
  – Borrow 24000 FTM, which is the maximum he can borrow at 96% LTV and 1 LDO = 2.5 FTM conversion rate.
• Afterwards, the oracle's conversion rate is updated to 1 LDO = 2.628866 FTM.
  – Attacker's position is now unhealthy as his collateral is worth less than his loaned amount.
• Attacker back-runs the oracle price update to liquidate himself:
  – At 96% LTV, Liquidation Discount = 10%.
  – He repays 24742 FTM. (FTM/ETH drops 3%)
  – He grabs 11111 LDO
    * Assets / 1- discount = 10000 LDO / 0.9 = 11111 LDO
• He has gained 1111 LDO - 742 FTM = 828 LDO worth of profit using 10000 LDO, which is a 8.28% arbitrage opportunity.

## Impact

Loss of protocol fund due to arbitrage.

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L67

## Tool used

Manual Review

## Recommendation

Consider implementing a borrowing fee to mitigate against arbitrage opportunities.
Ideally, this fee would be larger than the oracle's maximum price deviation so that it is not possible to
profit from arbitrage.
Further possible mitigations have also been explored by other protocols:
• [Angle Protocol: Oracles and Front-Running](https://medium.com/angle-protocol/angle-research-series-part-1-oracles-and-front-running-d75184abc67)
• [Liquity: The oracle conundrum](https://www.liquity.org/blog/the-oracle-conundrum)