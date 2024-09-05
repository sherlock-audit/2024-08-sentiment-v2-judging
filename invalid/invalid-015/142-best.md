Cheery Scarlet Hippo

Medium

# Potential for Incorrect Asset Pricing by ChainlinkEthOracle If the Underlying Aggregator Hits its minAnswer Limit

### Summary

Chainlink aggregators include a built-in mechanism to prevent an asset's price from straying beyond a predetermined range. However, this safety feature can result in the oracle consistently returning the minPrice instead of the true asset price during a sharp decline, as seen during the LUNA crash.


### Root Cause

In ChainlinkEthOracle.sol (lines 100-104) (https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L100-L104) and ChainlinkUsdOracle.sol (lines 115-119) (https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L115-L119), there are calls to latestRoundData(), but the code lacks validation for cases where the token price drastically drops or increases. This could lead to a situation where the token price is much lower or higher than the actual price, creating an attack vector where a user could borrow at an incorrect price, bypassing the checks in the repay and borrow functions.

Similar issues:

https://solodit.xyz/issues/m-7-risk-of-incorrect-asset-pricing-by-stableoracle-in-case-of-underlying-aggregator-reaching-minanswer-sherlock-none-ussd-autonomous-secure-dollar-git
https://github.com/code-423n4/2023-07-moonwell-findings/issues/340
https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/18

### Internal pre-conditions

(If the price of the token drops drastically and the `minPrice` is $1, but the actual price is $0.10):
1. Users will not be able to partially repay their debt because they would need to pay 10 times more to meet the condition specified here: [Pool.sol#L511](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L511).
2. Users could borrow tokens below the `minBorrow` limit.
3. The overall protocol could be manipulated because the oracle returns an incorrect price for the asset.

### External pre-conditions

1. Token needs to drastically drop in price (below Oracle's `minPrice`) or to increase in price over `maxPrice`.

### Attack Path

For example, consider a pool with a `minBorrow` of $10:
1. The price of the asset drops below the `minPrice` (where `minPrice` is $1).
2. A user borrows 10 tokens, which have a real value of $2, but the protocol considers them to be worth $20, allowing the user to borrow tokens below the `minBorrow` limit.

### Impact

Users can exploit inflated prices to manipulate the borrowing and repayment functions.

### PoC

_No response_

### Mitigation

Add `minPrice` and `maxPrice` validation like that:
```solidity
          require(price < _maxPrice, "Upper price bound breached");
          require(price > _minPrice, "Lower price bound breached");
```
Here's the reference where to obtain `minPrice` and `maxPrice`:
https://docs.chain.link/data-feeds#check-the-latest-answer-against-reasonable-limits