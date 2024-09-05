Glamorous Blush Gecko

Medium

# The RedstoneCoreOracle has a constant stale price threshold, this is dangerous to use with tokens that have a smaller threshold as the oracle will report stale prices as valid

### Summary

Different tokens have different `STALE_PRICE_THRESHOLD`. The protocol uses a constant `STALE_PRICE_THRESHOLD = 3600` for all tokens in the RedstoneCoreOracle. 

The issue arises when the token actually has a STALE_PRICE_THRESHOLD < 3600, then the oracle will report the stale price as valid. 

Here are some tokens whose redstone priceFeed has a STALE_PRICE_THRESHOLD < 3600 (1 hour)

1. TRX/USD 10 minutes
2. BNB/USD 1 minute

### Root Cause

using a [constant](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/oracle/RedstoneOracle.sol#L19) `STALE_PRICE_THRESHOLD = 3600`, rather than setting one for each token

### Internal pre-conditions

_No response_

### External pre-conditions

Token has a threshold < 3600

### Attack Path

_No response_

### Impact

The protocol will report stale prices as valid, this results in collateral being valued using stale prices.

It will lead to unfair liqudiations due to stale price valuation of collateral AND/OR a position not being liquidated due to stale price valuation of collateral

It will also lead to borrowing a wrong amount due to stale price valuation of collateral

### PoC

_No response_

### Mitigation

Set a unique `STALE_PRICE_THRESHOLD` for each token, similar to the chainlink oracle