Deep Cedar Hare

Medium

# RedstoneOracle lacks proper validation

## Summary
The RedstoneOracle considers a fetched price of `0` as a valid price and caches this value in storage. As a result, the priced asset will be undervalued during `RedstoneOracle::getValueInETH` calls. 

## Vulnerability Detail
RedstoneOracle does not validate the fetched price from the [getOracleNumericValuesFromTxMsg internal function call](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/RedstoneOracle.sol#L52-L55).  If the fetched price is `0`, then this invalid price will be cached in storage. A `0` price for the `assetUsdPrice` will result in the [getValueInETH](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/RedstoneOracle.sol#L63-L71) function returning `0` for any asset amount. 

## Impact
An invalid `assetUsdPrice` of `0` can enable a malicious user to borrow (steal) all the asset from the base pool since the value of any borrow amount in this state will be valued at `$0` and thus will not require any collateral backing. This state can essentially allow free borrows. 

Internal Conditions: 
- Redstone oracle is used for borrow asset in base pool
- `minBorrow` and `minDebt` are both set to `0`

External Conditions: 
- Oracle malfunction returns price of `0` for `ASSET_FEED_ID`

Given the high impact and constraints above, I have chosen to label this report as Medium severity. 

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/RedstoneOracle.sol#L52-L55

## Tool used
Manual Review

## Recommendation
I would recommend validating the return values from the `getOracleNumericValuesFromTxMsg` call in `RedstoneCoreOracle::updatePrice`. If any of the values are equal to zero, the `updatePrice` function call should revert so that invalid prices do not get cached in storage. 