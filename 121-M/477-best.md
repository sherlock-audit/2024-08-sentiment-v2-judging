Stale Cyan Fish

Medium

# `RedstoneOracle` priceTimestamp can be acurately determined , eliminating the need for a -3 mins worst case scenario

### Summary

`RedstoneOracle` sets the `priceTimestamp` of a price feed update to `block.timestamp` - 3 mins. Assuming the worst case, `priceTimestamp` is 3 mins behind the actual timestamp of price update ,this 3 min lag is significant enough to dos the oracle when the price feed is not yet stale.

Especially when it is possible to retrieve the actual timestamp by overriding the `validateTimestamp` function.

### Root Cause

In `RedstoneOracle::updatePrice` it is assumed that the price timestamp of the price feed cannot be retrieved: 

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/RedstoneOracle.sol#L60

```solidity
 function updatePrice() external {
        // values[0] -> price of ASSET/USD
        // values[1] -> price of ETH/USD
        // values are scaled to 8 decimals
        uint256[] memory values = getOracleNumericValuesFromTxMsg(dataFeedIds);

        assetUsdPrice = values[0];
        ethUsdPrice = values[1];

        // RedstoneDefaultLibs.sol enforces that prices are not older than 3 mins. since it is not
        // possible to retrieve timestamps for individual prices being passed, we consider the worst
        // case and assume both prices are 3 mins old 
    ->  priceTimestamp = block.timestamp - THREE_MINUTES;
    }
```

However this is not correct as we see in the `getOracleNumericValuesFromTxMsg` function and from the redstone docs:

```solidity
  function getOracleNumericValuesFromTxMsg(bytes32[] memory dataFeedIds)
    internal
    view
    virtual
    returns (uint256[] memory)
  {
    (uint256[] memory values, uint256 timestamp) = _securelyExtractOracleValuesAndTimestampFromTxMsg(dataFeedIds);
->  validateTimestamp(timestamp);
    return values;
  }

/**
   * @dev This function may be overridden by the child consumer contract.
   * It should validate the timestamp against the current time (block.timestamp)
   * It should revert with a helpful message if the timestamp is not valid
   * @param receivedTimestampMilliseconds Timestamp extracted from calldata
   */
  function validateTimestamp(uint256 receivedTimestampMilliseconds) public view virtual {
    RedstoneDefaultsLib.validateTimestamp(receivedTimestampMilliseconds);
  }
```

The `validateTimestamp` function can be overridden. It's possible to retrieve the actual timestamp by overriding the `validateTimestamp` function and prevent any possible oracle DOS due to the time lag.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Possible Oracle DOS due to lagging priceTimestamp

### PoC

_No response_

### Mitigation

Override `validateTimestamp` to retrieve the actual timestamp, as an example:

```solidity
function validateTimestamp(uint256 timestamp) public view override {
  priceTimestamp = timestamp;
  super.validateTimestamp(timestamp);

}
```