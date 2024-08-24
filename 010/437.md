Abundant Maroon Pangolin

Medium

# An attacker can pick up a new price that is older than the current stored one

### Summary

Contract implementation uses the current `block.timestamp - 3 minutes` as the timestamp for when a price was observed rather than using actual observation timestamp associated with the price itself. This allows an attacker to set the price to an older value and to be considered fresher. 

### Root Cause

1. Redstone's `validateTimestamp` allows a user to pick up a price from the interval [3 minutes in the past, 1 minute in the future];[ See timestamp validation [here](https://github.com/redstone-finance/redstone-oracles-monorepo/blob/94ac46f41be52ee9132bede9d13897f5922c800d/packages/evm-connector/contracts/core/RedstoneDefaultsLib.sol#L28-L31)
The call chain is like :
`RedstoneCoreOracle.updatePrice` ->`RedstoneConsumerNumericBase.getOracleNumericValuesFromTxMsg` ->`validateTimestamp`
2. The `RedstoneCoreOracle.updatePrice`  has no extra time validation.
3. The attack is possible becasue a signed payload calldata (containing price and timestamp associated with it) must pe passed to `getOracleNumericValuesFromTxMsg` which is called from our `updatePrice` function.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

First we need to understand how prices are updated in Redstone oracle context. 
From their [docs](https://docs.redstone.finance/docs/get-started/data-formatting-processing#context) we can see that package of  prices and their associated timestamp are injected into a user tx. After the package is validated prices can be consumed. 

`
Transferring data to a blockchain requires packing an extra payload to a user’s transaction and processing the 
message on the blockchain. Said differently, the data that is put on the blockchain, such as a cryptocurrency’s price,
is inserted into part of the data that makes up a user’s transaction. 
`

1. Redstone payload is appended as calldata when `updatePrice` is called, before prices are consumed (before `getValueInEth` is called, ideally in same tx).  The payload contains [price, timestamp] = [p1, 100] that passes the (-3,+1) minutes [validation](https://github.com/redstone-finance/redstone-oracles-monorepo/blob/94ac46f41be52ee9132bede9d13897f5922c800d/packages/evm-connector/contracts/core/RedstoneDefaultsLib.sol#L27-L33)
2. An attacker can pick up an older payload (eg. [price, timestamp] = [p2, 98]) that also passes the timestampValidation, but with an older price (prices) than the curent saved one. (saved in `assetUsdPrice`, `ethUsdPrice`). Attacker call `updatePrice` with this old payload.
3. Next attacker calls `getValueInEth` (from borrowing, liquidate, etc). Stale price check passes since the `priceTimestamp = block.timestamp - THREE_MINUTES;`  is bigger than `block.timestamp - STALE_PRICE_THRESHOLD` used in if stale check.

### Impact

Asset prices up to 3 minutes old can be consumed by an attacker.

### PoC

_No response_

### Mitigation

1. Since the payload contains timestamp bounded to the price itself, save this timestamp instead of current `block.timestamp - THREE_MINUTES;` Do not update the price if the new timestamp is older than the saved time. 

```solidity
  if (calldataTimestamp < priceTimestamp) return;
          assetUsdPrice = values[0];
          ethUsdPrice = values[1];

priceTimestamp = calldataTimestamp;
```