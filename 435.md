Joyous Cream Coyote

High

# Even if an asset's `isKnownAsset` is turned off, users can keep borrowing against it

### Summary

`isKnownAsset` is a whitelist of the assets that users can use in their positions as potential collaterals. However, when toggling an `isKnownAsset` off, and disallowing it for further usage, multiple problems arise. 
1- in case the oracle is still providing the price feed, users can continue to borrow against that asset.
2- Users that previously had their funds inside the protocol can not take it out. 
3- Users can further transfer funds into the positions and can grow the position larger.
Managing such situations is indeed important, as assets evolve and many can become deprecated over the years or their price feed stops working. In such cases `isKnownAsset` should be turned off  to protect the users.

### Root Cause

- [`PositionManager.sol:316`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L316) blocks transfer functionality. This locks in the assets inside the contract. The only way to get them out of the contract is to liquidate them.
- [`PositionManager.sol:334`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L334) does not actually block depositing into the position.
- [`PositionManager.sol:350`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L350) blocks approve and users can not transfer the tokens out of the protocol.
- [`PositionManager.sol:411`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L411) only stops the tokens from being added to the pool after `isKnownAsset` is turned off, and it does not remove the ones that are already added.
- [`Position.sol:65`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Position.sol#L65-L67) still returns the removed token, and [`RiskModule:_getPositionDebtData`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L202) still loops through all the available pools.
- The oracle for the previously `isKnownAsset` can not be removed, or the price be set to zero. In each case honest users will face problems.

### Internal pre-conditions

- An `isKnownAsset` is being deprecated and it needs to be turned off.

### External pre-conditions

N/A

### Attack Path

- An attacker waits until the `toggleIsKnownAsset` for a known asset is called.
- The attacker opens a position with the previously set `isKnownAsset`.
- After the `isKnownAsset` is called, attacker can continue to grow the position but can not take anything out.

### Impact

- Since the asset is still included in the assets array, it continues to count towards collateral.
- if the oracle price is kept, after some time that the price is deprecated, the oracle price might deviate from the market price and give infinite arbitrage opportunity to the attacker.
- If the oracle with zero price value is set for the token, users that that this asset can get liquidated and lose all of the assets to liquidators.
- User's assets become locked in the protocol.
- Malicious users can still transfer more assets into the position to take advantage of the deprecated tokens.

### PoC

N/A

### Mitigation

- Don't count the assets that are not `isKnownAsset` inside the array towards the collateral.
- Allow users to take back their tokens.