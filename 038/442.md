Shambolic Cobalt Copperhead

Medium

# Users wont be able to set approve 0 for unknown spenders in an edge case

## Summary
Users wont be able to set approve 0 for unknown spenders, which was previous known and was approved max.
## Vulnerability Detail
PositionManager::approve() will revert if a spender is unknown
```solidity
if (!isKnownSpender[spender]) revert PositionManager_UnknownSpender(spender);
```
The problem is that it does not consider the case where the unknown spender was previously known and has been approved max by the user. In this case, there is no way to approve 0 this unknown spender, and it can still freely move the asset token in position toother places, since after being approved max,  allowance wont be decreased after transfer for most erc20 tokens.

Consider this scenario:
1. Spender A has been added into known spender.
2. User B has approved max spender A for their position.
3. Spender A is now removed from known spender (becoming unknown spender).
4. Spender A still have max allowance of user B' position and can transfer user B' allowed token anytime.
5. There is no way for user B to approve 0 this spender A.
## Impact
Unknown spenders in this scenario can freely transfer money from positions to other places. Might be risky if the spender is malicious.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L351
## Tool used

Manual Review

## Recommendation
Consider checking position's allowance for this spender; if it is not 0, it means that this spender was known before so allowance should be set to 0; 

```solidity
if (!isKnownSpender[spender]) { 
      if (asset.allowance(position, spender) != 0) {
            Position(payable(position)).approve(asset, spender, 0);
      } else {
         revert PositionManager_UnknownSpender(spender);
      }
};
```