Expert Lipstick Okapi

Medium

# `SuperPool` is ERC-4626 compliant, but the `maxWithdraw` & `maxRedeem` functions are not fully up to EIP-4626's specification

## Summary
The `maxWithdraw` & `maxRedeem` functions should return the `0` when the withdrawal is `paused`, but in this case it is not returning 0.
## Vulnerability Detail
SuperPool can be paused, since it is pausable contract and also there is a function `togglePause()` , also in the readMe it is specifically written that `superPool` is supposed to be strictly ERC4626 compliant, i.e any issue arising from non compliance should be taken into account and will be a valid issue in this case.

According to [EIP-4626 specifications](https://eips.ethereum.org/EIPS/eip-4626):

`maxWithdraw`
```solidity
MUST factor in both global and user-specific limits, like if withdrawals are entirely disabled (even temporarily) it MUST
 return 0.
 ```
 `maxRedeem`
 
 ```solidity
MUST factor in both global and user-specific limits, like if redemption is entirely disabled (even temporarily) it MUST
 return 0.
 ```


But it is not enforced in our case and the `maxWithdraw` and `maxRedeem` functions are not having any logic to return 0 when to whole contract is paused and withdraw and redeem is disabled in that case.
## Impact

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L220-L223

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L226-L232
## Tool used

Manual Review

## Recommendation
Include a logic for returning 0 when the contract is paused.