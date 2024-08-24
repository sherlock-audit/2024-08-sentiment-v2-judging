Melted Honey Deer

High

# Only Multisig or Governance can liquidate bad debt

## Summary
Owner of the `PositionManager` contract will be multisig, initially by the team and eventually by governance. function `liquidateBadDebt` uses `onlyOwner` modifier but it's not feasible for them to do this many times. 

## Vulnerability Detail
The `liquidateBadDebt` function currently uses the `onlyOwner` modifier, restricting its execution to the contract owner. This design presents a significant operational inefficiency, as the owner (a multisig wallet) or governance is required to execute this function multiple times, which is not due to frequency of liquidations of bad debt in case of sudden price actions.


## Impact
Protocol will accumulate bad debt. 

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L446

## Tool used

Manual Review

## Recommendation
Use different role/address for liquidations.