Bubbly Wool Pike

Medium

# [M-4] Missing Implementation of Pausing Mechanism for Withdrawals in the Pool Contract

## Summary
If the Pool is in a paused state withdrawals are still enabled
## Vulnerability Detail
In the Pool contract, the `Pool::deposit` function can be paused, allowing the protocol to temporarily halt deposits during emergency situations. However, the `Pool::withdraw` function is not protected by the same pausing mechanism. According to communication with the protocol sponsor, "it was intended that withdrawals would be paused when the PositionManager is paused". However, after reviewing the codebase, it was found that this functionality has not been implemented.

This discrepancy suggests that either the pausing of withdrawals was mistakenly omitted from the implementation or it was an intended design choice that needs to be explicitly addressed.

## Impact
 If the protocol encounters a situation where withdrawals need to be paused (e.g., during a security incident or market instability), the inability to pause withdrawals could lead to a drain on the protocol's liquidity, further exacerbating the situation.
There's also the issue of Inconsistency with Protocol Design.

## Code Snippet
https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/Pool.sol#L339
## Tool used

Manual Review

## Recommendation
To ensure consistency and operational security, consider the following actions:

Implement Pausing Mechanism for Withdrawals, or implement a similar mechanism that pauses withdrawals when the `PositionManager` is paused:




