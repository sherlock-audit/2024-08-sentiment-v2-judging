Keen Jetblack Turtle

Medium

# healthy operations will revert if they don't bring the loan fully healthy

## Summary
Healthy operations, like increase collateral, repay, addToken, will still revert if they don't bring the loan back to a healthy state.
## Vulnerability Detail
At then end of `process()` or `processBatch()`, it will be always checked if the position is healthy

```solidity
    function process(address position, Action calldata action) external nonReentrant whenNotPaused {
        _process(position, action);
@>        if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
    }
```

```solidity
    function processBatch(address position, Action[] calldata actions) external nonReentrant whenNotPaused {
        // loop over actions and process them sequentially based on operation
        uint256 actionsLength = actions.length;
        for (uint256 i; i < actionsLength; ++i) {
            _process(position, actions[i]);
        }
        // after all the actions are processed, the position should be within risk thresholds
@>        if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
    }
```

This effectivelly blocks users from repaying or increasing the health of their position.

### PoC
No partial repayment allowed 

## Impact
The current check, dosses protocol users from improving the health of their position

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L231
## Tool used

Manual Review

## Recommendation
The simplest way to solve this problem is to skip the check on deposit/addToken/repay in the `process()` function

```diff
    function process(address position, Action calldata action) external nonReentrant whenNotPaused {
        _process(position, action);
++        if (action.op == Operation.Repay || action.op == Operation.Deposit || action.op == Operation.AddToken) return;
       if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
    }
```
