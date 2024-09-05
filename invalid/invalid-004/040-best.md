Polished White Coyote

Medium

# Authorization Bypass Risk at toggleAuth  function in PositionManager contract

### Summary

Line: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L217

 The toggleAuth function allows the owner of a position to toggle the authorization of other addresses. However, there is no event emitted when the authorization status is changed. This can lead to a situation where authorized addresses are added or removed without detection.

### Root Cause

Lack of notification.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Unauthorized users could gain control over a position, leading to potential loss of assets or incorrect position operations.

### PoC

_No response_

### Mitigation

Emit an event whenever authorization is toggled.