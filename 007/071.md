Massive Slate Dalmatian

Medium

# Removing a known asset in the `PositionManager` causes all deposited funds of that asset to be locked forever

### Summary

When users deposit funds in their position through the position manager, it checks if the deposited asset is known, this is done in:
```solidity
// mitigate unknown assets being locked in positions
if (!isKnownAsset[asset]) revert PositionManager_DepositUnknownAsset(asset);
```
This makes sense, as not to allow users to deposit dummy/worthless assets in their positions. The position manager also allows users to transfer tokens out of their position, the main problem is that it also checks if the asset is known before allowing the transfer.

This causes an issue where if the user had some funds deposited in token X, and then that token X was removed from known assets, the user's funds will be locked/stuck forever.

**NOTE: even if the owner is trusted, however, in case of an attack or a depeg or any other scenario, and the owner urgently removes the asset, users should still be able to transfer out these tokens. It doesn't make sense for the owner to "wait" until all users transfer out these tokens in case of an emergency.**


### Root Cause

The main issue lies in the "isKnownAsset" check in `PositionManager::transfer`, https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L316:
```solidity
if (!isKnownAsset[asset]) revert PositionManager_TransferUnknownAsset(asset);
```

### Attack Path

1. The user deposits some funds of token X.
2. For whatever reason, X is removed from the known assets in the position manager.
3. The user is unable to transfer out his deposited tokens, and they're stuck forever.

### Impact

The user's tokens will remain stuck in his position forever.

### PoC

Add the following test in `protocol-v2/test/core/PositionManager.t.sol`:

```solidity
function testStuckTokens() public {
    uint256 amount = 100 ether;

    deal(address(asset2), positionOwner, amount);

    // Verify that asset2 is known
    assertTrue(
        PositionManager(positionManager).isKnownAsset(address(asset2))
    );

    // User adds asset2 to the position and deposits 100 tokens
    vm.startPrank(positionOwner);
    asset2.approve(address(positionManager), amount);
    PositionManager(positionManager).process(
        position,
        addToken(address(asset2))
    );
    PositionManager(positionManager).process(
        position,
        deposit(address(asset2), amount)
    );
    vm.stopPrank();

    // asset2 is removed from the known assets
    vm.prank(protocolOwner);
    PositionManager(positionManager).toggleKnownAsset(address(asset2));

    // Verify that asset2 is not known
    assertFalse(
        PositionManager(positionManager).isKnownAsset(address(asset2))
    );

    // User tries to transfer out his tokens, reverts
    vm.prank(positionOwner);
    vm.expectRevert(
        abi.encodeWithSelector(
            PositionManager.PositionManager_TransferUnknownAsset.selector,
            address(asset2)
        )
    );
    PositionManager(positionManager).process(
        position,
        transfer(positionOwner, address(asset2), amount)
    );
}
```

### Mitigation

Remove the "isKnownAsset" check from `PositionManager::transfer`.