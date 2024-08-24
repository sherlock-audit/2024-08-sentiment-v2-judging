Acidic Heather Goldfish

Medium

# Absence of Minimum Asset Cap in `addPool` Function

## Summary

The `addPool` function in the `SuperPool` contract does not enforce a minimum value for the `assetCap` parameter. This omission can result in pools being added with an asset cap of extremely low values, leading to potential inefficiencies and misconfigurations within the SuperPool system.

## Vulnerability Detail

The `addPool` function allows the addition of new pools by specifying a `poolId` and an `assetCap`. However, there is no check to ensure that the `assetCap` is above a reasonable minimum value. This lack of validation opens the door for pools to be configured improperly, either accidentally or maliciously, with asset caps that make them unusable or severely limited in utility.

An improperly configured pool with a very low `assetCap` might never receive any assets, leading to "dead" pools within the SuperPool. Such misconfigurations can create unnecessary complexity, administrative overhead, and potential confusion for users interacting with the protocol.

## Impact

- **Dead or Misconfigured Pools**: Pools with extremely low asset caps will remain unused, creating clutter and potential confusion within the system.
- **Administrative Overhead**: Additional effort will be required to manage, audit, and potentially remove such pools, increasing the risk of human error.
- **User Trust and Experience**: Users may lose confidence in the protocol if they encounter inactive or misconfigured pools, adversely affecting the reputation and reliability of the SuperPool.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L317-L324
```solidity
function addPool(uint256 poolId, uint256 assetCap) external onlyOwner {
    if (poolCapFor[poolId] != 0) revert SuperPool_PoolAlreadyInQueue(poolId);
    // cannot add pool with zero asset cap
    if (assetCap == 0) revert SuperPool_ZeroPoolCap(poolId);
    _addPool(poolId);
    poolCapFor[poolId] = assetCap;
    emit PoolCapSet(poolId, assetCap);
}
```

## Tool used

Manual Review

## Recommendation

Introduce a minimum value check for `assetCap` in the `addPool` function to ensure that pools are added with a meaningful capacity. Here is an example modification:

```diff
+ uint256 constant MIN_ASSET_CAP = 10**6; // Example minimum value (1 million units)

  function addPool(uint256 poolId, uint256 assetCap) external onlyOwner {
      if (poolCapFor[poolId] != 0) revert SuperPool_PoolAlreadyInQueue(poolId);
      // cannot add pool with zero asset cap
+     if (assetCap < MIN_ASSET_CAP) revert SuperPool_AssetCapTooLow();
-     if (assetCap == 0) revert SuperPool_ZeroPoolCap(poolId);
      _addPool(poolId);
      poolCapFor[poolId] = assetCap;
      emit PoolCapSet(poolId, assetCap);
  }
```

By enforcing a minimum `assetCap`, the SuperPool can avoid the addition of unusable pools and ensure efficient management and user trust in the protocol.