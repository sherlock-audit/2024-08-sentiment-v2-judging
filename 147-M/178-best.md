Agreeable Pewter Urchin

Medium

# `SuperPool` fails to correctly deposit into pools

## Summary

When a depositor calls `SuperPool::deposit()` the internal `_deposit()` is called, it checks if `astTotalAssets + assets > superPoolCap` , transfers the assets from `msg.sender` to `superPool address` , mints `shares` to `receiver` and then calls `_supplyToPools()`. 

[SuperPool::_deposit()](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L497-L506)
```solidity
    function _deposit(address receiver, uint256 assets, uint256 shares) internal {
        // assume that lastTotalAssets are up to date
        if (lastTotalAssets + assets > superPoolCap) revert SuperPool_SuperPoolCapReached();
        // Need to transfer before minting or ERC777s could reenter.
        ASSET.safeTransferFrom(msg.sender, address(this), assets);
        ERC20._mint(receiver, shares);
        _supplyToPools(assets);    <<<@
        lastTotalAssets += assets;
        emit Deposit(msg.sender, receiver, assets, shares);
    }
```

[SuperPool::_supplyToPools()](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L524-L543)

```solidity
    function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));  <<<@


            if (assetsInPool < poolCapFor[poolId]) {
                uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;
                ASSET.forceApprove(address(POOL), supplyAmt);


                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }


                if (assets == 0) return;
            }
        }
    }
```

`_supplyToPools()` loops through all pools, depositing assets sequentially until the cap is reached. When it checks if the `cap of the poolId` is reached instead of comparing the `total deposit assets amount` of the `poolId` with the  `pool.poolCap` to see if there is a free space for depositing into, it only compares the total assets deposited by the `SuperPool address` into the `poolId` with `poolCapFor[poolId] mapping ` set by the `owner of the SuperPool` when the pool was added by calling `addPool()` and subtract the result with the wanted asset value for depositing. 

## Vulnerability Detail

When calculating if there is a free space for depositing into the `poolId` by calling `uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));` it can return bigger value than the actual one left in the `pool.poolCap` , increasing the chances of `deposit()` function for the `poolId` to revert, unsuccessfully filling up the left space in the `poolId`  before moving forward to the next `poolId` if there is any asset amount left. 

## Impact

Fails to correctly fill up assets into pools even if there is any free space to do so.

## Code Snippet

```solidity
    function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));


            if (assetsInPool < poolCapFor[poolId]) {
                uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;
                ASSET.forceApprove(address(POOL), supplyAmt);


                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }


                if (assets == 0) return;
            }
        }
    }
```
## PoC

Lets look at the following example:

1. Owner of `poolId = 1` creates the pool and sets `poolCap = 2000 USDC`
2. In `SuperPool` `poolId = 1` is added to the contract with `poolCapFor[poolId] = 1500` . 
3. Alice deposits 1000 USDC to `poolId = 1` by calling `SuperPool.deposit()`.
 a) Now the `poolCapFor[poolId] ` free space is 500 USDC.
 b) And `poolCap free space for poolId = 1` is 1000 USDC.
4. Bob calls directly `Pool.deposit()` for `poolId = 1` with 600 USDC , and `poolCap free space for poolId = 1` is 400USDC.
5. John calls `SuperPool.deposit()` with 500 USDC and it will try to deposit into `poolId = 1` because `poolCapFor[poolId] free space = 500` , but `poolCap free space = 400`, the tx will revert for that poolId and will move forward and try to deposit into the next pool even when there is free space for 400 USDC . 

## Tool used

Manual Review

## Recommendation

In Pool.sol add :

```diff
+    function getPoolCap(uint256 poolId) public view returns(uint256) {
+        return poolDataFor[poolId].poolCap;
+    }
```
And in SuperPool.sol

```diff
    function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
+            uint256 capLeft = pool.getPoolCap(poolId) - pool.getTotalAssets(poolId);
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));

                if (assetsInPool < poolCapFor[poolId]) {
                uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;
+                If(supplyAmt > capLeft){
+                    supplyAmt = capLeft;
                ASSET.forceApprove(address(POOL), supplyAmt);
+                } else {
+                    ASSET.forceApprove(address(POOL), supplyAmt);
+                }
                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }

                if (assets == 0) return;
            }
        }
    }
```