Flat Navy Bee

High

# Attacker can decrease Superpool APR by depositing assets when base pools are paused or split their deposit into many small parts

## Summary

When a user tries to deposit some assets to Superpool, and Superpool passes the assets to some base pools, it doesn't check if the pass is complete or not, making it possible for attackers to grief protocol.

## Vulnerability Detail

When a user tries to deposit some assets to Superpool, `_deposit` is called:
```solidity
    function _deposit(address receiver, uint256 assets, uint256 shares) internal {
        // assume that lastTotalAssets are up to date
        if (lastTotalAssets + assets > superPoolCap) revert SuperPool_SuperPoolCapReached();
        // Need to transfer before minting or ERC777s could reenter.
        ASSET.safeTransferFrom(msg.sender, address(this), assets);
        ERC20._mint(receiver, shares);
        _supplyToPools(assets);
        lastTotalAssets += assets;
        emit Deposit(msg.sender, receiver, assets, shares);
    }
```
And it forward call to `_supplyToPools`:
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

It's worth noting that when `_supplyToPools` finishes traversing all poolIDs, it doesn't check that `assets == 0` is guaranteed. This means that the user's deposit is not necessarily deposited into basepool -- As long as the external calls in try-catch block REVERT, the user's deposit will exist in Superpool as a "fake yield".

`POOL.deposit()` will revert in below scenario:

1. pools are paused.
2. poolCap is reached.
3. shares == 0.

For the first scenario, since Superpool does not have the ability to pause deposits, a user can always implement this attack once base pools is suspended.

In this contest, we leave the second scenario aside for now, since the trusted admin will always set the superpool cap that corresponds to the pool cap.

For the third scenario, attackers can split their deposit into many small parts to make shares == 0.

## Impact

This attack equivalent to an attacker stealing yields from others in the superpool -- The attacker's money is not deposited into the basepool, i.e., the attacker's assets does not provide revenue to the protocol, but participates in the distribution of others revenue.

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L524

## Tool used

Manual Review

## Recommendation

Should revert if all deposits to base pools revert.