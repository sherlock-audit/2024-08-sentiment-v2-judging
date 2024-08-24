Radiant Aquamarine Iguana

Medium

# Reallocate can leave assests in contract

## Summary
The rellocate function will move funds from one pool to another one.However  there is no check that the total amount of assets redeemed as effectively deposited into the new pools.Assests not deposited will not earn interest,so SuperPool user earning will be effected.
## Vulnerability Detail

  function reallocate(ReallocateParams[] calldata withdraws, ReallocateParams[] calldata deposits) external {
        if (!isAllocator[msg.sender] && msg.sender != Ownable.owner()) {
            revert SuperPool_OnlyAllocatorOrOwner(address(this), msg.sender);
        }

        uint256 withdrawsLength = withdraws.length;
        for (uint256 i; i < withdrawsLength; ++i) {
            if (poolCapFor[withdraws[i].poolId] == 0) revert SuperPool_PoolNotInQueue(withdraws[i].poolId);
            POOL.withdraw(withdraws[i].poolId, withdraws[i].assets, address(this), address(this));
        }

        uint256 depositsLength = deposits.length;
        for (uint256 i; i < depositsLength; ++i) {
            uint256 poolCap = poolCapFor[deposits[i].poolId];
            // disallow deposits to pool not associated with this SuperPool
            if (poolCap == 0) revert SuperPool_PoolNotInQueue(deposits[i].poolId);
            // respect pool cap
            uint256 assetsInPool = POOL.getAssetsOf(deposits[i].poolId, address(this));
            if (assetsInPool + deposits[i].assets < poolCap) {
       @>         ASSET.approve(address(POOL), deposits[i].assets);
                POOL.deposit(deposits[i].poolId, deposits[i].assets, address(this));
            }
        }
    }

## Impact
SuperPool user earning will be effected.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L431
## Tool used

Manual Review

## Recommendation
Verify that the total amount redeemed from the pools matches the total amount deposited.
