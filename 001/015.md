Genuine Lemonade Gerbil

Medium

# Allocator can't deposit assets up to the pool cap.

## Summary
If allocator tries to deposit assets up to the pool cap using `SuperPool.reallocate()`, it will be skipped.

## Vulnerability Detail
`SuperPool.reallocate()` function is following.
```solidity
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
449:        if (assetsInPool + deposits[i].assets < poolCap) {
                ASSET.approve(address(POOL), deposits[i].assets);
                POOL.deposit(deposits[i].poolId, deposits[i].assets, address(this));
            }
        }
    }
```
As can be seen, `<` is used instead of `<=` in the conditional expression of `L449`.
So the allocator can't deposit assets up to the pool cap.

## Impact
Allocator can't deposit assets up to the pool cap.
In particular, if allocator tries to deposit withdrawn assets up to the pool cap, the function doesn't revert but skips depositing without notifying the allocator. As a result, the undeposited assets remains in the `SuperPool` while not depositing into pools. It decreases the capital efficiency and reduces the users' profit.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L449

## Tool used

Manual Review

## Recommendation
Modify `SuperPool.reallocate()` function as follows.
```solidity
    function reallocate(ReallocateParams[] calldata withdraws, ReallocateParams[] calldata deposits) external {
        --- SKIP ---
        uint256 depositsLength = deposits.length;
        for (uint256 i; i < depositsLength; ++i) {
            uint256 poolCap = poolCapFor[deposits[i].poolId];
            // disallow deposits to pool not associated with this SuperPool
            if (poolCap == 0) revert SuperPool_PoolNotInQueue(deposits[i].poolId);
            // respect pool cap
            uint256 assetsInPool = POOL.getAssetsOf(deposits[i].poolId, address(this));
--          if (assetsInPool + deposits[i].assets < poolCap) {
++          if (assetsInPool + deposits[i].assets <= poolCap) {
                ASSET.approve(address(POOL), deposits[i].assets);
                POOL.deposit(deposits[i].poolId, deposits[i].assets, address(this));
            }
        }
    }
```
