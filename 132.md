Urban Caramel Llama

Medium

# The caller of `SuperPool::deposit` can skip depositing into pools by sending less gas

### Summary



When users deposit into the super pool the `SuperPool::_supplyPools` is called internally to distribute the funds to the underlying pools chosen by the owner.

By depositing the funds into the pools, other user can borrow this money which will accrue interest for the Super pool depositors.

However, due to the `Pool.deposit` function being wrapped in a try/catch, the user can specify an amount of gas that wouble be enough to execute the entire transaction, but not enough to execute the `POOL.deposit`.

Since other honest  users may be involved the malicious actor will still accrue interest even, if his funds were never put to work.

### Root Cause

The [_supplyToPools](https://github.com/sherlock-audit/2024-08-sentiment-v2/tree/main/protocol-v2/src/SuperPool.sol#L524-L543) function is called inside of `_deposit` to distribute the deposited funds to the underlying pools in order for users to borrow from them and earn interest.

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
                } catch {}

                if (assets == 0) return;
            }
        }
    }
```

The `POOL.deposit` function is wrapped in a try catch to avoid reverts. 
 However, due to this the user can precisely calculate the gas to make the function silently fail leaving the deposited funds inside of `SuperPool`.
    
The owner can  call `SuperPool::reallocate` to deposit the excess funds, but this does not stop the user from withdrawing and repeating it again.
   
### Internal pre-conditions

1. If there is only 1 pool added to the queue - None.
2. If there are more pools, all pools, but the last one have to:
    - either revert, be paused or reached the cap in order to be skipped.

### External pre-conditions

None

### Attack Path

1. User creates the Super pool and adds Pool 1 to the queue.
2. Users start depositing and supplying liquidity to Pool 1
2. User calls `SuperPool::deposit` with specifically calculated gas to make `Pool1.deposit` fail  leaving his funds inside of `SuperPool`.
 

### Impact

The user will accumulate interest, without ever having the risk of his funds getting borrowed. Additionally stealing interest from honest depositors.

### Mitigation

Remove the try/catch, and consider every single points where `Pool::deposit` can revert and apply checks for it