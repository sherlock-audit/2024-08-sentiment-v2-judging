Flat Tawny Haddock

Medium

# DOS on `reallocation` due to reliance on amounts

## Summary
DOS on `reallocation` due to reliance on amounts

## Vulnerability Detail
The `reallocate` function passes in an array which contains the amount of assets to withdraw and deposit
```solidity
    function reallocate(ReallocateParams[] calldata withdraws, ReallocateParams[] calldata deposits) external {
        if (!isAllocator[msg.sender] && msg.sender != Ownable.owner()) {
            revert SuperPool_OnlyAllocatorOrOwner(address(this), msg.sender);
        }


        uint256 withdrawsLength = withdraws.length;
        for (uint256 i; i < withdrawsLength; ++i) {
            if (poolCapFor[withdraws[i].poolId] == 0) revert SuperPool_PoolNotInQueue(withdraws[i].poolId);
=>          POOL.withdraw(withdraws[i].poolId, withdraws[i].assets, address(this), address(this));
        }
```

Since these are passed before the call itself and no dynamic check is done inside the contract (like POOL.getAssetsOf(poolId,address(this))), it is possible for the feature to face DOS due to the state changing from when the amounts were calculated. It can either happen as an attack where an attacker deposits/withdraws from the superpool or under normal operations when user's deposit/withdraw

Eg:
current superbool balance in poolA = 100
reallocation attempts to withdraw 80 from poolA and allocate to poolB
a user withdraws his balance of 30 asset making the balance in poolA to 70
the reallocate call reverts

## Impact
DOS on reallocate

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L431-L451

## Tool used
Manual Review

## Recommendation
If doing amount based reallocation I don't think there is a good solution to this. To just avoid the reverts one can keep contract balance checks ie. `POOL.getAssetsOf(poolId,address(this))` and `asset.balanceOf(address(this))` before the withdrawal and deposit  