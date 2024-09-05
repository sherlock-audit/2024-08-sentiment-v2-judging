Flat Tawny Haddock

Medium

# Attacker can inflict losses to other Superpool user's during a bad debt liquidation depending on the deposit/withdraw queue order

## Summary
Attacker can inflict losses to other Superpool user's during a bad debt liquidation depending on the deposit/withdraw queue order

## Vulnerability Detail
On bad debt liquidation the underlying BasePool depositors eats losses

```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        
        .....

        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
```
In a superpool this allows an attacker to inflict more losses to others depending on the deposit/withdraw pool order without suffering any losses for himself if he can deposit more assets in the to be affected pool and withdraw from another pool

```solidity
    function reorderDepositQueue(uint256[] calldata indexes) external onlyOwner {
        if (indexes.length != depositQueue.length) revert SuperPool_QueueLengthMismatch(address(this));
        depositQueue = _reorderQueue(depositQueue, indexes);
    }


    /// @notice Reorders the withdraw queue, based in withdraw priority
    /// @param indexes The new withdrawQueue, in order of priority
    function reorderWithdrawQueue(uint256[] calldata indexes) external onlyOwner {
        if (indexes.length != withdrawQueue.length) revert SuperPool_QueueLengthMismatch(address(this));
        withdrawQueue = _reorderQueue(withdrawQueue, indexes);
    }
```

Eg:
poolA = 100 value, 100shares
poolB = 100 value, 100shares
superPool deposit order [poolA,poolB]
superPool withdraw order [poolB,poolA]
superPool balance = 100 value, all deposited in poolB
bad debt liqudiation of 100 for poolA is about to happen
attacker deposits 100 value in superpool and withdraws 100
attacker suffers no loss
now superPool has entire balance in poolA
poolA = 200value , 200 shares
after bad debt liquidation, poolA = 100 value,200shares
this loss is beared by the other superpool depositors

## Impact
Attacker can inflict losses to other superpool depositors

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L345-L355

## Tool used
Manual Review

## Recommendation
Monitor for bad debt and manage the bad debt pool