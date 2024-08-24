Overt Wintergreen Rabbit

Medium

# In `SuperPool`, an attacker can move assets to a specific base pool

### Summary

In `SuperPool`, the design supply to pools and withdraw from pools in queue will allow an attacker to move assets to a specific base pool.

### Root Cause

The design supply to pools and withdraw from pools in queue

https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/SuperPool.sol#L524-L543
https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/SuperPool.sol#L548-L580

### Internal pre-conditions

Let's call a base pool that an attacker want to move assets is `X`.
1. Every base pool before `X` in `depositQueue` have `SuperPool#poolCapFor[poolId] != type(uint256).max` or `Pool#poolDataFor[poolId].poolCap != type(uint256).max`. The meaning of this pre-condition is there is way to deposit to `X`. 
2. There is exist a base pool before `X` in `withdrawQueue` that the `SuperPool` has assets in.

### External pre-conditions

_No response_

### Attack Path

There is a `SuperPool` that has:
- `depositQueue = [A, B, X]`
- `SuperPool#poolCapFor[A] = 100, Pool#poolDataFor[B].poolCap = 100`
- `Pool#getTotalAssets(A) = 50, Pool#getTotalAssets(B) = 50, Pool#getTotalAssets(X) = 0`
- `Pool#getAssetsOf(A, address(SuperPool)) = 50, Pool#getAssetsOf(B, address(SuperPool)) = 50, Pool#getAssetsOf(X, address(SuperPool)) = 0`
- `withdrawQueue = [A, B, X]`

This `SuperPool` is satisfied the internal pre-conditions. The base pool `A` represents for base pools that have `SuperPool#poolCapFor[poolId] != type(uint256).max`. The base pool `B` represents for base pools that have `Pool#poolDataFor[poolId].poolCap != type(uint256).max`. The goal of this attack is to move assets from `A, B` to `X`.

An attacker performs the attack in one transaction:
1. Call to `SuperPool#deposit(50, attacker)`. New state:
   - `Pool#getTotalAssets(A) = 100`
   - `Pool#getAssetsOf(A, address(SuperPool)) = 100`
2. Call to `Pool#deposit(B, 50, attacker)`. New state:
   - `Pool#getTotalAssets(B) = 100`
3. Call to `SuperPool#deposit(100, attacker)`. The `SuperPool` will deposit to `X` because `SuperPool#poolCapFor[A], Pool#poolDataFor[B].poolCap` are reached. New state:
   - `Pool#getTotalAssets(X) = 100`
   - `Pool#getAssetsOf(X, address(SuperPool)) = 100`
4. Call to `SuperPool#withdraw(100, attacker, attacker)`. New state:
   - `Pool#getTotalAssets(A) = 0, Pool#getTotalAssets(B) = 0, Pool#getTotalAssets(X) = 100`
   - `Pool#getAssetsOf(A, address(SuperPool)) = 0, Pool#getAssetsOf(B, address(SuperPool)) = 0, Pool#getAssetsOf(X, address(SuperPool)) = 100`
5. Call to `Pool#withdraw(B, 50, attacker)`. The attacker retrieves the funds deposited in step 2.

The attacker moved all assets to `X`. By doing this attack in one transaction, the attacker can flash-loan `150` tokens at the start of the attack for step 1 and 2, and then returns `150` tokens back at the end of the attack. Note that, the attacker does not hold any shares of `SuperPool` or `Pool` at the end of the attack. Meaning the cost this attack is only gas fee and flash-loan fee.

### Impact

By moving assets to a specific base pool, an attacker can cause the following larger impacts:
- Front-running `PositionManager#liquidateBadDebt` with this attack to cause loss of funds for the `SuperPool`. When the protocol calls `PositionManager#liquidateBadDebt`, a base pool that has its bad debt being liquidated will suffer a loss. So, the attacker will move assets from other pools to the pools that has its bad debt being liquidated, which will cause loss of funds to the `SuperPool`.
- Use liquidity from other pools for withdrawing in the attacker's desired pool. Users can not call to `Pool#withdraw` when `maxWithdrawAssets` is not enough. In case of, the pool that the attacker want to withdraw from does not have enough liquidity, the attacker can perform this attack to move assets from other pools to their desired pool.
- Move assets to a low performance pool to cause loss of yield for the `SuperPool`.

### PoC

_No response_

### Mitigation

Add a two-step `SuperPool#deposit/mint`. First the users stage their `deposit/mint`. After a short timelock (E.g: 10 seconds), the users can finalize their `deposit/mint`. This will prevent the attack that uses flash-loan, but if the attacker has enough liquidity, then this attack still can happen.