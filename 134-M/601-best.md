Suave Hotpink Badger

High

# Calculation issue will impact in loss in user funds and DOS

### Summary

In withdraw function in pool.sol contract while calculating amount of shares it is rounding up which results in loss in user funds and DOS as user will not be able to fully withdraw the deposited assets and Superpool is also not compliant with ERC 4626.

### Root Cause

The choice to round up on [pool.sol:350](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L350) is a mistake as it results in loss of user funds and DOS as user can't withdraw the full asset amount. It also affects withdraw function in SuperPool.sol as underneath it calls withdraw function on pool.sol

### Internal pre-conditions

It will happen in all scenarios after interest is accrued and peg is not 1:1 between assets and shares.

### External pre-conditions

_No response_

### Attack Path

1. In [testTimeIncreasesDebt](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/test/core/Pool.t.sol#L217) test case after time is elapsed, debt is increased and interest is accrued if a user deposits funds and later tries to withdraw all the funds they are not able to withdraw it all due to issue in calculation

### Impact

The user loose a part of deposited asset amount and can't withdraw the deposited amount fully causing [withdraw](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L339) function unusable to withdraw all assets and also cause the same DOS issue in superPool withdraw function. 

### PoC

In Pool.t.sol
```solidity
function testTimeIncreasesDebt(uint96 assets) public {
        testBorrowWorksAsIntended(assets);

        (,,,,,,, uint256 totalBorrowAssets, uint256 totalBorrowShares,,) = pool.poolDataFor(linearRatePool);
        console.log("totalBorrowAssets -> ", totalBorrowAssets);
        console.log("totalBorrowShares -> ", totalBorrowShares);

        uint256 time = block.timestamp + 1 days;
        vm.warp(time + 86_400 * 7);
        vm.roll(block.number + ((86_400 * 7) / 2));

        pool.accrue(linearRatePool);

        (,,,,,,, uint256 newTotalBorrowAssets, uint256 newTotalBorrowShares,,) = pool.poolDataFor(linearRatePool);
        console.log("newTotalBorrowAssets -> ", newTotalBorrowAssets);
        console.log("newTotalBorrowShares -> ", newTotalBorrowShares);
        console.log("shares first -> ", pool.balanceOf(user, linearRatePool));
        console.log("assets -> ",assets);

        (uint256 depositedEarlier) = pool.getAssetsOf(linearRatePool, user);
        console.log("assets in pool before ->", depositedEarlier);
        // (uint256 liquidity) = pool.getPoolAssetFor(linearRatePool);
        // console.log("total assets in pool ->", liquidity);

        vm.startPrank(user2);
        asset1.mint(user2, assets);
        asset1.approve(address(pool), assets);
        (uint256 sharesBefore) = pool.deposit(linearRatePool, assets, user2);
        console.log("shares minted on deposit -> ", sharesBefore);
        (uint256 sharesAfter) = pool.withdraw(linearRatePool, assets, user2, user2);
        console.log("shares burned on withdraw -> ", sharesAfter);
        vm.stopPrank();

        (uint256 deposited) = pool.getAssetsOf(linearRatePool, user);
        console.log("total assets deposited ->", deposited);

        assertEq(sharesBefore, sharesAfter);
        assertEq(newTotalBorrowShares, totalBorrowShares);
        assertGt(newTotalBorrowAssets, totalBorrowAssets);
    }
```

In Superpool.t.sol

```solidity
function testInterestEarnedOnTheUnderlingPool() public {
        // 1. Setup a basic pool with an asset1
        // 2. Add it to the superpool
        // 3. Deposit assets into the pool
        // 4. Borrow from an alternate account
        // 5. accrueInterest
        // 6. Attempt to withdraw all of the liquidity, and see the running out of the pool
        vm.startPrank(poolOwner);
        superPool.addPool(linearRatePool, 50 ether);
        superPool.addPool(fixedRatePool, 50 ether);
        vm.stopPrank();

        vm.startPrank(user);
        asset1.mint(user, 50 ether);
        asset1.approve(address(superPool), 50 ether);

        vm.expectRevert();
        superPool.deposit(0, user);

        superPool.deposit(50 ether, user);
        vm.stopPrank();

        vm.startPrank(Pool(pool).positionManager());
        Pool(pool).borrow(linearRatePool, user, 35 ether);
        vm.stopPrank();

        vm.warp(block.timestamp + 365 days);
        vm.roll(block.number + 5_000_000);
        pool.accrue(linearRatePool);

        vm.startPrank(user2);
        asset1.mint(user2, 421 ether);
        asset1.approve(address(superPool), 421 ether);

        (uint256 sharesMinted) = superPool.deposit(421 ether, user2);
        console.log("Shares Minted ->", sharesMinted);
        (uint256 sharesBurned) = superPool.withdraw(421 ether, user2, user2);
        console.log("Shares Burned ->", sharesBurned);
        vm.stopPrank();

        vm.startPrank(Pool(pool).positionManager());
        uint256 borrowsOwed = pool.getBorrowsOf(linearRatePool, user);

        asset1.mint(Pool(pool).positionManager(), borrowsOwed);
        asset1.approve(address(pool), borrowsOwed);
        Pool(pool).repay(linearRatePool, user, borrowsOwed);
        vm.stopPrank();

        superPool.accrue();

        vm.startPrank(user);
        vm.expectRevert(); // Not enough liquidity
        superPool.withdraw(40 ether, user, user);
        vm.stopPrank();

        vm.startPrank(poolOwner);
        vm.expectRevert(); // Cant remove a pool with liquidity in it
        superPool.removePool(linearRatePool, false);
        vm.stopPrank();
    }
```

### Mitigation

Changing `Math.Rounding.Up` to `Mat.Rounding.Down` in [Pool.sol:350](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L350) solves the issue.