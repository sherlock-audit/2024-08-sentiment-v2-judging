Sour Holographic Kookaburra

Medium

# Unpaid loan will block SuperPool owner from removing pools

### Summary

The Pool contract does not have enough asset balance (because of unpaid loans) causing will block SuperPool owners from removing pools.


### Root Cause

The function `SuperPool#removePool` can successfully remove pools when the [deposited assets is zero](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L597). If the owner wants to force remove pool, all the assets deposited will [be withdrawn first](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L328-L329) before removed

But there is scenario that Pool contract does not have enough asset balance to serve.  For example:
- There are 2 pools with the same asset added to a Super Pool: P1, P2 with total deposits: (P1, 50), (P2, 50)
- Total borrowed asset is 60: (40 from P1) + (20 from P2)
- The Super Pool owner fails to remove pool P1 (or P2) because there is not enough asset balance in the Pool contract because of the [revert error at this line](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L362), even though the owner decides to force remove or not



### Internal pre-conditions

1. The borrowers do not repay enough funds
2. Pool contract asset balance is lower than Super Pool's pool asset deposited

### External pre-conditions

No.

### Attack Path

1. Super Pool owner adds 2 pool: P1 with cap 50, P2 with cap 50
2. Lenders supply full cap for 2 pools (all pools cap reached)
3. Other users borrow and the total amount is up to: 60
4. Super Pool owner fails to execute function `removePool` with both P1 and P2 even though it is force remove or not

### Impact

- The Super Pool owner can not remove pools as expected even forcing remove or not
- As a result, there also will be lenders who will not able to withdraw all his deposited assets

### PoC

```solidity
function testCanNotRemovePool() public {
        address feeTo = makeAddr("feeTo");

        vm.prank(protocolOwner);
        asset1.mint(address(this), 1e5);
        asset1.approve(address(superPoolFactory), 1e5);
        

        // 1. deploy super pool
        SuperPool superPool = SuperPool(
            superPoolFactory.deploySuperPool(
                poolOwner, address(asset1), feeTo, 0.01 ether, 1_000_000 ether, 1e5, "test", "test"
            )
        );

        // 2. Make a SuperPool with the 2 pools
        vm.startPrank(poolOwner);
        superPool.addPool(fixedRatePool, 50 ether);
        superPool.addPool(fixedRatePool2, 50 ether);
        vm.stopPrank();

        // 3. User fills up the pool
        vm.startPrank(user);
        asset1.mint(user, 100 ether);
        asset1.approve(address(superPool), 100 ether);
        superPool.deposit(100 ether, user);
        vm.stopPrank();

        // 4. User2 borrows
        vm.startPrank(user2);
        asset2.mint(user2, 500 ether);
        asset2.approve(address(positionManager), 500 ether);

        // Make a new position
        (address position, Action memory _newPosition) = newPosition(user2, "test");
        positionManager.process(position, _newPosition);

        Action memory addNewCollateral = addToken(address(asset2));
        Action memory depositCollateral = deposit(address(asset2), 500 ether);
        Action memory borrowAct = borrow(fixedRatePool, 40 ether);
        Action memory borrowAct2 = borrow(fixedRatePool2, 20 ether);

        Action[] memory actions = new Action[](4);
        actions[0] = addNewCollateral;
        actions[1] = depositCollateral;
        actions[2] = borrowAct;
        actions[3] = borrowAct2;

        positionManager.processBatch(position, actions);
        vm.stopPrank();

        // Can not remove pool for both pools, with forcing or not
        vm.startPrank(poolOwner);
        vm.expectRevert();
        superPool.removePool(fixedRatePool, false);

        vm.expectRevert();
        superPool.removePool(fixedRatePool2, false);

        vm.expectRevert();
        superPool.removePool(fixedRatePool, true);

        vm.expectRevert();
        superPool.removePool(fixedRatePool2, true);
        vm.stopPrank();
    }
```

Run the test and the console shows:
```bash
Ran 1 test for test/integration/BigTest.t.sol:BigTest
[PASS] testCanNotRemovePool() (gas: 4922431)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.06ms (1.35ms CPU time)
```

### Mitigation

In case Pool contract asset balance is not enough and the owner forces to remove, consider preparing a mechanism to:
1. Treat that pool as if it has zero asset balance
2. Later withdraw all assets from that pool when available (maybe with a different function rather than the normal `withdraw()`)