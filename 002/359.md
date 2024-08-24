Melodic Tangelo Hedgehog

High

# Bad Debts continue to accumulate interest that exposes Lenders to more liability

## Summary

Bad Debts accrue interest for as long as the position is open, resulting in more liability for the lenders feeding the borrowers.

## Vulnerability Detail

When lenders provide liquidity to borrowers, they expect that the borrowers can pay back the funds borrowed with interest. However, for several reasons, the borrower may be unable to pay back the interest and the funds borrowed. This peculiar situation creates bad debt.

Sentiment V2's system for neutralizing bad debts when they arise is to socialize them. As seen in the codebase, the higher the debt, the more liability recorded by lenders.

```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        PoolData storage pool = poolDataFor[poolId];
        accrue(pool, poolId);


        // revert if the caller is not the position manager
        if (msg.sender != positionManager) revert Pool_OnlyPositionManager(poolId, msg.sender);


        // compute pool and position debt in shares and assets
        uint256 totalBorrowShares = pool.totalBorrowShares;
        uint256 totalBorrowAssets = pool.totalBorrowAssets;
        uint256 borrowShares = borrowSharesOf[poolId][position];
        // [ROUND] round up against lenders
        uint256 borrowAssets = _convertToAssets(borrowShares, totalBorrowAssets, totalBorrowShares, Math.Rounding.Up);


        // rebalance bad debt across lenders
        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
    }
```
The function above has to be called through the PositionManager contract and [`PositionManager::liquidateBadDebt()`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L446-L464) can only be called by the owner address. Unlike `PositionManager:liquidate()` that can be called by an external liquidator, it might take longer for bad debt to be socialize and in that time, interest is being accrued. When the debt is finally socialized, it would cause the lenders to be liable for a higher value that they ought to have if the debt was called earlier. Time called is a factor but not the main issue here. The issue is that interest keeps accruing on the bad debt causing lenders to be liable for more.

## Proof of Concept

Add this to `test/LiquidationTest.sol.` Run `forge test --match-contract LiquidationTest` in your console to see the result of the test. The test proves that interest continues to accrue on bad debt and thus increases the liability of the lenders. The magnitude of liability is dependent on the time passed since borrowing became bad debt.

```solidity
    function test__InterestKeepsAccruingForBadDebt() public {
        vm.startPrank(user);
        asset2.approve(address(positionManager), 1e18);

        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory actions = new Action[](5);
        (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
        actions[1] = deposit(address(asset2), 1e18);
        actions[2] = addToken(address(asset2));
        actions[3] = borrow(fixedRatePool, 5e17);
        actions[4] = addToken(address(asset2));
        positionManager.processBatch(position, actions);
        vm.stopPrank();

        // modify asset2 price from 1eth to 0.1eth
        FixedPriceOracle pointOneEthOracle = new FixedPriceOracle(0.1e18);
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset2), address(pointOneEthOracle));
        riskEngine.riskModule().validateBadDebt(position); //ensure that the borrowing is now considered bad debt

        //Logs:
        emit log_named_uint("Value of Debt at the point when the borrow is considered bad debt:", riskEngine.riskModule().getTotalDebtValue(position));
        vm.warp(block.timestamp + 30 days);
        emit log_named_uint("Debt Value After 1 month:", riskEngine.riskModule().getTotalDebtValue(position));
        vm.warp(block.timestamp + 60 days);
        emit log_named_uint("Debt Value After 2 months:", riskEngine.riskModule().getTotalDebtValue(position));
        vm.warp(block.timestamp + 90 days);
        emit log_named_uint("Debt Value After 3 months:", riskEngine.riskModule().getTotalDebtValue(position));
        vm.warp(block.timestamp + 180 days);
        emit log_named_uint("Debt Value After 6 months:", riskEngine.riskModule().getTotalDebtValue(position));
    }
```

## Impact

Loss of more funds by lenders resulting from more interest accruable on bad debt.

## Code Snippet

```solidity
    function liquidateBadDebt(address position) external onlyOwner {
        ...
        // clear all debt associated with the given position
        uint256[] memory debtPools = Position(payable(position)).getDebtPools();
        uint256 debtPoolsLength = debtPools.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
            pool.rebalanceBadDebt(debtPools[i], position);
            Position(payable(position)).repay(debtPools[i], type(uint256).max);
        }
    }
```

## Tool used

Manual Review & Foundry Testing

Inspired By [This Issue](https://solodit.xyz/issues/h-09-bad-debts-should-not-continue-to-accrue-interest-code4rena-jpegd-jpegd-contest-git)

## Recommendation
Temporary Fix: Open up bad debt liquidation to external liquidators. Position assets will still be transferred to the owner's account, and bad debt will be socialized as it should.

Permanent Fix: Alongside the other checks, validate bad debts at the beginning of every transaction and socialize the bad debt immediately to limit the lender's exposure.