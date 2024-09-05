Tall Goldenrod Barracuda

High

# Users may be liquidated right after taking maximal debt

### Summary

Protocol allows users to borrow maximum amount based on LTV and this causes become liquidate right after taking loan

### Root Cause
Let's assume 
1-[LTV has been set 80% by poolOwner](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L190)
2-Alice deposit 100 USDT and borrow 80 USDC [USDT/USDC] price is 1
3-USDT/USDC become 0.99 and Alice's position become unhealthy 
4-[Liquidator can liquidate Alice](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L272)

### External pre-conditions

ETH oracle price needs to go from 1e18 to 0.99e18 

### Impact

Since there's no gap between the maximal LTV and the liquidation LTV, user positions may be liquidated as soon as maximal debt is taken, without leaving room for collateral and asset prices fluctuations. Users have no chance to add more collateral or reduce debt before being liquidated. This may eventually create more uncovered and bad debt for the protocol.

### PoC

consider adding this test `test/integration/LiquidationTest.t.sol`
```solidity
function testLiquidateImmeditelyWhenGetMaxLoan() external {
          vm.startPrank(user);
        asset2.approve(address(positionManager), 1e18);

        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory actions = new Action[](4);
        (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
        actions[1] = deposit(address(asset2), 1e18);
        actions[2] = addToken(address(asset2));
        actions[3] = borrow(fixedRatePool, 0.5e18);
        positionManager.processBatch(position, actions);
        vm.stopPrank();
        assertTrue(riskEngine.isPositionHealthy(position));
        vm.prank(protocolOwner);



        //construct liquidator data
        DebtData memory debtData = DebtData({ poolId: fixedRatePool, amt: type(uint256).max });
        DebtData[] memory debts = new DebtData[](1);
        debts[0] = debtData;
        AssetData memory asset2Data = AssetData({ asset: address(asset2), amt: 555555555555555555 });
        AssetData[] memory assets = new AssetData[](1);
        assets[0] = asset2Data;



        // // modify asset2 price from 1eth to 0.99e18
        FixedPriceOracle pointOneEthOracle = new FixedPriceOracle(0.99e18);
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset2), address(pointOneEthOracle));
        assertFalse(riskEngine.isPositionHealthy(position));

        // // liquidate
        vm.startPrank(liquidator);
        asset1.approve(address(positionManager), 1e18);
        positionManager.liquidate(position, debts, assets);
        vm.stopPrank();
    }
```

### Mitigation

Consider adding a liquidation LTV that's bigger than the maximal borrow LTV; positions can only be liquidated after reaching the liquidation LTV. This will create a room for price fluctuations and let users increase their collateral or decrease debt before being liquidating.