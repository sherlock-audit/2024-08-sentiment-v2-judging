Innocent Menthol Dog

Medium

# If PositionManager is paused users can be liquidated without any way of saving their position

### Summary

If PositionManager is paused users can be liquidated without any way of saving their position

### Root Cause

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L229

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L238

Only the PositionManager can operate on the pools so, if it is paused, users will lose the ability to:
- deposit/withdraw collateral
- borrow
- repay

As we can see in `Pool:repay()`, the call will revert if the caller isn't the PositionManager:
```js
if (msg.sender != positionManager) revert Pool_OnlyPositionManager(poolId, msg.sender);
```

The issue is that PositionManager:liquidate() isn't affected by the pausing state, meaning that users can be liquidated without having any way to avoid it by repaying or depositing more collateral.


### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

1. bob has WBTC as collateral 
2. positionManager is paused by the protocol owner
3. the price of WBTC plummets, now bob collateral isn't enough to cover his debt
3. bob tries to repay his debt to avoid liquidation but he can't since PositionManager is now paused
4. liquidators can still liquidate bob's position
5. bob has lost his collateral without any way to prevent it by repaying or adding more collateral

### Impact

Since repayments and depositing collateral are disabled but liquidations are not users can be liquidated without any way to save their position

### PoC

Add the following test to `test/integration/LiquidationTest.t.sol`:

```js
function testRepaymentsPausedButLiquidationsStillPossible() public {
        vm.startPrank(user);
        asset2.approve(address(positionManager), 1e18);

        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory actions = new Action[](7);
        (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
        actions[1] = deposit(address(asset2), 1e18);
        actions[2] = addToken(address(asset2));
        actions[3] = borrow(fixedRatePool, 1e18);
        actions[4] = approve(address(mockswap), address(asset1), 1e18);
        bytes memory data = abi.encodeWithSelector(SWAP_FUNC_SELECTOR, address(asset1), address(asset3), 1e18);
        actions[5] = exec(address(mockswap), 0, data);
        actions[6] = addToken(address(asset3));
        positionManager.processBatch(position, actions);
        vm.stopPrank();
        assertTrue(riskEngine.isPositionHealthy(position));

        (uint256 totalAssetValue, uint256 totalDebtValue, uint256 minReqAssetValue) = riskEngine.getRiskData(position);

        assertEq(totalAssetValue, 2e18);
        assertEq(totalDebtValue, 1e18);
        assertEq(minReqAssetValue, 2e18);

        // construct liquidator data
        DebtData memory debtData = DebtData({ poolId: fixedRatePool, amt: type(uint256).max });
        DebtData[] memory debts = new DebtData[](1);
        debts[0] = debtData;
        AssetData memory asset1Data = AssetData({ asset: address(asset3), amt: 1e18 });
        AssetData memory asset2Data = AssetData({ asset: address(asset2), amt: 1e18 });
        AssetData[] memory assets = new AssetData[](2);
        assets[0] = asset1Data;
        assets[1] = asset2Data;

        // attempt to liquidate before price moves
        asset1.mint(liquidator, 10e18);
        vm.startPrank(liquidator);
        asset1.approve(address(positionManager), 1e18);
        vm.expectRevert(abi.encodeWithSelector(RiskModule.RiskModule_LiquidateHealthyPosition.selector, position));
        positionManager.liquidate(position, debts, assets);
        vm.stopPrank();

        // position manager is paused
        vm.startPrank(protocolOwner);
        positionManager.togglePause();

        // modify asset2 price from 1eth to 0.1eth
        FixedPriceOracle pointOneEthOracle = new FixedPriceOracle(0.1e18);
        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset2), address(pointOneEthOracle));
        
        // now user is liquidatable
        assertFalse(riskEngine.isPositionHealthy(position));

        // user tries to add more collateral to avoid being liquidated
        vm.startPrank(user);
        asset2.mint(user, 10e18);
        asset2.approve(address(positionManager), 10e18);
        actions = new Action[](1);
        actions[0] =  deposit(address(asset2), 10e18);
        
        // but it will revert since the protocol is paused
        vm.expectRevert();
        positionManager.processBatch(position, actions);

        // liquidate
        vm.startPrank(liquidator);
        asset1.approve(address(positionManager), 1e18);
        positionManager.liquidate(position, debts, assets);
        vm.stopPrank();    
    }
```

### Mitigation

Add `whenNotPaused` to `PositionManager:liquidate()`.
Impose a grace period, after the contract is unpaused, where users can repay/deposit collateral while liquidations cannot happen to avoid users being liquidated as soon as the contract is unpaused.
