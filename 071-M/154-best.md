Expert Nylon Leopard

Medium

# Bad Debt Accumulation Due to Incomplete Liquidation Checks in Protocol's isHealthyPosition Function

## Summary 

The Liquidation Discount contains the Liquidator's Profit and Liquidation Fee. 
The current implementation of the protocol's liquidation process contains a flaw in the `isHealthyPosition` check, which fails to account for the liquidation fee when determining if a position should be liquidated. As a result, positions that should be liquidated may not be, leading to the accumulation of bad debt within the protocol. This issue is exacerbated by plans to increase the liquidation fee to as much as 20-30%, which would further distort the liquidation process and make liquidations unprofitable.

## Vulnerability Detail

The `isHealthyPosition` function is designed to check whether a position is healthy by comparing the total assets with a buffered amount based on the LTV. However, this check does not include the liquidation fee in its calculation of the minimum required asset value (`minReqAssetValue`). As a result, the protocol may incorrectly determine that a position is healthy when, in fact, it should be liquidated.

When the liquidation fee is eventually increased (as indicated by the protocol team's plans), this flaw will become more pronounced. Specifically, the `isHealthyPosition` check may allow positions to remain open even when they should be liquidated, leading to a buildup of bad debt. Furthermore, when these positions are finally liquidated, the liquidator may incur losses because the liquidation fee reduces the amount available for repayment, making the liquidation unprofitable.

## Impact

The impact of this vulnerability is significant, as it can lead to the protocol accumulating bad debt and making liquidations unprofitable for liquidators. This could deter liquidators from participating in the liquidation process, exacerbating the accumulation of bad debt. As bad debt increases, the protocol's solvency and overall financial health could be jeopardized, leading to potential losses for both the protocol and its users.

Update Base.t.sol setup to Readme values
```solidity
  function setUp() public virtual {
        Deploy.DeployParams memory params = Deploy.DeployParams({
            owner: protocolOwner,
            proxyAdmin: proxyAdmin,
            feeRecipient: address(this),
            minLtv: 10e16, // 0.1
            maxLtv: 98e16, // 0.8
            minDebt: 0,
            minBorrow: 0,
            liquidationFee: 0.2e18,
            liquidationDiscount: 0.3e18,
            badDebtLiquidationDiscount: 1e16,
            defaultOriginationFee: 0,
            defaultInterestFee: 0
        });
```

Update liquidation function changing the ltv to  90% = 900000000000000000

```solidity

contract LiquidationTest is BaseTest {
    Pool pool;
    address position;
    RiskEngine riskEngine;
    PositionManager positionManager;
    address public liquidator = makeAddr("liquidator");

   function setUp() public override {
        super.setUp();

        pool = protocol.pool();
        riskEngine = protocol.riskEngine();
        positionManager = protocol.positionManager();

        // ZeroOracle zeroOracle = new ZeroOracle();
        FixedPriceOracle oneEthOracle = new FixedPriceOracle(1e18);

        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(oneEthOracle)); // 1 asset1 = 1 eth
        riskEngine.setOracle(address(asset2), address(oneEthOracle)); // 1 asset2 = 1 eth
        riskEngine.setOracle(address(asset3), address(oneEthOracle)); // 1 asset3 = 1 eth
        vm.stopPrank();

        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(fixedRatePool, address(asset3), 0.9e18); // 2x lev
        riskEngine.acceptLtvUpdate(fixedRatePool, address(asset3));
        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.9e18); // 2x lev
        riskEngine.acceptLtvUpdate(fixedRatePool, address(asset2));
        vm.stopPrank();

        asset1.mint(lender, 100e18);
        asset2.mint(user, 10e18);
         asset3.mint(user, 10e18);

        vm.startPrank(lender);
        asset1.approve(address(pool), 100e18);
        pool.deposit(fixedRatePool, 100e18, lender);
        vm.stopPrank();    
    }


    function testLiquidate() public {
        vm.startPrank(user);
        asset2.approve(address(positionManager), 2e18);
        asset3.approve(address(positionManager), 1e18);

        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory actions = new Action[](6);
        (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
        actions[1] = deposit(address(asset2), 2e18);
        actions[2] = deposit(address(asset3), 1e18);

        actions[3] = addToken(address(asset2));
        actions[4] = addToken(address(asset3));
        actions[5] = borrow(fixedRatePool, 1e18);
        // actions[4] = approve(address(mockswap), address(asset1), 1e18);
        // bytes memory data = abi.encodeWithSelector(SWAP_FUNC_SELECTOR, address(asset1), address(asset3), 1e18);
        // actions[5] = exec(address(mockswap), 0, data);
        // actions[6] = addToken(address(asset3));
        positionManager.processBatch(position, actions);
        vm.stopPrank();
        assertTrue(riskEngine.isPositionHealthy(position));

        (uint256 totalAssetValue, uint256 totalDebtValue, uint256 minReqAssetValue) = riskEngine.getRiskData(position);

        assertEq(totalAssetValue, 3e18);
        assertEq(totalDebtValue, 1e18);
        assertEq(minReqAssetValue, 1.111111111111111110e18);

        // construct liquidator data
        DebtData memory debtData = DebtData({ poolId: fixedRatePool, amt: type(uint256).max });
        DebtData[] memory debts = new DebtData[](1);
        debts[0] = debtData;
        AssetData memory asset1Data = AssetData({ asset: address(asset3), amt: 1e18 });
        AssetData memory asset2Data = AssetData({ asset: address(asset2), amt: 2e18 });
        AssetData[] memory assets = new AssetData[](2);
        assets[0] = asset1Data;
        assets[1] = asset2Data;

        // attempt to liquidate before price moves
        asset1.mint(liquidator, 10e18);
        vm.startPrank(liquidator);
        asset1.approve(address(positionManager), 2e18);
        vm.expectRevert(abi.encodeWithSelector(RiskModule.RiskModule_LiquidateHealthyPosition.selector, position));
        positionManager.liquidate(position, debts, assets);
        vm.stopPrank();

        // modify asset2 price from 1eth to 0.01eth
        FixedPriceOracle pointOneEthOracle = new FixedPriceOracle(1e16);
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset2), address(pointOneEthOracle));
         vm.stopPrank();
        assertFalse(riskEngine.isPositionHealthy(position));

        (uint256 totalAssetValue2, uint256 totalDebtValue2, uint256 minReqAssetValue2) = riskEngine.getRiskData(position);

        assertEq(totalAssetValue2, 1.02e18);
        assertEq(totalDebtValue2, 1e18);
        assertEq(minReqAssetValue2, 1.111111111111111111e18);

       

        // liquidate
        vm.startPrank(liquidator);
        asset1.approve(address(positionManager), 1e18);
        positionManager.liquidate(position, debts, assets);
        vm.stopPrank();

        asset2.balanceOf(liquidator);
        asset3.balanceOf(liquidator);
    }
```
```solidity
emitted value for asset2 and 3 

 [539] MockERC20::balanceOf(liquidator: [0x08333132c5237Efd5712407bBe672EE1CA871eEA]) [staticcall]
    │   └─ ← [Return] 1600000000000000000 [1.6e18]
    ├─ [539] MockERC20::balanceOf(liquidator: [0x08333132c5237Efd5712407bBe672EE1CA871eEA]) [staticcall]
    │   └─ ← [Return] 800000000000000000 [8e17]
    └─ ← [Stop] 
```

value of asset 2 is 0.01 Eth.
Amount = 1.6e18

value 1 = 1.6e18 * 0.01 Eth = 0.016e18Eth

value of asset 3 is 1 Eth.
Amount = 8e17

value 2 = 8e17 * 1 Eth = 8e17Eth

Total Value = 0.016e18Eth +  8e17Eth = 0.8168Eth ..     NOTE liquidator paid 1e18 from the POC and ended up with 0.8168Eth.

If the Values above is increased note the required amount (minReqAssetValue2, ) checked against total value is 1.111111111111111111e18.

Else Liquidate will revert stating all is well

```solidity
  
  /// @notice Evaluates whether a given position is healthy based on the debt and asset values
    function isPositionHealthy(address position) public view returns (bool) {
        // a position can have four states:
        // 1. (zero debt, zero assets) -> healthy
        // 2. (zero debt, non-zero assets) -> healthy
        // 3. (non-zero debt, zero assets) -> unhealthy
        // 4. (non-zero assets, non-zero debt) -> determined by weighted ltv

        (uint256 totalDebtValue, uint256[] memory debtPools, uint256[] memory debtValueForPool) =
            _getPositionDebtData(position);
        if (totalDebtValue == 0) return true; // (zero debt, zero assets) AND (zero debt, non-zero assets)

        (uint256 totalAssetValue, address[] memory positionAssets, uint256[] memory positionAssetWeight) =
            _getPositionAssetData(position);
        if (totalAssetValue == 0) return false; // (non-zero debt, zero assets)

        uint256 minReqAssetValue =
            _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);

@audit >> higher than 1.11e18 says position is ok when it is not>>        return totalAssetValue >= minReqAssetValue; // (non-zero debt, non-zero assets)
    }

```

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L107-L120

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L84

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L152

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L117

## Tool used

Manual Review

## Recommendation

To mitigate this issue, the following steps should be taken:

1. **Include Liquidation Fee in `isHealthyPosition` Check**:
   Update the `isHealthyPosition` function to include the liquidation fee in its calculation of the minimum required asset value. This ensures that a position is deemed unhealthy and subject to liquidation when its total assets fall below the sum of the debt value and the liquidation fee.
The liquidation fee should operate like _validateSeizedAssetValue, 

  ```solidity
++   function  _getliquidationFee(  address position,
++         DebtData[] calldata debtData,
++         AssetData[] calldata assetData,
++         uint256 discount) internal view returns (uint) {


++     // compute value of debt repaid by the liquidator
++         uint256 debtRepaidValue;
++         uint256 debtLength = debtData.length;
++         for (uint256 i; i < debtLength; ++i) {
++             uint256 poolId = debtData[i].poolId;
++             uint256 amt = debtData[i].amt;
++             if (amt == type(uint256).max) amt = pool.getBorrowsOf(poolId, position);
++             address poolAsset = pool.getPoolAssetFor(poolId);
++             IOracle oracle = IOracle(riskEngine.getOracleFor(poolAsset));
++             debtRepaidValue += oracle.getValueInEth(poolAsset, amt);
++         }

++         // compute value of assets seized by the liquidator
++         uint256 assetSeizedValue;
++         uint256 assetDataLength = assetData.length;
++         for (uint256 i; i < assetDataLength; ++i) {
++             IOracle oracle = IOracle(riskEngine.getOracleFor(assetData[i].asset));
++           assetSeizedValue += oracle.getValueInEth(assetData[i].asset, assetData[i].amt);
++        }

++       // max asset value that can be seized by the liquidator
++        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));

++ liquidationFee = PositionManager.liquidationFee
++  if (assetSeizedValue > maxSeizedAssetValue) {

++     return  uint256 fee = liquidationFee.mulDiv(maxSeizedAssetValue, 1e18);     
++        } else {

++     return  uint256 fee = liquidationFee.mulDiv(assetSeizedValue, 1e18);  }
  ```

   ```solidity
 /// @notice Evaluates whether a given position is healthy based on the debt and asset values
    function isPositionHealthy(address position) public view returns (bool) {
     
 uint256 minReqAssetValue =
            _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);
--        return totalAssetValue >= minReqAssetValue; // (non-zero debt, non-zero assets)

++      liquidationFee= _getliquidationFee(position, debtData, assetData, LIQUIDATION_DISCOUNT);
++      uint256 minReqAssetValue = minReqAssetValue + liquidationFee;
++       return totalAssetValue > minReqAssetValue;
   }
  ```

