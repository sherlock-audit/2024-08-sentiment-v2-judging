Broad Pecan Troll

High

# Users are unable to borrow up to their LTV set into the system.

## Summary

## Vulnerability Detail

When a user deposit asset into the system then he could borrow against his deposited assets, if his position is healthy.
```solidity
        if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
```

However, if a user has deposited into a single pool with a single type of asset and tries to borrow using the `PositionManager::processBatch`  function, then the user will not be able to borrow according to the LTV set in the system, since the above health check will revert due to the current incorrect calculation of `minReqAssetValue `  var in the `RiskModule::_getMinReqAssetValue`  function.

```solidity
minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
```

Since in this case the position can be healthy if `totalAssetValue >= minReqAssetValue;`, but due to incorrect `minReqAssetValue` calculation it will not allow any user to borrow corresponding to LTV set into the system.

```solidity
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
@>       return totalAssetValue >= minReqAssetValue; // (non-zero debt, non-zero assets)
    }
```


POC:

```solidity
    function testSimpleDepositCollateral(uint96 amount) public {
        vm.assume(amount > 0);
        asset2.mint(positionOwner, amount);

        vm.startPrank(positionOwner);
        Action[] memory actions = new Action[](1);

        actions[0] = addToken(address(asset2));
        PositionManager(positionManager).processBatch(position, actions);

        actions[0] = deposit(address(asset2), amount);
        asset2.approve(address(positionManager), amount);
        PositionManager(positionManager).processBatch(position, actions);

        (uint256 totalAssetValue, uint256 totalDebtValue, uint256 minReqAssetValue) = riskEngine.getRiskData(position);
        assertEq(
            totalAssetValue, IOracle(riskEngine.getOracleFor(address(asset2))).getValueInEth(address(asset2), amount)
        );
        assertEq(totalDebtValue, 0);
        assertEq(minReqAssetValue, 0);
        assertEq(asset2.balanceOf(address(position)), amount);

        vm.stopPrank();
    }
    

        function testCantBorrowCorrespondingToTvl() public {
        testSimpleDepositCollateral(100 ether);

        vm.startPrank(positionOwner);
        // not able to borrow more than 3 ether when ltv is 0.75 ether.
        bytes memory data = abi.encode(linearRatePool, 4 ether);

        Action memory action = Action({ op: Operation.Borrow, data: data });
        Action[] memory actions = new Action[](1);
        actions[0] = action;
        
        // User unable to borrow 4 ether against 100 ether collateral
        vm.expectRevert();
        PositionManager(positionManager).processBatch(position, actions);
    }
```

## Impact
Users cannot borrow up to the intended Loan-to-Value (LTV) ratio, restricting their ability to leverage their assets effectively.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L272

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L84

## Tool used

Manual Review

## Recommendation
Consider to fix below line correctly in `RiskModule::_getMinReqAssetValue` function would be the solution.

```solidity
 minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up); 
```