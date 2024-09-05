Rhythmic Cherry Starfish

Medium

# Liquidators may repay a position's debt to pools that are within their risk tolerance, breaking the concept of isolated risk in base pools

## Summary

The trust model of the protocol is such that depositors to pools must trust the pool owners, however there was no documented trust assumption between base pool owners. Creating a base pool is permissionless so the owner of pool A shouldn't be able to do something that adversely affects pool B.

However, liquidations that affect Pool B can be caused by Pool A's risk settings despite the position being within Pool B's risk tolerance, which means base pools do not have isolated risk and there is a trust assumption between base pool owners.

According to the [Sentiment Docs](https://docs.sentiment.xyz/concepts/core-concepts/isolated-pools#base-pools), one of the core concepts is isolated financial activities and risk:

>"Each Base Pool operates independently, ensuring the isolation of financial activities and risk."

But with the current design, the LTVs set by a base pool impacts the likelihood of liquidations in every other base pool which shares a common position via loans.


## Vulnerability Detail

A position with debt and recognized assets is determined to be healthy if the recognized collateral exceeds the `minReqAssetValue`:

```javascript

    function isPositionHealthy(address position) public view returns (bool) {
        // a position can have four states:
        // 1. (zero debt, zero assets) -> healthy
        // 2. (zero debt, non-zero assets) -> healthy
        // 3. (non-zero debt, zero assets) -> unhealthy
        // 4. (non-zero assets, non-zero debt) -> determined by weighted ltv

        ... SKIP!...

@>      uint256 minReqAssetValue =
            _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);
        return totalAssetValue >= minReqAssetValue; // (non-zero debt, non-zero assets)
    }
```

`_getMinReqAssetValue` is the sum of required asset value across all collateral tokens and debt positions, adjusted for: the weight of each collateral token, magnitude of debt from a given pool, and the ltv setting for that asset set by that pool:

```javascript
    function _getMinReqAssetValue(
        uint256[] memory debtPools,
        uint256[] memory debtValuleForPool,
        address[] memory positionAssets,
        uint256[] memory wt,
        address position
    ) internal view returns (uint256) {
        uint256 minReqAssetValue;

        ... SKIP!...

        uint256 debtPoolsLength = debtPools.length;
        uint256 positionAssetsLength = positionAssets.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
            for (uint256 j; j < positionAssetsLength; ++j) {
                uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);
                ... SKIP!...
@>              minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
            }
        }
        ... SKIP!...
        return minReqAssetValue;
    }
```

Note from above, that a position is either healthy or unhealthy across all debtPools and assets held by the position. There is no allocation of collateral to a debt position with respect to it's risk parameters. This means that the risk settings of one pool can directly impact the ability to liquidate a position in another pool.

Also note, in the [liquidation flow](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L430-L444), liquidators are [free to chose which assets they seize and which debt they repay](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L432-L433), as long as the position returns to a [healthy state after the liquidation](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L442). This means that debt from a pool may be repaid even though the position was within the risk parameters of that pool.

Base pool owners are able to set LTV for assets individually through a [request /](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L167-L187) [accept](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L190-L210) pattern. 
But as shown, LTVs set by base pools do not strictly impact the risk in their pool, but all pools for which a single position has debt in. 

There is a [timelock delay](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L182) on proposed changes to LTV, and here is why this doesn't completely mitigates this issue:
1. The issue doesn't not require a change in LTV in any pool for a pool to be exposed to the risk settings of another pool via a liquidated position (that is just the adversarial-pool attack path).
2. There is no limit on how many different positions a pool will loan to at any given time (call this numPools). Each position a pool loans to can have debts in [up to 4 other pools](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Position.sol#L25). So even though a [`TIMELOCK_DURATION`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L20) of 24 hours is implemented, it may not be practical for pools to monitor the proposed LTV changes for up to numPools^4 (numPools is uncapped).
3. An adversarial pool could propose an LTV setting, then all other impacted pools may notice this and respond by adjusting their own LTVs to ensure their `totalBorrowAssets` is minimally impacted, then the adverserial pool may not even accept the proposed setting. Even if the setting is accepted there will be a window between when the first pool is allowed to update the settings and when other pools are able to, in which liquidations can occur.


## Impact

- Pool A's risk settings can cause liquidations in Pool B, despite the debt position being within the risk tolerance of Pool B.
- The liquidation of Pool B would decrease borrow volume and utilization which decreases earnings for all depositors (both through volume and rate in the linear and kinked IRM models).
- This may occur naturally, or through adversarial pools intentionally adjusting the LTV of assets to cause liquidations. In fact they may do this to manipulate the utilization or TVL in other pools, or to liquidate more positions themselves and claim the liquidation incentives.


## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L67-L85
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L250-L278


## POC

Paste the below coded POC into LiquidateTest.t.sol. 

Simply put, it shows a single debt position on a pool get liquidated when the collateral price did not change and the pool owner did not change LTV settings. The sole cause of the liquidation was another pool changing their LTV settings.

Step by step:
1. user deposits into base fixedRatePool and linearRatePool which both accept asset1. Both pools accept asset2 as collateral.
   - fixedRatePool has an LTV for asset2 of 70% (ie. minReqCollateral = debt / .7)
   - linearRatePool has an LTV for asset2 of 70% (ie. minReqCollateral = debt / .7)
2. user2 opens a position and deposits 3e18 asset2 as collateral
3. user2 borrows from both pools and has a healthy position:
   - user2 borrows 1e18 from fixedRatePool and 1e18 from linearRatePool
   - minReqCollateral = (1e18 * 1e18 / 0.7e18) + (1e18 * 1e18 / 0.7e18) = 1.428571e18 + 1.428571e18 = 2.857142e18
4. fixedRatePool decides to decrease the LTV setting for asset2 to 60%
5. Position is no longer health because minReqCollateral = (1e18 * 1e18 / 0.6e18) + (1e18 * 1e18 / 0.7e18) = 1.666e18 + 1.428571e18 = 3.094571e18
6. A liquidator, which could be controlled by the owner of fixedRatePool then liquidates the position which has become unhealthy by repaying the debt from linearRatePool, thus impacting the utilization and interest rate of linearRatePool, despite the collateral price not changing and the owner of linearRatePool not adjusting it's LTV settings.


```javascript
    function test_AuditBasePoolsShareRisk() public {

        // Pool risk settings
        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.7e18); 
        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.7e18); 
        vm.warp(block.timestamp +  24 * 60 * 60); // warp to satisfy timelock
        riskEngine.acceptLtvUpdate(fixedRatePool, address(asset2));
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));
        vm.stopPrank();

        // 1. user deposits into base fixedRatePool and linearRatePool which both accept asset1. Both pools accept asset2 as collateral.
        vm.startPrank(user);
        asset1.mint(user, 20e18);
        asset1.approve(address(pool), 20e18);
        pool.deposit(fixedRatePool, 10e18, user);
        pool.deposit(linearRatePool, 10e18, user);
        vm.stopPrank();

        // 2. user2 opens a position and deposits 3e18 asset2 as collateral
        vm.startPrank(user2);
        asset2.mint(user2, 3e18);
        asset2.approve(address(positionManager), 3e18); // 3e18 asset2
        
        Action[] memory actions = new Action[](5);
        (position, actions[0]) = newPosition(user2, bytes32(uint256(0x123456789)));
        actions[1] = deposit(address(asset2), 3e18);
        actions[2] = addToken(address(asset2));

        // 3. user2 borrows from both pools and has a healthy position:
        actions[3] = borrow(fixedRatePool, 1e18);
        actions[4] = borrow(linearRatePool, 1e18);
        positionManager.processBatch(position, actions);
        assertTrue(riskEngine.isPositionHealthy(position));
        vm.stopPrank();


        // 4. fixedRatePool decides to decrease the LTV setting for asset2 to 60%
        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.6e18); 
        vm.warp(block.timestamp + 24 * 60 * 60); // warp to satisfy timelock
        riskEngine.acceptLtvUpdate(fixedRatePool, address(asset2));
        vm.stopPrank();

        // 5. Position is no longer health because minReqCollateral = (1e18 * 1e18 / 0.6e18) + (1e18 * 1e18 / 0.7e18) = 1.666e18 + 1.428571e18 = 3.094571e18
        assertTrue(!riskEngine.isPositionHealthy(position));

        // 6. A liquidator, which could be controlled by the owner of fixedRatePool then liquidates the position which has become unhealthy by repaying the debt from linearRatePool, thus impacting the utilization and interest rate of linearRatePool, despite the collateral price not changing and the owner of linearRatePool not adjusting it's LTV settings.
        DebtData[] memory debts = new DebtData[](1);
        DebtData memory debtData = DebtData({ poolId: linearRatePool, amt: type(uint256).max });
        debts[0] = debtData;

        AssetData memory asset1Data = AssetData({ asset: address(asset2), amt: 1.25e18 });
        AssetData[] memory assets = new AssetData[](1);
        assets[0] = asset1Data;

        vm.startPrank(liquidator);
        asset1.mint(liquidator, 2e18);
        asset1.approve(address(positionManager), 2e18);
        positionManager.liquidate(position, debts, assets);
        vm.stopPrank();
    }
```

## Tool used

Manual Review

## Recommendation

- To maintain the concept of isolated financial risk in base pools, a position's health can be considered at the 'position level', but in the liquidation flow, collateral could be weighted to pools based on the level of debt in each pool.
  
- For example, taking the example from the POC above, after fixedRatePool changed the LTV setting from 70% to 60%, the position became unhealthy as the minReqAssetValue of 3.094571e18 exceeded the deposited collateral worth 3e18. 
- The minReqCollateral was calculated in each iteration of the loop in `RiskModule::_getMinReqAssetValue()`, and we saw in the POC that the contribution required from linearRatePool was 1.4285e18 and the contribution required from fixedRatePool was 1.666e18.
- If we apportion the deposited collateral based on the size of debt in each pool we would apportion 1.5e18 value of collateral to each debt (because the value of each debt was equal), this would show:
  - The position is within linearRatePool's risk tolerance because 1.5e18 > 1.4285e18
  - The position is not within fixedRatePool's risk tolerance because 1.5e18 < 1.666e18
- So I recommend we allow the liquidation of debt from fixedRatePool but not linearRatePool. This makes sense as fixedRatePool was the pool who opted for a riskier LTV.
- This solution is consistent with the idea of isolated pool risk settings and a trustless model between the owners of base pools
