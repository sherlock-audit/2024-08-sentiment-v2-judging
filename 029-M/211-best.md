Expert Nylon Leopard

High

# All borrowed assest are deducted instead of LOSS leading to Improper Loss Calculation in Bad Debt Liquidation Leading to Significant User Losses

## Summary
The implementation of the `rebalanceBadDebt` function fails to correctly handle bad debt liquidation, leading to an inequitable distribution of losses among lenders. Instead of socializing the loss proportionally among all lenders, the function deducts the entire amount of borrowed shares from the pool, potentially causing a significant loss for users withdrawing from the Pool while SuperPool loses funds as more shares are burnt to receive less assets. This can result in a user losing 20% or more of the tokens they should receive.
_Docs-_

_### Bad Debt Positions_

**Bad debt positions positions include positions that owe more debt to the protocol than the total value of assets in the position.** The purpose of liquidating a bad debt position is to ensure the Base Pool is not rendered unusable due to accumulation of bad debt. Accordingly, these positions can only be liquidated by the protocol governance.

The process of liquidating a bad debt position involves socializing the bad debt across all lenders of the Base Pool proportional to their share of deposits. The protocol clears the debt owed by the bad debt position and **the loss is realized equitably among all lenders.**

## Vulnerability Detail

According to the protocol documentation, when liquidating a bad debt position, the loss should be socialized across all lenders in the Base Pool proportionally to their share of deposits. This ensures that no single user bears the entire loss and the Base Pool remains usable.

However, the current implementation of the `rebalanceBadDebt` function does not adhere to this principle. Instead, it deducts the entire amount of asset borrowed from the pool without considering the actual loss incurred. This behavior leads to a situation where a user who withdraws from the SuperPool immediately this function is called will receive significantly fewer tokens than they are entitled to and more of their shares will burnt, as the total deposit amount is reduced by the borrowed amount rather than the actual loss.



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

@audit>> we are reducing by totalborrowasset not LOSS>>   pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
    borrowSharesOf[poolId][position] = 0;
}
```


## Impact

This issue can lead to significant financial losses for users withdrawing from the SuperPool. As the total deposit assets are incorrectly reduced, users may lose a large portion of their tokens.
### Steps to Reproduce

1. A user deposits assets into the SuperPool.
2. Another user borrows a significant amount from the Base Pool.
3. The borrowed amount is not repaid, leading to a bad debt situation.
4. The `rebalanceBadDebt` function is called to liquidate the bad debt.
5. The function reduces the total deposit assets by the entire borrowed amount instead of the actual loss incurred.
6. The first user attempts to withdraw their assets from the SuperPool and receives significantly less than expected due to the incorrect deduction.


```solidity
// instead of reducing the total deposit by the loss we deduct the whole amount borrowed
    function testDepositBorrowLiquidateandWithdrawAssets() public { //uint96 assets
        uint96 assets1 = 200e18;
        testCanDepositAssets(assets1);

// initiall shares of user 200e18
        assertEq(pool.getAssetsOf(linearRatePool, user),200e18);

       
     // another user borrows 10e18 and his borrow ebters baddebt, loss of about 74% of the position. the debt was cleared but when user withdraws 100e18 all his shares is burnt because all the borrowed amount was deducted.   
         vm.startPrank(user);
        asset2.approve(address(positionManager), 100e18);
        asset3.approve(address(positionManager), 50e18);

        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory actions = new Action[](6);
        (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
        actions[1] = deposit(address(asset2), 100e18);
        actions[2] = deposit(address(asset3), 50e18);

        actions[3] = addToken(address(asset2));
        actions[4] = addToken(address(asset3));
        actions[5] = borrow(linearRatePool, 100e18);
        // actions[4] = approve(address(mockswap), address(asset1), 1e18);
        // bytes memory data = abi.encodeWithSelector(SWAP_FUNC_SELECTOR, address(asset1), address(asset3), 1e18);
        // actions[5] = exec(address(mockswap), 0, data);
        // actions[6] = addToken(address(asset3));
        positionManager.processBatch(position, actions);
        vm.stopPrank();
        assertTrue(riskEngine.isPositionHealthy(position));

        // (uint256 totalAssetValue, uint256 totalDebtValue, uint256 minReqAssetValue) = riskEngine.getRiskData(position);

        // assertEq(totalAssetValue, 150e18);
        // assertEq(totalDebtValue, 100e18);
        // assertEq(minReqAssetValue, 111.1111111111111110001e18);

        // construct liquidator data
        DebtData memory debtData = DebtData({ poolId: linearRatePool, amt: type(uint256).max });
        DebtData[] memory debts = new DebtData[](1);
        debts[0] = debtData;
        AssetData memory asset1Data = AssetData({ asset: address(asset3), amt: 50e18 });
        AssetData memory asset2Data = AssetData({ asset: address(asset2), amt: 100e18 });
        AssetData[] memory assets = new AssetData[](2);
        assets[0] = asset1Data;
        assets[1] = asset2Data;

        // modify asset2 price from 1eth to 0.1eth
        FixedPriceOracle pointOneEthOracle = new FixedPriceOracle(1e16);
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset2), address(pointOneEthOracle));
         vm.stopPrank();
        assertFalse(riskEngine.isPositionHealthy(position));

         // modify asset2 price from 1eth to 0.1eth
        FixedPriceOracle pointtwoEthOracle = new FixedPriceOracle(5e17);
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset3), address(pointtwoEthOracle));
         vm.stopPrank();
        assertFalse(riskEngine.isPositionHealthy(position));

        (uint256 totalAssetValue2, uint256 totalDebtValue2, uint256 minReqAssetValue2) = riskEngine.getRiskData(position);

        assertEq(totalAssetValue2, 26e18);
        assertEq(totalDebtValue2, 100e18);
        assertEq(minReqAssetValue2, 111.111111111111111001e18);

       

        // liquidate
        vm.startPrank(protocolOwner);
        asset1.approve(address(positionManager), 100e18);
        positionManager.liquidateBadDebt(position);
        vm.stopPrank();

        vm.prank(user);
        pool.withdraw(linearRatePool, 100e18, user, user);

        assertEq(pool.getAssetsOf(linearRatePool, user), 0);
        assertEq(pool.balanceOf(user, linearRatePool), 0);


        assertEq(asset1.balanceOf(user), 100000000000000000000);

// even if admins tries to swap and redeposit this token back there is a big risk here 
// 1. contract can be paused  
// 2. the deposit inflates the deposited shares and the loss to the user remains the same

    }
```

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L528-L549

## Tool used

Manual Review

## Recommendation



Even if Admin batches a call to clear bad debt and swap the asset gotten and redeposit into the pool we should note that pools can be paused to prevent deposits but withdrawals, and bad debt clearing can't be stopped.  hence it is safe to account for this appropriately and transfer the swapped funds back to the pool. 

To correctly socialize the loss among all lenders, modify the `rebalanceBadDebt` function to calculate the actual loss and distribute it proportionally among all lenders. 

### Proposed Solution

1. Calculate the loss in ETH: `loss = ETH value of borrowed asset - ETH value of total deposit`.
2. Determine the loss per lender by dividing the loss by the total borrowed asset in ETH.
3. Multiply the result by the total borrowed asset in token decimals to get the actual loss to be subtracted.
4. Update the `rebalanceBadDebt` function to include a new variable for the loss and adjust the total deposit assets accordingly.

Here’s a conceptual example of the modification:

```solidity
uint256 loss = (totalBorrowAssetsInETH - totalDepositAssetsInETH);
uint256 lossInToken = (loss * totalBorrowAssetsInTokenDecimals) / totalBorrowAssetsInETH;

```

This change will ensure that the loss is equitably realized among all lenders, preventing a significant and unfair loss to any single user.