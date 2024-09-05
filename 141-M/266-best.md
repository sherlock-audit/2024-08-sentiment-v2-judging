Abundant Hazel Newt

High

# Super Pool shares can be inflated by bad debt leading to overflows

## Summary
Super Pool shares can be inflated by bad debt leading to overflows.

## Vulnerability Detail
Super Pool shares are calculated based on total assets and total supply, i.e $Shares = Deposit Amount * Total Shares / Total Assets$.
[SuperPool.sol#L194-L197](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L194-L197):
```solidity
    function convertToShares(uint256 assets) public view virtual returns (uint256 shares) {
        (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
        return _convertToShares(assets, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
    }
```
At the beginning, when user deposits $1000e18$ asset tokens, they can mint $1000e18$ shares. The assets will be deposited into underlying pools and normally `Shares per Token` is expected to be deflated as interest accrues. 

However, if the borrowed assets are not repaid, bad debt may occur and it can be liquidated by pool owner. As a result, `Total Assets` owned by the Super Pool will be largely reduced, as a result, `Shares per Token` can be heavily inflated to a very large value, eventually leading to overflows if bad debt liquidated for several times.

Consider the following scenario in PoC:
1. Initially in Super Pool `Total Assets` is $1000$ and `Total Shares` is $1000$, `Shares per Token` is $1$;
2. Depositor mints $1000e18$ shares by depositing $1000e18$ asset tokens, the assets is deposited into underlying pool;
3. Borrower borrows $1000e18$ asset tokens from underlying pool, somehow the borrower is unable to repay and due to price fluctuation, bad debt occurs and is liquidated by the owner;
4. At the point, Super Pool's `Total Assets` is $1000$ and `Total Shares` is $1000000000000000001000$, `Shares per Token` is inflated to $999000999000999001999000999000999000$;
5. As more asset tokens may be deposited into underlying pool through Super Pool, similar bad debt may occur again and `Shares per Token` will be further inflated. 

In the case of PoC, `Shares per Token` can be inflated to be more than `uint256.max`(around $1e78$) after just **4** bad debt liquidations:
| | Total Assets | Total Shares  | Shares per Token  |
| :------ | :------------| :-------------| :------------------|
| 1 | 1000 | 1000000000000000001000 | 999000999000999001999000999000999000 |
| 2 | 1000| 999000999000999002999000999000999001999 | 998002996004994008990010988012986015984015984015984015 |
| 3 | 1000| 998002996004994009989011987013985018983016983016983017983 | 997005990014979030958053933080904114868148834182800217766233766233766233 |
| 4 | 1000| 997005990014979031956056929085898124857160821196785236749250749250749251749 | **OverFlow** |

Please run the PoC in **BigTest.t.sol**:
```solidity
    function testAudit_Overflows() public {
        // Pool Asset
        MockERC20 poolAsset = new MockERC20("Pool Asset", "PA", 18);
        // Collateral Asset
        MockERC20 collateralAsset = new MockERC20("Collateral Asset", "CA", 18);

        vm.startPrank(protocolOwner);
        positionManager.toggleKnownAsset(address(poolAsset));
        positionManager.toggleKnownAsset(address(collateralAsset));
        riskEngine.setOracle(address(poolAsset), address(new FixedPriceOracle(1e18)));
        riskEngine.setOracle(address(collateralAsset), address(new FixedPriceOracle(1e18)));
        vm.stopPrank();

        // Create Underlying Pool
        address poolOwner = makeAddr("PoolOwner");

        vm.startPrank(poolOwner);
        bytes32 FIXED_RATE_MODEL_KEY = 0xeba2c14de8b8ca05a15d7673453a0a3b315f122f56770b8bb643dc4bfbcf326b;
        uint256 poolId = pool.initializePool(poolOwner, address(poolAsset), type(uint128).max, FIXED_RATE_MODEL_KEY);
        riskEngine.requestLtvUpdate(poolId, address(collateralAsset), 0.8e18);
        riskEngine.acceptLtvUpdate(poolId, address(collateralAsset));
        vm.stopPrank();

        // Create Super Pool
        address superPoolOwner = makeAddr("SuperPoolOwner");
        poolAsset.mint(superPoolOwner, 1000);

        vm.startPrank(superPoolOwner);
        poolAsset.approve(address(superPoolFactory), 1000);
        address superPoolAddress = superPoolFactory.deploySuperPool(
            superPoolOwner, // owner
            address(poolAsset), // asset
            superPoolOwner, // feeRecipient
            0, // fee
            10000e18, // superPoolCap
            1000, // initialDepositAmt
            "SuperPool", // name
            "SP" // symbol
        );
        vm.stopPrank();

        SuperPool superPool = SuperPool(superPoolAddress);

        // add pool
        vm.prank(superPoolOwner);
        superPool.addPool(poolId, 1000e18);

        address alice = makeAddr("Alice");
        address bob = makeAddr("Bob");

        (address payable position, Action memory newPos) = newPosition(bob, "Borrower");
        positionManager.process(position, newPos);

        for (uint i; i < 3; ++i) {
            inflatedSharesByBadDebt(alice, bob, position, poolId, superPool, poolAsset, collateralAsset);
        }

        inflatedSharesByBadDebt(alice, bob, position, poolId, superPool, poolAsset, collateralAsset);
        superPool.accrue();

        // Super Pool operations are blocked
        vm.expectRevert("Math: mulDiv overflow");
        superPool.previewDeposit(1e18);

        vm.expectRevert("Math: mulDiv overflow");
        superPool.previewWithdraw(1e18);
    }

    function inflatedSharesByBadDebt(
        address depositor, 
        address borrower,
        address position,
        uint256 poolId, 
        SuperPool superPool,
        MockERC20 poolAsset, 
        MockERC20 collateralAsset
    ) private {
        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(collateralAsset), address(new FixedPriceOracle(1e18)));
        vm.stopPrank();

        uint256 assetAmount = 1000e18;
        uint256 collateralAmount = assetAmount * 10 / 8;

        // Depositor deposits
        poolAsset.mint(depositor, assetAmount);

        vm.startPrank(depositor);
        poolAsset.approve(address(superPool), assetAmount);
        superPool.deposit(assetAmount, depositor);
        vm.stopPrank();

        // Borrower borrows from Underlying Pool
        collateralAsset.mint(borrower, collateralAmount);

        Action memory addNewCollateral = addToken(address(collateralAsset));
        Action memory depositCollateral = deposit(address(collateralAsset), collateralAmount);
        Action memory borrowAct = borrow(poolId, assetAmount);

        Action[] memory actions = new Action[](3);
        actions[0] = addNewCollateral;
        actions[1] = depositCollateral;
        actions[2] = borrowAct;
    
        vm.startPrank(borrower);
        collateralAsset.approve(address(positionManager), type(uint256).max);
        positionManager.processBatch(position, actions);
        vm.stopPrank();

        // Collateral price dumps and Borrower's position is in bad debt
        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(collateralAsset), address(new FixedPriceOracle(0.8e18)));
        vm.stopPrank();

        // Owner liquiates bad debt
        vm.prank(protocolOwner);
        positionManager.liquidateBadDebt(position);
    }
```

## Impact
Shares are inflated by bad debts, the more volatile an asset is, the more likely bad debt occurs. Small bad debt may not be a problem because they can only inflate shares by a little bit, however, a few large bad debts as showed in PoC can cause irreparable harm to the protocol (it is especially so if the asset token has higher decimals), and shares are very likely be inflated to overflow in the long run. 
As a result, most of the operations can be blocked, users cannot deposit or withdraw. 

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L456-L472

## Tool used
Manual Review

## Recommendation
It is recommended to adjust token/share ratio if it has been inflated to a very large value, but ensure the precision loss is acceptable. For example, if the ratio value is $1000000000000000000000000000000000000$ ($1e36$), it can be adjusted to $1000000000000000000$ ($1e18$). This can be done by using a dynamic `AdjustFactor` to limit the ratio to a reasonable range:
[SuperPool.sol#L456-L472](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L456-L472):
```diff
    function _convertToShares(
        uint256 _assets,
        uint256 _totalAssets,
        uint256 _totalShares,
        Math.Rounding _rounding
    ) public view virtual returns (uint256 shares) {
-       shares = _assets.mulDiv(_totalShares + 1, _totalAssets + 1, _rounding);
+       shares = _assets.mulDiv(_totalShares / AdjustFactor + 1, _totalAssets + 1, _rounding);
    }

    function _convertToAssets(
        uint256 _shares,
        uint256 _totalAssets,
        uint256 _totalShares,
        Math.Rounding _rounding
    ) public view virtual returns (uint256 assets) {
-       assets = _shares.mulDiv(_totalAssets + 1, _totalShares + 1, _rounding);
+       assets = (_shares / AdjustFactor).mulDiv(_totalAssets + 1, (_totalShares / AdjustFactor) + 1, _rounding);
    }
```
