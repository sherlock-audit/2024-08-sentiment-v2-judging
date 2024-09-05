Bubbly Wool Pike

Medium

# M-1:  Delisted asset can still be borrowed against

## Summary
Continued Use of Delisted Assets as Collateral 
## Vulnerability Detail
In the `PositionManager` contract, assets that have been delisted can still be used as collateral by positions that already hold them in their `PositionAssets` array. This creates two problematic scenarios:

**Continued Use of Delisted Assets:** If an asset is delisted, but the protocol does not remove it from existing positions, those positions can continue to use the delisted asset as collateral. This means users can still borrow against an asset that is no longer supported, which may undermine the protocol’s risk management.

**Removal of Oracle for Delisted Assets:** If an asset is delisted and the protocol subsequently removes the oracle for that asset, positions holding the asset may face immediate liquidation. Without a valid price feed, the asset's value cannot be determined, leading to quick and potentially unfair liquidations. Users may lose their collateral without sufficient notice or opportunity to adjust their positions.
## Impact
These scenarios pose significant risks to both the protocol and its users:

**For the Protocol:** Allowing delisted assets to be used as collateral could expose the protocol to unexpected risks, especially if the asset's value declines or becomes volatile after delisting.

**For Users:** The removal of the oracle for a delisted asset can result in abrupt liquidations, causing users to lose their collateral unfairly. This undermines user trust and could lead to financial losses, particularly in volatile markets.

## Proof of Concept
Consider the following scenarios where a delisted asset continues to be used as collateral:

**Scenario 1:** An asset is delisted but remains in the `PositionAssets` array of existing positions. Users can still borrow against this asset despite it being delisted, which might not align with the protocol's risk management objectives.

solidity
Copy code
```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../BaseTest.t.sol";
import {console2} from "forge-std/console2.sol";
import {FixedPriceOracle} from "src/oracle/FixedPriceOracle.sol";

contract SuperPoolUnitTests is BaseTest {
    uint256 initialDepositAmt = 1e5;

    Pool pool;
    Registry registry;
    SuperPool superPool;
    RiskEngine riskEngine;
    SuperPoolFactory superPoolFactory;
    uint256 public HighFee = 1e19;

    address public feeTo = makeAddr("FeeTo");

    function setUp() public override {
        super.setUp();

        pool = protocol.pool();
        registry = protocol.registry();
        riskEngine = protocol.riskEngine();
        superPoolFactory = protocol.superPoolFactory();

        FixedPriceOracle asset1Oracle = new FixedPriceOracle(1e18);
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset1Oracle));

        vm.prank(protocolOwner);
        asset1.mint(address(this), initialDepositAmt);
        asset1.approve(address(superPoolFactory), initialDepositAmt);

        superPool = SuperPool(
            superPoolFactory.deploySuperPool(
                poolOwner,
                address(asset1),
                feeTo,
                0.01 ether,
                1_000_000 ether,
                initialDepositAmt,
                "test",
                "test"
            )
        );
        function test_DelistedCanStillBeBorrowedAgainst() public {
        vm.startPrank(user);
        asset2.approve(address(positionManager), 10e18);
        asset3.approve(address(positionManager), 10e18);
        asset4.approve(address(positionManager), 10e18);
        asset5.approve(address(positionManager), 10e18);
        asset6.approve(address(positionManager), 10e18);

        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory actions = new Action[](14);
        (position, actions[0]) = newPosition(
            user,
            bytes32(uint256(0x123456789))
        );
        actions[1] = deposit(address(asset4), 1e18); // deposit BUSD
        skip(1 days);
        actions[2] = deposit(address(asset2), 0.5e18); // deposit USDC

        actions[3] = deposit(address(asset6), 1e18); // deposit DAI
        actions[4] = addToken(address(asset3)); // add USDT
        actions[5] = borrow(fixedRatePool, 1e18);
        skip(1 days);
        actions[6] = deposit(address(asset3), 1e18); // deposit USDT
        //actions[4] = addToken(address(asset2));
        actions[7] = borrow(fixedRatePool, 1e18);
        actions[8] = deposit(address(asset2), 0.5e18); // add USDC

        actions[9] = deposit(address(asset5), 1e18); // deposit ETH
        actions[10] = addToken(address(asset5)); // add ETH
        //@audit Why am i able to add the same asset to a Position asset?
        // IterableSet lib fixed that 👍
        actions[11] = addToken(address(asset2)); // add USDC
        actions[12] = addToken(address(asset6)); // add DAI
        actions[13] = addToken(address(asset4)); // add BUSD
        positionManager.processBatch(position, actions);
        riskModule.isPositionHealthy(position);
        vm.stopPrank();
        //🚨 First possible scenairo; Delisting of assets by the protocol
        vm.startPrank(protocolOwner);
        protocol.positionManager().toggleKnownAsset(address(asset5));
        protocol.positionManager().toggleKnownAsset(address(asset6));
        vm.stopPrank();
        vm.startPrank(user);
        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory action = new Action[](2);
        (position, actions[0]) = newPosition(
            user,
            bytes32(uint256(0x123456789))
        );

        action[0] = borrow(fixedRatePool, 0.25e18);

        action[1] = borrow(fixedRatePool, 0.25e18);
        positionManager.processBatch(position, action);

        assertEq(riskModule.getTotalAssetValue(position), 5e18);
        assertEq(riskModule.getTotalDebtValue(position), 2.5e18);
        //🚩 The test passes, which is a signal that delisted assets can still be used to take loans
    }
```

**Scenario 2:** An asset is delisted, and its oracle is removed. Positions holding this asset are unable to maintain their health due to the lack of a price feed, leading to sudden liquidations:
solidity
Copy code
```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../BaseTest.t.sol";
import {console2} from "forge-std/console2.sol";
import {FixedPriceOracle} from "src/oracle/FixedPriceOracle.sol";

contract SuperPoolUnitTests is BaseTest {
    uint256 initialDepositAmt = 1e5;

    Pool pool;
    Registry registry;
    SuperPool superPool;
    RiskEngine riskEngine;
    SuperPoolFactory superPoolFactory;
    uint256 public HighFee = 1e19;

    address public feeTo = makeAddr("FeeTo");

    function setUp() public override {
        super.setUp();

        pool = protocol.pool();
        registry = protocol.registry();
        riskEngine = protocol.riskEngine();
        superPoolFactory = protocol.superPoolFactory();

        FixedPriceOracle asset1Oracle = new FixedPriceOracle(1e18);
        vm.prank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset1Oracle));

        vm.prank(protocolOwner);
        asset1.mint(address(this), initialDepositAmt);
        asset1.approve(address(superPoolFactory), initialDepositAmt);

        superPool = SuperPool(
            superPoolFactory.deploySuperPool(
                poolOwner,
                address(asset1),
                feeTo,
                0.01 ether,
                1_000_000 ether,
                initialDepositAmt,
                "test",
                "test"
            )
        );
       
         function test_UnjustLiquidation() public {
        vm.startPrank(user);
        asset2.approve(address(positionManager), 10e18);
        asset3.approve(address(positionManager), 10e18);
        asset4.approve(address(positionManager), 10e18);
        asset5.approve(address(positionManager), 10e18);
        asset6.approve(address(positionManager), 10e18);

        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory actions = new Action[](14);
        (position, actions[0]) = newPosition(
            user,
            bytes32(uint256(0x123456789))
        );
        actions[1] = deposit(address(asset4), 1e18); // deposit BUSD
        skip(1 days);
        actions[2] = deposit(address(asset2), 0.5e18); // deposit USDC

        actions[3] = deposit(address(asset6), 1e18); // deposit DAI
        actions[4] = addToken(address(asset3)); // add USDT
        actions[5] = borrow(fixedRatePool, 1e18);
        skip(1 days);
        actions[6] = deposit(address(asset3), 1e18); // deposit USDT
        actions[7] = borrow(fixedRatePool, 1e18);
        actions[8] = deposit(address(asset2), 0.5e18); // add USDC

        actions[9] = deposit(address(asset5), 1e18); // deposit ETH
        actions[10] = addToken(address(asset5)); // add ETH
        actions[11] = addToken(address(asset2)); // add USDC
        actions[12] = addToken(address(asset6)); // add DAI
        actions[13] = addToken(address(asset4)); // add BUSD
        positionManager.processBatch(position, actions);
        riskModule.isPositionHealthy(position);
        vm.stopPrank();
          //🚨 Delisting an asset, and subsequently Removing the Oracle for those delisted asset
        vm.startPrank(protocolOwner);
        protocol.positionManager().toggleKnownAsset(address(asset5));
        protocol.positionManager().toggleKnownAsset(address(asset6));
        riskEngine.setOracle(address(asset5), address(remEthOracle)); // 1 asset5 = 1 eth
        riskEngine.setOracle(address(asset6), address(remEthOracle)); // 1 asset6 = 1 eth
        vm.stopPrank();

        vm.startPrank(user);
        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory action = new Action[](2);
        (position, actions[0]) = newPosition(
            user,
            bytes32(uint256(0x123456789))
        );

        action[0] = borrow(fixedRatePool, 0.25e18);

        action[1] = borrow(fixedRatePool, 0.25e18);
        vm.expectRevert();
        positionManager.processBatch(position, action);
    }
    //🚩The test passes, which means users with such asset in their position are subject to quick liquidations

  }

```


## Code Snippet
https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/PositionManager.sol#L384
## Tool used

Manual Review

## Recommendation
To address these issues, consider the following actions:

**Prevent Borrowing Against Delisted Assets:** When an asset is delisted, prohibit its use as collateral in any new borrowing actions. Update the risk management system to exclude delisted assets from the collateral calculation for new loans; i.e when calculating the Health of a position post-action, unsupported asset should not be considered in the total value of the account.

**Graceful Handling of Oracle Removal:** If an asset's oracle is removed, allow users a grace period to either repay their loans or replace the delisted asset with another supported asset. This can prevent sudden liquidations and give users a fair chance to manage their positions.

Implementing these changes will help protect both the protocol and its users from the risks associated with delisted assets, ensuring fair and transparent operations.

