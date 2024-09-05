Bubbly Wool Pike

Medium

# [M-5] Inability to Transfer Out Delisted Assets from PositionAsset Array

## Description:
In the protocol, when an asset is delisted, positions that hold this asset in their `PositionAsset` array are unable to transfer the asset out. This creates a situation where users with delisted assets are effectively trapped, unable to manage or liquidate their positions. The inability to transfer out these assets may lead to various operational and financial issues for users, particularly if the asset's value declines or if the user wishes to rebalance their portfolio.

## Impact:
The inability to transfer delisted assets introduces several significant risks:

User Funds Locked: Users with delisted assets are unable to transfer or sell them, effectively locking their funds. This can lead to significant financial loss if the value of the delisted asset declines or if the user is unable to manage their position effectively.

Operational Inefficiency: The inability to remove delisted assets from a position may prevent users from optimizing their portfolios or fulfilling other financial strategies, leading to a suboptimal user experience.

## Proof of Concept:
Consider the following scenario:

A user holds a delisted asset in their PositionAsset array. The protocol does not allow the transfer of this asset out of the position, effectively locking the user’s funds and preventing any further management of their position.
The relevant portion of the code might look something like this:

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
 function test_DelistedCantStillBeTransfered() public {
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

        vm.startPrank(protocolOwner);
        protocol.positionManager().toggleKnownAsset(address(asset5));
        protocol.positionManager().toggleKnownAsset(address(asset6));
        // riskEngine.setOracle(address(asset5), address(remEthOracle)); // 1 asset5 = 1 eth
        // riskEngine.setOracle(address(asset6), address(remEthOracle)); // 1 asset6 = 1 eth
        vm.stopPrank();
        vm.startPrank(user);
        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory action = new Action[](2);
        (position, actions[0]) = newPosition(
            user,
            bytes32(uint256(0x123456789))
        );

        action[0] = transfer(user, address(asset2), 0.25e18);

        action[1] = borrow(fixedRatePool, 0.25e18);
        positionManager.processBatch(position, action);
}
```
the Test fails which means user asset can't be transfered if it has been delisted by the protocol
## Recommended Mitigation:
To resolve this issue, consider implementing the following changes:

Allow Transfers of Delisted Assets: Modify the transfer logic to permit the transfer of delisted assets out of the PositionAsset array. This will allow users to manage their positions and remove delisted assets as needed.
**Alternative Mechanisms:** If transferring delisted assets is not an option, consider implementing an alternative mechanism, such as allowing users to sell or liquidate the asset within the protocol, or providing a redemption process for delisted assets.
## Code Snipet
https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/PositionManager.sol#L307
