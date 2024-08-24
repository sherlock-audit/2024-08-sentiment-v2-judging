Zesty Rainbow Wombat

Medium

# PositionManager.liquidate() lacks slippage control and a liquidator might receive less collateral tokens than he expected.

### Summary

```PositionManager.liquidate()``` lacks slippage control and a liquidation might receive less collateral tokens than he expected. The liquidator might start his liquidation process with the current ```liquidationfee```. However, it might be  frontun by ```setLiquidationFee()```, which might raise the ```liquidationfee```. As a result, the liquidator will receive less collateral tokens than he expected.  

### Root Cause

There is a race condition between ```PositionManager.liquidate()``` and  ```setLiquidationFee()```: the former will read ```liquidationfee``` and the later will update ```liquidationfee```. If the former is fronrun by the later, then the liquidator will receive less collateral tokens than he expected. 

[https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L516-L519](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L516-L519)

### Internal pre-conditions

 None

### External pre-conditions

The liquidation fee is increased by ```setLiquidationFee()```, which front-run a ```PositionManager.liquidate()``` transaction.

### Attack Path

An example (shown in the POC): 
1. leo initiates ```PositionManager.liquidate()```  with ```liquidationfee = 0%```, expecting to receive 100 ether asset2 tokens.
2. This transaction is frontrun by  ```setLiquidationFee()```, which set  ```liquidationfee = 5%```;
3. Leo's ```PositionManager.liquidate()```  proceeds with the new ```liquidationfee = 5%```. Frank receives only 95 ether asset2, which is less tokens than he expected. Frank might be better off to buy those tokens from the market. If he knew ```liquidationfee = 5%```, he would not have started that liquidation process. 
4. run ``` forge test --match-test testLiquidate1 -vv```

### Impact

PositionManager.liquidate() lacks slippage control and a liquidator might receive less collateral tokens than he expected. He might perform a liquidation that is worse than he purchase those tokens from the market. 

### PoC

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { FixedRateModel } from "../../src/irm/FixedRateModel.sol";
import { LinearRateModel } from "../../src/irm/LinearRateModel.sol";
import "../BaseTest.t.sol";
import { MockERC20 } from "../mocks/MockERC20.sol";
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { Action, Operation } from "src/PositionManager.sol";
import { IOracle } from "src/interfaces/IOracle.sol";
import { FixedPriceOracle } from "src/oracle/FixedPriceOracle.sol";
import {DebtData, AssetData} from "../../src/PositionManager.sol";


contract PositionManagerUnitTests is BaseTest {
    // keccak(SENTIMENT_POOL_KEY)
    bytes32 public constant SENTIMENT_POOL_KEY = 0x1a99cbf6006db18a0e08427ff11db78f3ea1054bc5b9d48122aae8d206c09728;
    // keccak(SENTIMENT_RISK_ENGINE_KEY)
    bytes32 public constant SENTIMENT_RISK_ENGINE_KEY =
        0x5b6696788621a5d6b5e3b02a69896b9dd824ebf1631584f038a393c29b6d7555;
    // keccak(SENIMENT_POSITION_BEACON_KEY)
    bytes32 public constant SENTIMENT_POSITION_BEACON_KEY =
        0x6e7384c78b0e09fb848f35d00a7b14fc1ad10ae9b10117368146c0e09b6f2fa2;

    Pool pool;
    Registry registry;
    address payable position;
    RiskEngine riskEngine;
    RiskModule riskModule;
    PositionManager positionManager;

    address public positionOwner = makeAddr("positionOwner");
    FixedPriceOracle asset1Oracle;
    FixedPriceOracle asset2Oracle;
    FixedPriceOracle asset3Oracle;

    function setUp() public override {
        console2.log("testContract: ", address(this));
        super.setUp();

        asset1Oracle = new FixedPriceOracle(10e18);
        asset2Oracle = new FixedPriceOracle(0.5e18);
        asset3Oracle = new FixedPriceOracle(1e18);

        pool = protocol.pool();
        registry = protocol.registry();
        riskEngine = protocol.riskEngine();
        riskModule = riskEngine.riskModule();
        positionManager = protocol.positionManager();

        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset1Oracle));
        riskEngine.setOracle(address(asset2), address(asset2Oracle));
        riskEngine.setOracle(address(asset3), address(asset3Oracle));
        vm.stopPrank();

        asset1.mint(address(this), 10_000 ether);
        asset1.approve(address(pool), 10_000 ether);

        pool.deposit(linearRatePool, 10_000 ether, address(0x9)); // liquidity pool

        Action[] memory actions = new Action[](1);
        (position, actions[0]) = newPosition(positionOwner, bytes32(uint256(3_492_932_942))); // salt
        console2.log("position: ", position);  // position owned by positionOwner...each positionOwner can have multipol eposition with different salt
                                               // so one can open a psotion for another owner?
        PositionManager(positionManager).processBatch(position, actions);


        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(linearRatePool, address(asset3), 0.75e18);
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset3));
        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.75e18);
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));
        vm.stopPrank();

        console2.log("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\n \n ");
    }

    
    function printPosition(address pos, string memory name) public view{
        console2.log("\n -------------------------------------------------------------");
        console2.log("infor for position: ", name);
        console2.log("asset 1 balance: ", asset1.balanceOf(pos));
        console2.log("asset 2 balance: ", asset2.balanceOf(pos));
        console2.log("totalAssetValue: ", riskModule.getTotalAssetValue(pos));
        console2.log("totalDebtValue: ", riskModule.getTotalDebtValue(pos));
        console2.log("healthy? ", riskModule.isPositionHealthy(pos));
        console2.log("\n -------------------------------------------------------------");
    }

     function printBalances(address pos, string memory name) public view{
        console2.log("\n -------------------------------------------------------------");
        console2.log("Balances for  ", name);
        console2.log("asset 1 balance: ", asset1.balanceOf(pos));
        console2.log("asset 2 balance: ", asset2.balanceOf(pos));
        console2.log("\n -------------------------------------------------------------");
    }


    function testLiquidate1() public {      // ???
     
        vm.startPrank(poolOwner);
           
         riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.75 ether);    // asset2 as collateral , asset1 as lend tokens
         vm.warp(block.timestamp + 1 days);
         riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));
         vm.stopPrank();
        
       
        testSimpleDepositCollateral(100 ether);        // collateral is in position

        vm.startPrank(positionOwner);   // add asset2  collateral tokens
        Action memory action = addToken(address(asset2));
        PositionManager(positionManager).process(position, action);
        vm.stopPrank();

        printPosition(position, "position before borrow");


        printBalances(positionOwner, "PositionOwner before borrow...");
        vm.startPrank(positionOwner);
        bytes memory data = abi.encode(linearRatePool, 2 ether);       // borrow 2 ether of asset1
        action = Action({ op: Operation.Borrow, data: data });
        Action[] memory actions = new Action[](1);
        actions[0] = action;
        PositionManager(positionManager).processBatch(position, actions);
        vm.stopPrank();        
     
    
        console2.log("\n The price of asset2 goes down, the position becomes liquidable.");
         testOracle = new FixedPriceOracle(0.25e18);
        console2.log("testOracle: ", address(testOracle));
        vm.startPrank(protocolOwner);
        protocol.riskEngine().setOracle(address(asset2), address(testOracle));
        vm.stopPrank();

        printPosition(position, "after price drops");

          // prepare the data and liquidate
        DebtData[] memory debtData = new DebtData[](1);
        AssetData[] memory assetData = new AssetData[](1);
        debtData[0] = DebtData({poolId: linearRatePool, amt: type(uint256).max});   
        assetData[0] = AssetData({asset: address(asset2), amt: 100 ether});

        console2.log("liquidationFee: ", positionManager.liquidationFee());

        // front-run transaction change the liquidationFee to 5%
        vm.startPrank(protocolOwner);
        positionManager.setLiquidationFee(0.05 ether);
        vm.stopPrank();

        address leo = makeAddr("leo");
        deal(address(asset1), leo, 2 ether);
        vm.startPrank(leo);
        asset1.approve(address(positionManager), 2 ether);
        PositionManager(positionManager).liquidate(position, debtData, assetData);
        vm.stopPrank();
 
        printBalances(leo, " leo after liquidation position");
        
    }
}

```

### Mitigation

_No response_