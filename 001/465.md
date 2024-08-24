Keen Jetblack Turtle

Medium

# `maxWithdraw` and `maxRedeem` are not ERC4626 compliant

## Summary
- both functions `maxWithdraw` and `maxRedeem` can return a value higher than the actual maximum that a `user`  can withdraw , and cause a revert when the user tries to withdraw.which is not compliant with the ERC4626 spec.
## Vulnerability Detail
- form the [readMe](https://github.com/sherlock-audit/2024-08-sentiment-v2/tree/main?tab=readme-ov-file#q-is-the-codebase-expected-to-comply-with-any-eips-can-there-beare-there-any-deviations-from-the-specification) , the `superPool` contract is strictly ERC4626 compliant. 
- per the [ERC4626](https://eips.ethereum.org/EIPS/eip-4626) spec : 

> MUST return the maximum amount of assets that could be transferred from owner through withdraw and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary).

- However the `maxWithdraw` can return a value higher than the actual maximum that can be withdrawn , and cause a revert when the user tries to withdraw. 
```js
    function maxWithdraw(address owner) public view returns (uint256) {
        (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
        return _maxWithdraw(owner, newTotalAssets, totalSupply() + feeShares);
    }
     function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool
        uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
        return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
```
- as we can see from the function, we check that the totalLiquidity in pools is greater than the userAssets , and if so we assume that there is enough liquidity to withdraw the userAssets.however totalLiquidity in pools  doesn't mean that this liquidity can be withdrawn by `superPool`. 

#### poc  : 
- the Poc shows that the function `maxWithdraw` can return an amount larger than what's actually withdrawable, leading to failed transactions. This occurs because `maxWithdraw` considers the total liquidity across all underlying pools, rather than the total liquidity in pools with respect to it's balance, 
- to run poc : create a `poc.sol` in `test/core/` and copy/paste the code below :
```js
 contract testPoc20 is BaseTest {
    // keccak(SENTIMENT_POOL_KEY)
    bytes32 public constant SENTIMENT_POOL_KEY = 0x1a99cbf6006db18a0e08427ff11db78f3ea1054bc5b9d48122aae8d206c09728;
    // keccak(SENTIMENT_RISK_ENGINE_KEY)
    bytes32 public constant SENTIMENT_RISK_ENGINE_KEY = 0x5b6696788621a5d6b5e3b02a69896b9dd824ebf1631584f038a393c29b6d7555;
    // keccak(SENIMENT_POSITION_BEACON_KEY)
    bytes32 public constant SENTIMENT_POSITION_BEACON_KEY = 0x6e7384c78b0e09fb848f35d00a7b14fc1ad10ae9b10117368146c0e09b6f2fa2;

    Pool pool;
    Registry registry;
    address payable position;
    RiskEngine riskEngine;
    PositionManager positionManager;

    FixedPriceOracle asset1Oracle;
    FixedPriceOracle asset2Oracle;
    FixedPriceOracle asset3Oracle;
    address attacker = makeAddr("attacker");

    function setUp() public override {
        super.setUp();

        asset1Oracle = new FixedPriceOracle(7e18);
        asset2Oracle = new FixedPriceOracle(10e18);
        asset3Oracle = new FixedPriceOracle(1e18);

        pool = protocol.pool();
        registry = protocol.registry();
        riskEngine = protocol.riskEngine();
        positionManager = protocol.positionManager();

        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset1Oracle));
        riskEngine.setOracle(address(asset2), address(asset2Oracle));
        riskEngine.setOracle(address(asset3), address(asset3Oracle));
        vm.stopPrank();

        asset1.mint(address(this), 10_000 ether);
        asset1.approve(address(pool), 10_000 ether);

        Action[] memory actions = new Action[](1);
        (position, actions[0]) = newPosition(attacker, bytes32(uint256(3_492_932_942)));

        PositionManager(positionManager).processBatch(position, actions);

        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(linearRatePool, address(asset3), 0.75e18);
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset3));
        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.75e18);
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));
        vm.stopPrank();
    }

    error SuperPool_NotEnoughLiquidity(address superPool);

    function initialSetup() public returns (SuperPool, address) {
        // Setup initial state
        uint256 initialDeposit = 600e18;
        asset1.mint(address(this), initialDeposit);
        asset1.approve(address(pool), initialDeposit);
        pool.deposit(linearRatePool, initialDeposit, address(this));

        // Setup SuperPool with poolA and poolB
        SuperPool superPool = new SuperPool(address(pool), address(asset1), address(this), 0, type(uint256).max, "test", "ts");
        superPool.addPool(linearRatePool, 500e18);
        superPool.addPool(fixedRatePool, 500e18);
        // User A deposits to SuperPool
        address userA = makeAddr("userA");
        uint256 userDeposit = 1000e18;
        asset1.mint(userA, userDeposit);
        vm.startPrank(userA);
        asset1.approve(address(superPool), userDeposit);
        superPool.deposit(userDeposit, userA);
        vm.stopPrank();
        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.75e18);
        riskEngine.acceptLtvUpdate(fixedRatePool, address(asset2));
        vm.stopPrank();
        // Simulate borrower borrowing from poolB
        deposit_asset2(1000 ether);
        vm.startPrank(attacker);
        bytes memory borrowData = abi.encode(fixedRatePool, 400e18);
        Action memory borrowAction = Action({ op: Operation.Borrow, data: borrowData });
        Action[] memory borrowActions = new Action[](1);
        borrowActions[0] = borrowAction;
        PositionManager(positionManager).processBatch(position, borrowActions);
        vm.stopPrank();
        return (superPool, userA);
    }

    function test_maxWithdrawRevert() public {
        (SuperPool superPool, address userA) = initialSetup();

        // get maxWithdraw userA can withdraw without a revert :
        uint256 maxWithdrawAmount = superPool.maxWithdraw(userA);
        // Attempt to withdraw maxWithdraw amount , will revert which SHOULDN'T :
        vm.startPrank(userA);
        vm.expectRevert(abi.encodeWithSelector(SuperPool_NotEnoughLiquidity.selector, address(superPool)));
        superPool.withdraw(maxWithdrawAmount, userA, userA);
        vm.stopPrank();
    }

    function deposit_asset2(uint96 amount) public {
        asset2.mint(attacker, amount);
        vm.startPrank(attacker);
        Action[] memory actions = new Action[](1);
        actions[0] = addToken(address(asset2));
        PositionManager(positionManager).processBatch(position, actions);
        actions[0] = deposit(address(asset2), amount);
        asset2.approve(address(positionManager), amount);
        PositionManager(positionManager).processBatch(position, actions);
        vm.stopPrank();
    }
 }
```
## Impact
- `MaxWithdraw` and `maxRedeem` are not erc4626 compliant
## Code Snippet
- https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L220-L223
- https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L226-L232
## Tool used

Manual Review

## Recommendation

- in `_maxWithdraw` function, you should account for the liquidity in the pool with respect to the `superPool` assets. 
```diff

     function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
-            totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
+            uint256 assetsInPool = POOL.getAssetsOf(depositQueue[i], address(this));
+            uint256 liquidityInPool = POOL.getLiquidityOf(depositQueue[i]);
+           totalLiquidity += liquidityInPool > assetsInPool ? assetsInPool : liquidityInPool
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool
        uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
        return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }

```

