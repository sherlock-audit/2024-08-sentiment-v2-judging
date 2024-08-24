Massive Slate Dalmatian

Medium

# `stalePriceThresholdFor` is being set for ETH instead of ETH's feed when creating `ChainlinkUsdOracle`, causing `getValueInEth` to always revert

### Summary

In `ChainlinkUsdOracle`, whenever a new feed is added, the owner is requested to add a stale threshold for that feed, this is done in `ChainlinkUsdOracle::setFeed`, and then `stalePriceThresholdFor[feed]` is set to that value. However, when deploying/creating the contract, an ETH/USD is being passed, but `stalePriceThresholdFor[ETH]` is being set to that value, [here](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L68), instead of the passed feed.

This will cause `getValueInEth` to always revert.

### Root Cause

Because stale threshold are meant to be for feeds, `_getPriceWithSanityChecks` checks against that feed is the price is up-to-date, this is done in:
```solidity
(, int256 price,, uint256 updatedAt,) = IAggegregatorV3(feed).latestRoundData();
if (price <= 0) revert ChainlinkUsdOracle_NonPositivePrice(asset);
if (updatedAt < block.timestamp - stalePriceThresholdFor[feed]) revert ChainlinkUsdOracle_StalePrice(asset);
```
Notice, that it is trying to access the threshold by `stalePriceThresholdFor[feed]` which is 0 (not set), because in the constructor `stalePriceThresholdFor[ETH]` was set and not for the feed.

### Attack Path

1. The owner deploys an instance of `ChainlinkUsdOracle` while passing the ETH/USD feed and the stale threshold for that feed.
2. `stalePriceThresholdFor` gets set for ETH instead of the passed feed.
3. `getValueInEth` will always revert, as `stalePriceThresholdFor[feed]` in `_getPriceWithSanityChecks` will always be 0.

### Impact

`ChainlinkUsdOracle::getValueInEth` will always revert.

### PoC

This assumes that another reported issue is fixed, to bypass this, comment out `_checkSequencerFeed();` in `ChainlinkUsdOracle::getValueInEth`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {ChainlinkEthOracle} from "../src/oracle/ChainlinkEthOracle.sol";
import {ChainlinkUsdOracle} from "../src/oracle/ChainlinkUsdOracle.sol";

contract ContestTest is Test {
    address public constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    address public constant USDC_ETH_FEED =
        0x986b5E1e1755e3C2440e960477f25201B0a8bbD4;
    address public constant USDC_USD_FEED =
        0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6;
    address public constant ETH_USD_FEED =
        0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;

    address owner;
    uint256 ownerPK;

    function setUp() public virtual {
        uint256 fork = vm.createFork(
            MAINNET_RPC_URL,
            20_543_153
        );
        vm.selectFork(fork);

        (owner, ownerPK) = makeAddrAndKey("owner");
    }

    function test_USDC_ETH_price() public {
        ChainlinkUsdOracle oracle = new ChainlinkUsdOracle(
            owner,
            address(0),
            ETH_USD_FEED,
            30 days
        );

        vm.prank(owner);
        oracle.setFeed(USDC, USDC_USD_FEED, 30 days);

        vm.expectRevert(
            abi.encodeWithSelector(
                ChainlinkUsdOracle.ChainlinkUsdOracle_StalePrice.selector,
                ETH
            )
        );
        oracle.getValueInEth(USDC, 1e6);
    }
}
```

### Mitigation

In `ChainlinkUsdOracle`'s constructor, replace:
```solidity
stalePriceThresholdFor[ETH] = ethUsdThreshold;
```
with:
```solidity
stalePriceThresholdFor[ethUsdFeed] = ethUsdThreshold;
```