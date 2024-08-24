Feisty Sangria Cougar

High

# `getValueInEth` in `ChainlinkEthOracle.sol` returns wrong value

## Summary
The function called `getValueInEth` in `ChainlinkEthOracle.sol` returns wrong value
## Vulnerability Detail
After diving into the `ChainlinkEthOracle` contract I come across the function `getValueInEth`.:
```solidity
    /// @notice Compute the equivalent ETH value for a given amount of a particular asset
    /// @param asset Address of the asset to be priced
    /// @param amt Amount of the given asset to be priced
    function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
        _checkSequencerFeed();

        // [ROUND] price is rounded down. this is used for both debt and asset math, neutral effect.
        return amt.mulDiv(_getPriceWithSanityChecks(asset), (10 ** IERC20Metadata(asset).decimals()));
    }
```
Reading from the function's *NatSpec*, we see that the purpose of the function is to compute and return the equivalent ETH value for a given amount of a particular asset. However, in practice this does not happen, the function does not work as intended.
## Proof of Concept
In the following example I use the `LINK` token on Arbitrum Sepolia Testnet which is a standart ERC20 with 18 decimals and its Chainlink price feed presented in the documentation:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// import { IOracle } from "src/interfaces/IOracle.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import { Test, console } from "forge-std/Test.sol";
import "src/oracle/ChainlinkEthOracle.sol";

contract ChainlinkEthOracleTest is Test  {

    using Math for uint256;

    address public arbSeqFeed = address(1);
    address public owner = address(2);
    ChainlinkEthOracle public chainlinkEthOracle = new ChainlinkEthOracle(owner, arbSeqFeed);

    // The original function in `ChainlinkEthOracle.sol`:
    // /// @notice Compute the equivalent ETH value for a given amount of a particular asset
    // /// @param asset Address of the asset to be priced
    // /// @param amt Amount of the given asset to be priced
    // function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
    //     _checkSequencerFeed();
    //
    //     // [ROUND] price is rounded down. this is used for both debt and asset math, neutral effect.
    //     return amt.mulDiv(_getPriceWithSanityChecks(asset), (10 ** IERC20Metadata(asset).decimals()));
    // }
    function testGetValueInEth() external view {
        // _checkSequencerFeed(); @notice We assume it passes
        address asset = 0xb1D4538B4571d411F07960EF2838Ce337FE1E80E; // LINK token contract on Arbitrum Sepolia Testnet
        // https://sepolia.arbiscan.io/address/0xb1d4538b4571d411f07960ef2838ce337fe1e80e#code
        uint256 amt = 250; // 250 LINK tokens
        console.log("LINK decimals: ", IERC20Metadata(asset).decimals());
        
        console.log("result: ", amt.mulDiv(_getPriceWithSanityChecks(), (10 ** IERC20Metadata(asset).decimals())));
    }

    // The original function in `ChainlinkEthOracle.sol`:
    // /// @dev Fetch price from chainlink feed with sanity checks
    // function _getPriceWithSanityChecks(address asset) private view returns (uint256) {
    //     address feed = priceFeedFor[asset];
    //     (, int256 price,, uint256 updatedAt,) = IAggegregatorV3(feed).latestRoundData();
    //     if (price <= 0) revert ChainlinkEthOracle_NonPositivePrice(asset);
    //     if (updatedAt < block.timestamp - stalePriceThresholdFor[feed]) revert ChainlinkEthOracle_StalePrice(asset);
    //     return uint256(price);
    // }

    /// @dev Fetch price from chainlink feed with sanity checks
    function _getPriceWithSanityChecks(/* address asset */) private view returns (uint256) {
        address feed = 0x3ec8593F930EA45ea58c968260e6e9FF53FC934f; // LINK/ETH Arbitrum Sepolia Testnet price feed
        // https://docs.chain.link/data-feeds/price-feeds/addresses?network=arbitrum&page=1#arbitrum-sepolia
        (, int256 price,, /* uint256 updatedAt */,) = IAggegregatorV3(feed).latestRoundData();
        if (price <= 0) revert(); /* ChainlinkEthOracle_NonPositivePrice(asset) */
        // if (updatedAt < block.timestamp - stalePriceThresholdFor[feed]) revert ChainlinkEthOracle_StalePrice(asset); @notice We assume the 2nd `if` statement passes
        console.log("LINK/ETH price: ", uint256(price));
        return uint256(price);
    }
}
```
After running the test on the Arbitrum Sepolia Testnet with `forge test --mt testGetValueInEth --fork-url $ARB_SEPOLIA_RPC_URL -vvvvv` results are:
```solidity
[⠒] Compiling...
[⠒] Compiling 1 files with Solc 0.8.24
[⠢] Solc 0.8.24 finished in 1.96s
Compiler run successful!

Ran 1 test for test/core/oracle/ChainlinkEthOracle.sol:ChainlinkEthOracleTest
[PASS] testGetValueInEth() (gas: 30179)
Logs:
  LINK decimals:  18
  LINK/ETH price:  3875087639449574
  result:  0

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 3.35s (2.11s CPU time)

Ran 1 test suite in 3.77s (3.35s CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```
As you can see the value of `result` = `0` while the actual price of `250` `LINK` tokens = `0,97` ETH

In order to run the test, make a folder in `protocol-v2/test` called `oracle` and inside it create a new file with the name `ChainlinkEthOracleTest.t.sol`. Paste the contract from the example above. Then create a `.env` file inside `protocol-v2` with a valid RPC_URL called `ARB_SEPOLIA_RPC_URL`. Run the test file with typing these commands in the following order:
1. `source .env`
2. `forge test --mt testGetValueInEth --fork-url $ARB_SEPOLIA_RPC_URL -vvvvv`
## Impact
Significant losses and unintended behaviour of the protocol
## Code Snippet
https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/oracle/ChainlinkEthOracle.sol#L64-L72
## Tool used
Manual Review
Foundry
Remix