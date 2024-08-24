Radiant Butter Dragonfly

Medium

# Inconsistent Handling of ERC-20 Token Decimals

## Summary
The `ChainlinkEthOracle`, `ChainlinkUsdOracle`, and `RedstoneOracle` contracts assume that all ERC-20 tokens and Chainlink price feeds implement the `decimal()` function, which is not part of the original ERC-20 standard but is an optional extension. This assumption can cause contract failures when interacting with tokens or feeds that do not support this function.

## Vulnerability Detail
- The contract directly calls the `decimal()` function on ERC-20 tokens and Chainlink price feeds without verifying whether the function is supported.
- Not all ERC-20 tokens implement the `IERC20Metadata` interface, which includes the `decimal()` function.
- Similarly, not all Chainlink price feeds may implement the `decimal()` function.
ChainlinkEthOracle
L71
`return amt.mulDiv(_getPriceWithSanityChecks(asset), (10 ** IERC20Metadata(asset).decimals()));`
L80
`assert(IAggegregatorV3(feed).decimals() == 18);`
ChainlinkUsdOracle
L82
`uint256 decimals = IERC20Metadata(asset).decimals();`
L95
`assert(IAggegregatorV3(feed).decimals() == 8);`
RedstoneOracle
L39
`ASSET_DECIMALS = IERC20Metadata(asset).decimals();`

## Impact
- If a token or feed does not support the `decimals()` function, the contract will revert, causing the entire transaction to fail.
- Limits the contract's compatibility with a wide range of ERC-20 tokens and Chainlink price feeds that do not implement the `decimals()` function.
- Users may experience failed transactions and inability to interact with the contract.

## Code Snippet
- ChainlinkEthOracle
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L67-L72
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L79-L84
- ChainlinkUsdOracle
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L76-L87
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L94-L99
- RedstoneOracle
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/RedstoneOracle.sol#L37-L46

## Tool used

Manual Review

## Recommendation
- Use `try/catch` blocks to safely call the `decimals()` function and handle cases where the function is not supported.
- Provide a sensible default value (e.g., 18 decimals) if the `decimals()` function is not available.
ChainlinkEthOracle
```diff
function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
    _checkSequencerFeed();

+   uint256 decimals;
+   try IERC20Metadata(asset).decimals() returns (uint8 dec) {
+       decimals = dec;
+   } catch {
+       decimals = 18; // Default to 18 decimals if decimals() is not supported
+   }

    return amt.mulDiv(_getPriceWithSanityChecks(asset), (10 ** decimals));
}

function setFeed(address asset, address feed, uint256 stalePriceThreshold) external onlyOwner {
+   uint256 feedDecimals;
+   try IAggegregatorV3(feed).decimals() returns (uint8 dec) {
+       feedDecimals = dec;
+   } catch {
+       revert("Feed does not support decimals() function");
+   }

+   require(feedDecimals == 18, "Feed must have 18 decimals");
-   assert(IAggegregatorV3(feed).decimals() == 18);
    priceFeedFor[asset] = feed;
    stalePriceThresholdFor[feed] = stalePriceThreshold;
    emit FeedSet(asset, feed);
}
```
ChainlinkUsdOracle
```diff
function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
    _checkSequencerFeed();

    uint256 ethUsdPrice = _getPriceWithSanityChecks(ETH);
    uint256 assetUsdPrice = _getPriceWithSanityChecks(asset);

-   uint256 decimals = IERC20Metadata(asset).decimals();
+   uint256 decimals;
+   try IERC20Metadata(asset).decimals() returns (uint8 dec) {
+       decimals = dec;
+   } catch {
+       decimals = 18; // Default fallback
+   }

    // [ROUND] price is rounded down. this is used for both debt and asset math, no effect
    if (decimals <= 18) return (amt * 10 ** (18 - decimals)).mulDiv(uint256(assetUsdPrice), uint256(ethUsdPrice));
    else return (amt / (10 ** decimals - 18)).mulDiv(uint256(assetUsdPrice), uint256(ethUsdPrice));
}

function setFeed(address asset, address feed, uint256 stalePriceThreshold) external onlyOwner {
-   assert(IAggegregatorV3(feed).decimals() == 8);
+   try IAggegregatorV3(feed).decimals() returns (uint8 dec) {
+       assert(dec == 8);
+   } catch {
+       revert("Feed does not support decimals()");
+   }
    priceFeedFor[asset] = feed;
    stalePriceThresholdFor[feed] = stalePriceThreshold;
    emit FeedSet(asset, feed);
}
```
RedstoneOracle
```diff
constructor(address asset, bytes32 assetFeedId, bytes32 ethFeedId) {
    ASSET = asset;
+   uint256 decimals;
+   try IERC20Metadata(asset).decimals() returns (uint8 dec) {
+       decimals = dec;
+   } catch {
+       decimals = 18; // Fallback to 18 decimals if `decimals()` is not supported
+   }
+   ASSET_DECIMALS = decimals;
-   ASSET_DECIMALS = IERC20Metadata(asset).decimals();

    ASSET_FEED_ID = assetFeedId;
    ETH_FEED_ID = ethFeedId;

    dataFeedIds[0] = assetFeedId;
    dataFeedIds[1] = ethFeedId;
}
```