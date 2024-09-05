Gorgeous Gingerbread Griffin

Medium

# Incorrect Decimals Check in Chainlink Price Feed Setup


## Reference
- https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L80
- https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L95
## Summary
The `setFeed` function in `ChainlinkEthOracle` and `ChainlinkUsdOracle` contracts contains a check that ensures the decimals for each feed are a fixed value (either 18 for ETH feeds or 8 for USD feeds). However, Chainlink feeds can have varying decimal configurations depending on the asset, which introduces a risk of incorrectly assuming uniformity across feeds. T
## Vulnerability Detail
In both contracts, the `setFeed` function asserts a fixed decimal value (e.g., `assert(IAggregatorV3(feed).decimals() == 18);` in `ChainlinkEthOracle` and `assert(IAggregatorV3(feed).decimals() == 8);` in `ChainlinkUsdOracle`). The assumption that all feeds have a uniform decimal format is incorrect as different assets can have different decimal configurations within Chainlink. This can lead to miscalculations when fetching prices and converting them for use in the protocol. 

If a price feed with a different decimal configuration is provided, this assertion will fail, causing the transaction to revert. For example, if a Chainlink feed has 6 decimals instead of the assumed 8 or 18, the function will revert, making it impossible to set the feed. This issue can prevent onboarding critical assets, lead to disruptions in protocol operations, and delay the configuration of price feeds.

This issue becomes more concerning when dealing with diverse assets that rely on Chainlink feeds, as differing decimals are common across various assets. The rigid assumption made in the current implementation not only limits feed configurability but also introduces potential operational risks when integrating new feeds. This could cause significant disruptions, especially in environments where time-sensitive updates are essential for maintaining accurate asset valuations.
## Impact
The protocol will be unable to set assets with feeds having different decimals, leading to missing or incorrect price data. Even it will cause continous reverts and restrict the protocol to only a few limited feeds. 
## Tool used

Manual Review

## Recommendation
Remove the fixed decimal assertion and dynamically handle feeds with varying decimals. Instead of assuming a fixed decimal configuration, fetch the feed’s decimals during setup and adjust calculations accordingly.