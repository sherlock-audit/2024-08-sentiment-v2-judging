Sharp Sapphire Ferret

Medium

# Price feeds will always check the sequencer even if they are on L1

## Summary
Price feeds will always check the sequencer even if they are on L1. This will cause TX to revert.

## Vulnerability Detail
Oracles don't differentiate between base layers and L2s. They check if the sequencer is active no matter what.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L67-L72
```solidity
    function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
        _checkSequencerFeed();

        uint256 ethUsdPrice = _getPriceWithSanityChecks(ETH);
        uint256 assetUsdPrice = _getPriceWithSanityChecks(asset);

        uint256 decimals = IERC20Metadata(asset).decimals();

        if (decimals <= 18) return (amt * 10 ** (18 - decimals)).mulDiv(uint256(assetUsdPrice), uint256(ethUsdPrice));
        else return (amt / (10 ** decimals - 18)).mulDiv(uint256(assetUsdPrice), uint256(ethUsdPrice));
    }
```

However there are no sequencers on L1. TH=he only option is to put a regular price feed on this place, but this will also revert since we are checking `startedAt` and this value represents the last price update (aka. heartbeat), which can be up to 24h.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L87-L96
```solidity
    function _checkSequencerFeed() private view {
        (, int256 answer, uint256 startedAt,,) = ARB_SEQ_FEED.latestRoundData();

        if (answer != 0) revert ChainlinkUsdOracle_SequencerDown();
        if (startedAt == 0) revert ChainlinkUsdOracle_InvalidRound();

        if (block.timestamp - startedAt <= SEQ_GRACE_PERIOD) revert ChainlinkUsdOracle_GracePeriodNotOver();
    }
```
Because of this TX checking the sequencer on L1s will revert.

## Impact
TX using the price feeds on L1s will revert.

## Code Snippet
```solidity
    function _checkSequencerFeed() private view {
        (, int256 answer, uint256 startedAt,,) = ARB_SEQ_FEED.latestRoundData();

        if (answer != 0) revert ChainlinkUsdOracle_SequencerDown();
        if (startedAt == 0) revert ChainlinkUsdOracle_InvalidRound();

        if (block.timestamp - startedAt <= SEQ_GRACE_PERIOD) revert ChainlinkUsdOracle_GracePeriodNotOver();
    }
```
## Tool used
Manual Review

## Recommendation
Add an `if` to verify we are on L2 and call the SEQ, else skip it.

```diff
-    constructor(...) Ownable() {
+    constructor(... , bool _isL2) Ownable() {
+        isL2 = _isL2;

    function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
-       _checkSequencerFeed();
+       if (isL2) _checkSequencerFeed();
```