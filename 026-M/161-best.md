Tricky Felt Lizard

Medium

# RedStone oracle is vulnerable because ```updatePrice``` is not called during the ```getEthValue``` function.

## Summary
Redstone oracle doesn't work as expected returning outdated or user selected prices leading to every asset using it return wrong ETH values.

## Vulnerability Detail
>[!NOTE]
> **All** off-chain mechanisms of Sentiment protocol in the scope of this audit are stated in this section of [README](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/README.md?plain=1#L53-L56)

As we can see in the ```RedstoneOracle``` contract the actual ```ethUsdPrice``` and ```assetUsdPrice``` are state variables which need to be updated every time the ```getValueInEth``` function be called so to calculate the real value of the asset in ETH. We can see the implementation here :
```solidity
function getValueInEth(address, uint256 amt) external view returns (uint256) {
        if (priceTimestamp < block.timestamp - STALE_PRICE_THRESHOLD) revert RedstoneCoreOracle_StalePrice(ASSET);

        // scale amt to 18 decimals
        if (ASSET_DECIMALS <= 18) amt = amt * 10 ** (18 - ASSET_DECIMALS);
        else amt = amt / 10 ** (ASSET_DECIMALS - 18);

        // [ROUND] price is rounded down
        return amt.mulDiv(assetUsdPrice, ethUsdPrice);
    }
```
However, the ```updatePrice``` function is not called from anywhere, not even from inside the ```getValueInEth``` function which should seem logical.

## Impact
Combined with the fact that the ```updatePrice``` function can be called by anyone "giving" the price 3 minutes of liveness, the impact/result of this vulnerability is someone to take advantage of a price which is not updated and get a wrong value of the asset in ETH, either lower or higher than the real one. For example, he can borrow with the wrong price and repay with the right price which is a bit higher, so return less amount that he took.


## Code Snippet
Here is the ```updatePrice``` of Redstone oracle : 
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
[Link to code](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/oracle/RedstoneOracle.sol#L48-L61)

## Tool used
Manual Review

## Recommendation
Consider calling ```updatePrice``` in the ```getEthValue``` function :
```diff
function getValueInEth(address, uint256 amt) external view returns (uint256) {
+       updatePrice();
        // ...
    }
```