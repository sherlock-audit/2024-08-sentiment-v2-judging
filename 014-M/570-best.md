Flat Tawny Haddock

Medium

# `ChainlinkOracle` doesn't validate for minAnswer/maxAnswer

## Summary
`ChainlinkOracle` doesn't validate for minAnswer/maxAnswer

## Vulnerability Detail
Current implementation of `ChainlinkOracle` doesn't validate for the minAnswer/maxAnswer values
[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L114-L120)
```solidity
    function _getPriceWithSanityChecks(address asset) private view returns (uint256) {
        address feed = priceFeedFor[asset];
        (, int256 price,, uint256 updatedAt,) = IAggegregatorV3(feed).latestRoundData();
        if (price <= 0) revert ChainlinkUsdOracle_NonPositivePrice(asset);
        if (updatedAt < block.timestamp - stalePriceThresholdFor[feed]) revert ChainlinkUsdOracle_StalePrice(asset);
        return uint256(price);
    }
```

Chainlink still has feeds that uses the min/maxAnswer to limit the range of values and hence in case of a price crash, incorrect price will be used to value the assets allowing user's to exploit this incorrectness by depositing the overvalued asset and borrowing against it. Since the project plans to deploy in `Any EVM-compatbile network`, I am attaching the link to BNB/USD oracle which still uses min/maxAnswer and is one of the highest tvl tokens in BSC https://bscscan.com/address/0x137924d7c36816e0dcaf016eb617cc2c92c05782#readContract, similar check exists for ETH/USD

## Impact
In the even of a flash crash, user's lenders will loose their assets

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L114-L120

## Tool used
Manual Review

## Recommendation
If the price is outside the minPrice/maxPrice of the oracle, activate a breaker to reduce further losses