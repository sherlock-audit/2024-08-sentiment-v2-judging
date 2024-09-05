Flat Tawny Haddock

Medium

# Division before multiplication causes precision losses for asset valuation

## Summary
Division before multiplication causes precision losses for asset valuation

## Vulnerability Detail
In `ChainlinkUsdOracle` and `RedstoneOracle`, when adjusting for the decimals, the division to adjust for the token's decimals are done first
```solidity
    function getValueInEth(address asset, uint256 amt) external view returns (uint256) {
        
        ....

        if (decimals <= 18) return (amt * 10 ** (18 - decimals)).mulDiv(uint256(assetUsdPrice), uint256(ethUsdPrice));
=>      else return (amt / (10 ** decimals - 18)).mulDiv(uint256(assetUsdPrice), uint256(ethUsdPrice));
    }
```

This will clear out the values in the decimal places after 18 leading to lower precision in the computed value

## Impact
Lower precision on the value obtained for valuation

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/oracle/ChainlinkUsdOracle.sol#L86

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/oracle/RedstoneOracle.sol#L63-L68

## Tool used
Manual Review

## Recommendation
Perform both division at the last combined ie. (amt).mulDiv(uint256(assetUsdPrice), (uint256(ethUsdPrice) * (10 ** decimals - 18)))