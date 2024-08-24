Flat Tawny Haddock

Medium

# Incorrect decimal adjustment in `ChainlinkUsdOracle`

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