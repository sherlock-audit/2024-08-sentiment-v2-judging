Flat Tawny Haddock

Medium

# KinkedRateModel's `getInterestRate` rounds down favour of the borrower's

## Summary
KinkedRateModel's `getInterestRate` rounds down favour of the borrower's

## Vulnerability Detail
The interest rate else where is rounded up in favour of the protocol

Eg:
```solidity
    function getInterestAccrued(uint256 lastUpdated, uint256 totalBorrows, uint256) external view returns (uint256) {
        // [ROUND] rateFactor is rounded up, in favor of the protocol
```

But KinkedRateModel rounds down the utilisation which favors the borrowers instead

```solidity
    function getInterestRate(uint256 totalBorrows, uint256 totalAssets) public view returns (uint256) {
        uint256 util = (totalAssets == 0) ? 0 : totalBorrows.mulDiv(1e18, totalAssets, Math.Rounding.Up);


=>      if (util <= OPTIMAL_UTIL) return MIN_RATE_1 + SLOPE_1.mulDiv(util, OPTIMAL_UTIL, Math.Rounding.Down);
        else return MIN_RATE_2 + SLOPE_2.mulDiv((util - OPTIMAL_UTIL), MAX_EXCESS_UTIL, Math.Rounding.Down);
```


## Impact
Protocol can loose dust amount of interest

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/irm/KinkedRateModel.sol#L58-L59

## Tool used
Manual Review

## Recommendation
If not intended, round up