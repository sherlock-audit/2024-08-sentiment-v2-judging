Flat Tawny Haddock

Medium

# `feeRecipeint` lacks setter function

## Summary
`feeRecipeint` lacks setter function

## Vulnerability Detail
The `feeRecipient` variable of Pool.sol is intended to be updated but lacks a setter function and hence cannot be updated

## Impact
`feeRecipient` cannot be updated

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L50

## Tool used
Manual Review

## Recommendation
Add a setter function