Small Daffodil Caribou

Medium

# Lack of Access Control on updateFromRegistry Function

Medium 

## Summary
The updateFromRegistry function allows anyone to update the pool and riskEngine state variables, which could lead to an attacker pointing these variables to malicious contracts.

## Vulnerability Details 
A malicious actor could invoke the updateFromRegistry function to replace the pool and riskEngine with their own contracts, potentially allowing them to manipulate liquidation logic or steal funds from users.

## Impact
Manipulation on liquidation logic or loss of funds from users

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskModule.sol#L61

## Tool used
Manual Review

## Recommendation
Restrict access to updateFromRegistry by adding an onlyOwner or similar modifier to ensure only authorised accounts can update these variables