Glamorous Blush Gecko

Medium

# Attacker can take advantage of high LTV tokens to create bad debt for the protocol

### Summary

If the deviation threshold for the collateral token > 100 - LTV, then it is possible for an attacker to borrow an amount worth more than the collateral leading to bad debt accumulation 

### Root Cause

If the deviation threshold for the collateral token > 100 - LTV, then it is possible for an attacker to borrow an amount worth more than the collateral leading to bad debt accumulation 

### Internal pre-conditions

Token has [LTV](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/RiskEngine.sol#L60) > 95

### External pre-conditions

price feed has a deviation > 100 - LTV

The price of the token drops by (100 - LTV) %

### Attack Path

Assume the token is FTM and has an LTV of 98

Assume the price feed deviation = 3% [here is an example of such a priceFeed FTM / ETH](https://etherscan.io/address/0x2DE7E4a9488488e0058B95854CC2f7955B35dC9b)

1. The initial price of 1 FTM = 1 USD, since it has an LTV of 98 a user can deposit 10000 FTM to borrow 9800 USDC
2. Attacker waits for the price to drop by 2.99%, at this point the actual price of 1 FTM = 0.9701 USD, BUT the oracle has not updated the price since the 3% deviation has not been crossed 
3. Now the attacker deposits 10000 FTM (worth 9701 USD) to borrow 9800 USDC, since he has borrowed an amount worth more than the collateral he has created bad debt for the protocol
4. The price feed updates to the new price
5. The owner liquidates bad debt, taking all the collateral leaving lenders at a huge loss

This is the simplest example, there are more complex variations to exaggerate the likelihood/impact because the protocol uses multiple price feeds and multiplies them together to get the price of an asset

### Impact

Bad debt accumulates in the protocol

Huge loss for lenders because they are not re-imbursed anything when the protocol accumulates bad debt

### PoC

_No response_

### Mitigation

_No response_