Attractive Caramel Fox

Medium

# Superpool contract does not strictly follow EIP4626

## Summary
`Superpool` contract does not strictly follow EIP4626
## Vulnerability Detail
As mentioned in the README, the `Superpool` contract should strictly follow the EIP4626 standard. According to the EIP, these must be the parameters for the `Deposit` event:
>inputs:
    - name: sender
      indexed: true
      type: address
    - name: owner
      indexed: true
      type: address
    - name: assets
      indexed: false
      type: uint256
    - name: shares
      indexed: false
      type: uint256

However, if we take a look at the `Deposit` event in `Superpool`:
```solidity
event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
```
We can see that the first parameter is called `caller` while according to the EIP, it should be `sender`. Thus, the EIP is not strictly followed.
## Impact
`Superpool` contract does not strictly follow EIP4626
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L87
## Tool used

Manual Review

## Recommendation
Change the first parameter