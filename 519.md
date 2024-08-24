Merry Butter Dog

High

# Security considerations of ERC6909 are not complied, thus an operator can steal funds

## Summary

The protocol's pools are strictly compilant with ERC6909, which introduces the `operator` model. An operator is an account which is granted permission to transfer assets on behalf of the `owner`. 

Also according to [ERC6909 specification security considerations](https://eips.ethereum.org/EIPS/eip-6909#security-considerations): 

1. ```The first consideration is consistent with all delegated permission models. Any account with operator permissions may transfer any amount of any token id on behalf of the owner until the operator permission is revoked```
2. ```The second consideration is unique to systems with both delegated permission models. In accordance with the `transferFrom`In accordance with the transferFrom method method, spenders with operator permission are not subject to allowance restrictions, spenders with infinite approvals SHOULD NOT have their allowance deducted on delegated transfers``` 

However these security considerations are not taken of concern. This allows an operator to transfer all the available token balance of the `owner` to himself. And since for this contest, it's confirmed that only the owners of pools, super pools and position manager are considered as TRUSTED, the operator role is not an owner i consider this scenario likely to happen.

## Vulnerability Detail

The problem lies in the `Pool::withdraw()` function: 

```javascript
function withdraw(uint256 poolId, uint256 assets, address receiver, address owner) public returns (uint256 shares) {
        ...
        if (msg.sender != owner && !isOperator[owner][msg.sender]) {
            uint256 allowed = allowance[owner][msg.sender][poolId];
            if (allowed != type(uint256).max) allowance[owner][msg.sender][poolId] = allowed - shares;
        }
        ...

@>      IERC20(pool.asset).safeTransfer(receiver, assets);
```

As can be seen the caller can specify any address as the receiver.

## Impact

- Impact: High, the entire balance of the owner can be drained
- Likelihood: Medium, because:
  - 1. an owner can revoke the operator role anytime, so an operator can frontrun such transactions to prevent, but some chains have private mempools, so this only partially mitigates the likelihood
  - 2. since by spec, the operator is granted infinite approval, the attacker needs only one successful tx to steal the tokens
- Overall: High/Medium -> High

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L371

## Tool used

Manual Review

## Recommendation

Restrict the operator to be able to transfer to himself: 

```javascript
if (receiver == msg.sender && msg.sender != owner) revert("Operator cannot transfer to themselves");
```

But since he can choose any address, this exploit is not fully mitigated, consider if having an operator for the pools is in need.