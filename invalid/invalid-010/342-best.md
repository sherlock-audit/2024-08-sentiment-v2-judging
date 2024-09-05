Huge Honeysuckle Rabbit

Medium

# Protocol does not full compliant with `EIP-6909`

## Summary
The core smart contracts in this protocol, `Pool.sol `does not include an implementation of `ERC-6909` as required by `EIP-6909` specifications.

## Vulnerability Detail
As per [EIP-6909 documentation](https://eips.ethereum.org/EIPS/eip-6909), smart accounts implementing this EIP must implement `EIP-6909`.

As in transfer and transferFrom functions the function must return on these condition but the protocol implementation does not handle this scenario.

---
**transfer**

MUST revert when the caller’s balance for the token id is insufficient.

**transferFrom**

MUST revert when the caller is neither the sender nor an operator for the sender and the caller’s allowance for the token id for the sender is insufficient.

MUST revert when the sender’s balance for the token id is insufficient.

---

## Impact
Medium. The protocol is not fully compliant with EIP-6909, which may lead to issues with interoperability and integration with other smart contracts and systems expecting ERC-6909 compliance.

## Tool used
Manual Review

## Recommendation
To ensure full compliance with EIP-6909, implement ERC-6909