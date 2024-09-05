Tame Seafoam Peacock

Medium

# Unsafe ERC20 Token Transfer in SuperPoolFactory Contract

## Vulnerability Detail
The SuperPoolFactory contract contains an unsafe ERC20 token transfer operation. Specifically, in the deploySuperPool function, the contract uses the standard transfer method to send tokens to a burn address, without checking the return value or using a safe transfer method.

## Impact
This vulnerability could lead to silent failures in token transfers, potentially resulting in:

1. Tokens not being properly burned, leading to discrepancies in the expected token supply.
2. Incorrect accounting of burned shares, which could affect the overall integrity of the SuperPool system.
3. In extreme cases, this could be exploited by malicious token implementations to manipulate the state of the SuperPool.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L76

## Proof of Concept
Some ERC20 tokens (like USDT) do not revert on failure but instead return a boolean value. The current implementation doesn't check this return value. If the transfer fails silently, the function will continue executing as if it succeeded, potentially leaving the system in an inconsistent state.

## Tool used

Manual Review

## Recommendation
Replace the unsafe transfer with a safe transfer method. Since the contract already imports OpenZeppelin's SafeERC20 library, it should use the safeTransfer function.
``IERC20(superPool).safeTransfer(DEAD_ADDRESS, shares);``

### Additional Recommendations
1. Apply the same principle to other token operations in the contract, such as using `safeApprove`.

#### Note
The severity is considered medium because while it doesn't directly lead to fund loss, it could potentially be exploited or lead to unexpected behavior in the system.