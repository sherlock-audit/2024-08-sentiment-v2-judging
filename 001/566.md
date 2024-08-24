Flat Tawny Haddock

Medium

# `maxMint` deviates from `ERC4626` spec

## Summary
`maxMint` deviates from `ERC4626` spec since minting the returned amount can revert

## Vulnerability Detail
`maxMint` is supposed to strictly comply with the `ERC4626` spec. According to the [spec](https://eips.ethereum.org/EIPS/eip-4626)`MUST return the maximum amount of shares mint would allow to be deposited to receiver and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary).`

But calling the mint function with the returned amount will revert if the receiver is address 0 since ERC20._mint will revert 

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L213-L217)
```solidity
    function maxMint(address) public view returns (uint256) {
        (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
        return
            _convertToShares(_maxDeposit(newTotalAssets), newTotalAssets, totalSupply() + feeShares, Math.Rounding.Down);
    }
```

## Impact
Failure to comply with the specification which is a mentioned necessity

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L213-L217

## Tool used
Manual Review

## Recommendation
Either relax the strict compliance or also check that the receiver is not address(0)