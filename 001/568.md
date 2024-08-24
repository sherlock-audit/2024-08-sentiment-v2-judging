Flat Tawny Haddock

Medium

# `maxRedeem` deviates from `ERC4626` spec

## Summary
`maxRedeem` deviates from `ERC4626` spec since it is not possible to withdraw the returned amount

## Vulnerability Detail
`maxRedeem` is supposed to strictly comply with the `ERC4626` spec. According to the [spec](https://eips.ethereum.org/EIPS/eip-4626)`MUST return the maximum amount of shares that could be transferred from owner through redeem and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary).`

But calling the redeem function with the returned amount will revert due to maxRedeem relying on `_maxWithdraw` which returns an incorrect amount explained in a seperate issue (ie. maxWithdraw will return more assets than what is actually withdrawable) 

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L225-L232)
```solidity
    function maxRedeem(address owner) public view returns (uint256) {
        (uint256 feeShares, uint256 newTotalAssets) = simulateAccrue();
        uint256 newTotalShares = totalSupply() + feeShares;
        return _convertToShares(
            _maxWithdraw(owner, newTotalAssets, newTotalShares), newTotalAssets, newTotalShares, Math.Rounding.Down
        );
    }
```

## Impact
Failure to comply with the specification which is a mentioned necessity

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L225-L232

## Tool used
Manual Review

## Recommendation
Correct the `maxWithdraw` function