Flat Tawny Haddock

Medium

# `maxDeposit` deviates from `ERC4626` spec

## Summary
`maxDeposit` deviates from `ERC4626` spec since depositing the returned amount can revert

## Vulnerability Detail
`maxDeposit` is supposed to strictly comply with the `ERC4626` spec. According to the [spec](https://eips.ethereum.org/EIPS/eip-4626)`MUST return the maximum amount of assets deposit would allow to be deposited for receiver and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted`

But calling the deposit function with the returned amount can revert due to multiple reasons

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L208-L210)
```solidity
    function maxDeposit(address) public view returns (uint256) {
        return _maxDeposit(totalAssets());
    }

    ...

    function _maxDeposit(uint256 _totalAssets) public view returns (uint256) {
        return superPoolCap > _totalAssets ? (superPoolCap - _totalAssets) : 0;
    }
```

1. Due to minted shares being 0 when the returned amount is dust amount
[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L258-L261)
```solidity
    function deposit(uint256 assets, address receiver) public nonReentrant returns (uint256 shares) {
        accrue();
        shares = _convertToShares(assets, lastTotalAssets, totalSupply(), Math.Rounding.Down);
        if (shares == 0) revert SuperPool_ZeroShareDeposit(address(this), assets);
```

Eg: share value has increased to greater than 1
totalAssets = 100 and supplyCap = 101
maxDeposit will return 1 but this will result in 0 shares being minted and hence cause revert

2. receiver being address 0 (ERC20._mint) will revert

## Impact
Failure to comply with the specification which is a mentioned necessity

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L208-L210

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L258-L261

## Tool used
Manual Review

## Recommendation
Either relax the strict compliance or also check that the receiver is not address(0) and also that the minted shares will be non-zero 