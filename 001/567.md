Flat Tawny Haddock

Medium

# `maxWithdraw` deviates from `ERC4626` spec

## Summary
`maxWithdraw` deviates from `ERC4626` spec since it is not possible to withdraw the returned amount

## Vulnerability Detail
`maxWithdraw` is supposed to strictly comply with the `ERC4626` spec. According to the [spec](https://eips.ethereum.org/EIPS/eip-4626)`MUST return the maximum amount of assets that could be transferred from owner through withdraw and not cause a revert, which MUST NOT be higher than the actual maximum that would be accepted (it should underestimate if necessary).`

But calling the withdraw function with the returned amount will revert due to incorrect handling of the pool liquidity

[link](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L474-L485)
```solidity
    function _maxWithdraw(address _owner, uint256 _totalAssets, uint256 _totalShares) internal view returns (uint256) {
        uint256 totalLiquidity; // max assets that can be withdrawn based on superpool and underlying pool liquidity
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            totalLiquidity += POOL.getLiquidityOf(depositQueue[i]);
        }
        totalLiquidity += ASSET.balanceOf(address(this)); // unallocated assets in the superpool


        // return the minimum of totalLiquidity and _owner balance
        uint256 userAssets = _convertToAssets(ERC20.balanceOf(_owner), _totalAssets, _totalShares, Math.Rounding.Down);
        return totalLiquidity > userAssets ? userAssets : totalLiquidity;
    }
```

In `_maxWithdraw`, the entire liquidity of the pool is assumed to be withdrawable by the Superpool but this is false as the Superpool is limited to its share

Eg:
superpool has a single user for ease and the maxWithdraw for that user is being calculated

poolA total value = 100, superpool value = 50 and liquidity/withdrawable value = 100
poolB total value = 150, superpool value = 150 and liquidity/withdrawable value = 100

Now maxWithdraw will return 200 as totalLiquidity(withdrawable value) = (100 + 100)==200 and user value = (50 + 150)== 200

but when withdrawing, only 50 from the first pool can be withdrawn since Superpool only owns 50 value. Hence total withdrawable will be 150 and this will cause revert

## Impact
Failure to comply with the specification which is a mentioned necessity

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/25a0c8aeaddec273c5318540059165696591ecfb/protocol-v2/src/SuperPool.sol#L474-L485

## Tool used
Manual Review

## Recommendation
Instead of totalLiquidity, compute the totalWithdrawable amount which factors in the Superpool balance as done in the actual `_withdrawFromPools` function 