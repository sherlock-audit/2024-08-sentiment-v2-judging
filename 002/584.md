Flat Tawny Haddock

Medium

# New depositors can loose their assets due to existing shares when totalAssets is 0 following a bad debt rebalance

## Summary
New depositors can loose their assets due to existing shares even when totalAssets is 0

## Vulnerability Detail
Having 0 totalAssets and non-zero shares is a possible scenario due to rebalacne
```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        
        ....
        //@auidt decreases totalDepositAssets while shares can be non-zero
        uint256 totalDepositAssets = pool.totalDepositAssets;
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
```

In such a case, if a new user deposits, it will not revert but instead mint shares 1:1 with the assets. But as soon as it is minted, the value of the user's share will decrease because of the already existing shares

```solidity
    function deposit(uint256 poolId, uint256 assets, address receiver) public returns (uint256 shares) {
        
        ....

        shares = _convertToShares(assets, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Down);
```

```solidity
    function _convertToShares(
        uint256 assets,
        uint256 totalAssets,
        uint256 totalShares,
        Math.Rounding rounding
    ) internal pure returns (uint256 shares) {
        if (totalAssets == 0) return assets;
        shares = assets.mulDiv(totalShares, totalAssets, rounding);
    }
```

Eg:
deposit shares = 100, deposit assets = 100, borrow assets = 100
borrow position becomes bad debt and rebalance bad debt is invoked
now deposit shares = 100, deposit assets = 0
new user calls deposit with 100 assets
they get 100 shares in return but share value is now 0.5 and they can withdraw only 50

This can occur if a large position undergoes a rebalance and the others manage to withdraw their assets right before the rebalance (superpool dominated pools can higher chances of such occurence) 

## Impact
Users can loose their assets when depositing to pools that have freshly undergone rebalanceBadDebt

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L275

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L547

## Tool used
Manual Review

## Recommendation
If totalShares is non-zero and totalAssets is zero, revert for deposits