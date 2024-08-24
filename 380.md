Flat Navy Bee

Medium

# No slippage check in superpool ERC4626 functions

## Summary

Users may send more than they want when `mint` new shares in superpools, and users may receive less than they want when `redeem` shares in superpools due to no slippage check.

## Vulnerability Detail

In superpool, users can specify `shares` when deposit/withdraw:

```solidity
    function mint(uint256 shares, address receiver) public nonReentrant returns (uint256 assets) {
        accrue();
        assets = _convertToAssets(shares, lastTotalAssets, totalSupply(), Math.Rounding.Up);
        if (assets == 0) revert SuperPool_ZeroAssetMint(address(this), shares);
        _deposit(receiver, assets, shares);
    }
```
```solidity
    function redeem(uint256 shares, address receiver, address owner) public nonReentrant returns (uint256 assets) {
        accrue();
        assets = _convertToAssets(shares, lastTotalAssets, totalSupply(), Math.Rounding.Down);
        if (assets == 0) revert SuperPool_ZeroAssetRedeem(address(this), shares);
        _withdraw(receiver, owner, assets, shares);
    }
```
This leads to the user potentially accepting a worse share price for the mint than they expected.

## Impact

Whales that occupy most shares of the pool can grief other whales(when they try to enter the pool with `mint`) by simply send some asset tokens to superpool(this will inflate asset-share ratio).

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L269
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L293

## Tool used

Manual Review

## Recommendation

In function `mint()`, users should be able to specify a "maxAssetAmount" to send.
In function `redeem()`, users should be able to specify a "minAssetAmount" to receive.