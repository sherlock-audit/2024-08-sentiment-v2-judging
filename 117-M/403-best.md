Bright Pecan Hawk

Medium

# `SuperPool`s deposit, withdraw, redeem and mint functions are not incomplaince with ERC4626

## Summary
 `SuperPool`s deposit, withdraw, redeem and mint functions are not incomplaince with ERC4626

## Vulnerability Detail
As per the contest readme, `SuperPool.sol is strictly ERC4626 compliant`. The `deposit()`, withdraw(), redeem() and mint() functions of `SuperPool` contract is not incompliance with ERC4626.

For understanding, Lets check deposit() function which is used to deposit the asset into the superPool and it is implemented as:

```solidity
    function deposit(uint256 assets, address receiver) public nonReentrant returns (uint256 shares) {
        accrue();
        shares = _convertToShares(assets, lastTotalAssets, totalSupply(), Math.Rounding.Down);
        if (shares == 0) revert SuperPool_ZeroShareDeposit(address(this), assets);
        _deposit(receiver, assets, shares);
    }
```

The issue here is that, `deposit()` function is not incompliance with ERC4626 as ERC4626 [deposit](https://eips.ethereum.org/EIPS/eip-4626) specification states,

>> MUST revert if all of assets cannot be deposited (due to deposit limit being reached, slippage, the user not approving enough underlying tokens to the Vault contract, etc).

It means that, the `maxDeposit` limit is not checked in deposit function. deposit() will not revert if the asset maximum limit is reached and per readme the deposit function must be strictly incompliance with ERC4626.

It should be noted that, `maxDeposit()` function is implemented in `superPool` contract which can be checked [here](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L208-L210) but its not checked in deposit function.

Similarly, `withdraw()`, `redeem()` and `mint()` are also not incompliance with ERC4626. Below specification related to them is not complied in functions.

 mint
 > MUST revert if all of shares cannot be minted (due to deposit limit being reached, slippage, the user not approving enough underlying tokens to the Vault contract, etc).
 
 withdraw
 > MUST revert if all of assets cannot be withdrawn (due to withdrawal limit being reached, slippage, the owner not having enough shares, etc).
 
 redeem
 > MUST revert if all of shares cannot be redeemed (due to withdrawal limit being reached, slippage, the owner not having enough shares, etc).

ERC4626 link- https://eips.ethereum.org/EIPS/eip-4626

## Impact
Failure to comply with the ERC4626 deposit, withdraw, redeem and mint specification which is considered as strict compliance by protocol as these functions should not exceed max deposit.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L258-L263

## Tool used
Manual Review

## Recommendation
Ensure SuperPool contracts deposit, withdraw, redeem and mint function must be incompliance with ERC4626.

For example understanding,

 consider below changes for deposit():

```diff
+  Error SuperPoolExceededMaxDeposit(address receiver, uint256 assets, uint256 maxAssets);

    . . . some code . . .     
    
    function deposit(uint256 assets, address receiver) public nonReentrant returns (uint256 shares) {
+     uint256 maxAssets = maxDeposit(receiver);
+        if (assets > maxAssets) {
+            revert SuperPoolExceededMaxDeposit(receiver, assets, maxAssets);
+        }
        accrue();
        shares = _convertToShares(assets, lastTotalAssets, totalSupply(), Math.Rounding.Down);
        if (shares == 0) revert SuperPool_ZeroShareDeposit(address(this), assets);
        _deposit(receiver, assets, shares);
    }
```