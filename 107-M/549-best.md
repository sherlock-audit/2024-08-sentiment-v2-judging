Merry Mercurial Osprey

Medium

# Inflation/donation attack isn't solved properly and it can cause DoS attacks due to wrong mitigation

## Summary
Inflation/Donation is a well-known attack vector in ERC-4626. In the Zach's report, https://github.com/sentimentxyz/protocol-v2/issues/133, this inflation attack problem is found and it's marked as fixed in mitigation. The problem arise due to wrong prevention against this attack. Inflation attack is not exist anymore but now it cause DoS.

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L322C1-L324C1

## Vulnerability Detail and Code Snippets
Inflation attacks can be occur in ERC-4626 Vault implementations in many different scenarios. Most known solution for this attack is applying virtual offset to supply in `_convertToShares()`. If this problem isn't solved it can cause loss of funds. In the previous audits, this problem is found and marked as fixed.

In the previous audit reports, Zach's suggestion was applying virtual offset to shares while execution of `_convertToShares()`. Please see the report and mitigation:
Report: https://github.com/sentimentxyz/protocol-v2/issues/133
Mitigation: https://github.com/sentimentxyz/protocol-v2/pull/141/commits/b61735bc54f64754c31437167cc6e9a2e56d8874

Zach's recommendation is not applied.
In the mitigation, inflation attack problem is solved with following line:

```solidity
    function deposit(uint256 poolId, uint256 assets, address receiver) public returns (uint256 shares) {
        PoolData storage pool = poolDataFor[poolId];

        if (pool.isPaused) revert Pool_PoolPaused(poolId);

        // update state to accrue interest since the last time accrue() was called
        accrue(pool, poolId);

        // Need to transfer before or ERC777s could reenter, or bypass the pool cap
        IERC20(pool.asset).safeTransferFrom(msg.sender, address(this), assets);

        if (pool.totalDepositAssets + assets > pool.poolCap) revert Pool_PoolCapExceeded(poolId);

        shares = _convertToShares(assets, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Down);
&>      if (shares == 0) revert Pool_ZeroSharesDeposit(poolId, assets);

        pool.totalDepositAssets += assets;
        pool.totalDepositShares += shares;

        _mint(receiver, poolId, shares);

        emit Deposit(msg.sender, receiver, assets, shares);
    }
```

It basicly prevents this attack vector with if statement. If the shares calculated for the corresponding user is zero then it reverts the whole deposit execution. It actually solves the inflation attack problem because now minting zero shares is not possible in this scenario. But this time, it makes the contract open to DoS attacks due to unproper mitigation.

## PoC

Idea is exactly same as inflation attack:

1) Pool is created
2) Attacker deposits 1 assets and got 1 shares from pool.
3) Alice try to deposit 100 assets
4) Attacker donate 100 assets with frontrunning against Alice's transaction
5) Now equation is 

$$
(Alice Deposit * Total Shares) / (Total Assets) =  (100 * 1) / (100+1) = 0
$$

5) Alice's transaction is reverted because shares will be 0 after calculation.

## Impact
DoS

## Tool used

Manual Review

## Recommendation

Applying Zach's recommendation and removing the if statement will solve the problem.

```solidity
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
    return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
}
```