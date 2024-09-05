Expert Nylon Leopard

Medium

# Denial of Service (DoS) Vulnerability in SuperPool Withdrawal Due to Precision Loss (shares=0) in Pool Share Calculations when we call withdraw in pool contract.

## Summary

The SuperPool contract contains a vulnerability that can cause a Denial of Service (DoS) for users attempting to withdraw their funds. Although the SuperPool may have enough liquidity, precision loss in pool share calculations can lead to failed withdrawals, preventing users from accessing their funds.

## Vulnerability Detail
When a user attempts to withdraw funds from the SuperPool, the `_withdrawFromPools` function loops through the various pools to gather the required assets. The function calls the `withdraw` function in each pool contract, which calculates the deposit shares to burn. Due to precision loss, the calculation may result in zero shares to burn, causing the withdrawal to revert. This issue occurs even when the pool has sufficient liquidity to cover the transaction, leading to a failed withdrawal despite the availability of funds.

```solidity
 
    function _withdraw(address receiver, address owner, uint256 assets, uint256 shares) internal {

@audit>> calll >>        _withdrawFromPools(assets);
    
    if (msg.sender != owner) ERC20._spendAllowance(owner, msg.sender,
```
```solidity

    function _withdrawFromPools(uint256 assets) internal {
        uint256 assetsInSuperpool = ASSET.balanceOf(address(this));

        if (assetsInSuperpool >= assets) return;
        else assets -= assetsInSuperpool;


// loop through  
 uint256 withdrawQueueLength = withdrawQueue.length;
        for (uint256 i; i < withdrawQueueLength; ++i) {


   @audit>> as long as amount is greater than 0 even if this is 1 wei >>    if (withdrawAmt > 0) {
           
                                                             try POOL.withdraw(poolId, withdrawAmt, address(this), address(this)) {

   @audit>> reduce asset for the next withdrawal>>                 assets -= withdrawAmt;
              
  } catch { }
            }

            if (assets == 0) return;
        }

```
The vulnerability arises because the `withdraw` function in the pool contract uses the following logic:


```solidity


    @audit>> if 1 wei or less enough shares = 0 >>       shares = _convertToShares(assets, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Up);
 
// check for rounding error since convertToShares
 
   @audit>> Revert >>  if (shares == 0) revert Pool_ZeroShareRedeem(poolId, assets);
```


NOTE -  OpenZeppelin  Math.sol round up only when the multiplication of the numerators are greater than 1 else 0 is still returned.

```solidity
  /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
  
 @AUDIT>>     if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {
    
                   result += 1;
        }
        return result;
    }
```

If the calculated `shares` is zero due to precision loss, the function reverts, causing the entire withdrawal process in the SuperPool to fail.



## Impact
The inability to withdraw from the SuperPool, even when sufficient liquidity exists, can cause significant disruption for users. This DoS vulnerability can prevent users from accessing their funds.  

**FLOW** 

 Super pool A has 3 pools 1, 2 and 3.

Liquidity in each pool

                                               Superpool holds asset -- 30e18

assets + interest

                                               Pool 1 -  18.573457857309736565e18

                                               Pool 2 - 1.426542142690263434e18

                                               Pool 3 - 10e18

Total available asset in the pool -  59.999999999999999999e18.

User calls to withdraw - 50e18 of their asset in superppool.


We loop through each  Process- 

                           1. assets -= assetsInSuperpool;

assets = 20e18.

                              2.  assets -= withdrawAmt;

assets =1.426542142690263435e18

                              3.  assets -= withdrawAmt;
 
assets = 1



```solidity
  if (withdrawAmt > 0) {

      try POOL.withdraw(poolId, withdrawAmt, address(this), address(this))
```

 we attempt to withdraw this 1 wei.



                            **### _Pool 3._** 

```solidity

 function withdraw(
        uint256 poolId,
        uint256 assets,
        address receiver,
        address owner
    ) public returns (uint256 shares) {
        PoolData storage pool = poolDataFor[poolId];

        // update state to accrue interest since the last time accrue() was called
        accrue(pool, poolId);

        shares = _convertToShares(assets, pool.totalDepositAssets, pool.totalDepositShares, Math.Rounding.Up);
        // check for rounding error since convertToShares rounds down
        if (shares == 0) revert Pool_ZeroShareRedeem(poolId, assets);
-------------------------------------------------------------------------------------------

```



                         pool.totalDepositAssets = 18.9e18 ,

                         pool.totalDepositShares = 18.2e18 ,

                         assets= 1 wei.

                         Convert to shares = (1 * 18.2 e18)/ 18.9 e18 =  0.96296296296296296296296296296296= 0.

                         OpenZeppelin  Math.sol will not round to 1 because the answer is not greater than 0. thus this will revert.



**Also note** an attacker can also play with the asset in the Superpool by depositing dust amounts to ensure that the amount in the pool remains 1 wei at a point when we make external calls and cause a reversion. This is possible because we use address this to check the amount in the Superpool contract. 

## Code Snippet


https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L569-L573

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L350-L352

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/dc44c9f1a4c3b10af99492eed84f83ed244203f6/contracts/utils/math/Math.sol#L139-L145

## Tool used

Manual Review

## Recommendation

To mitigate this issue, modify the catch block in the `_withdrawFromPools` function to check if the pool liquidity is greater than the amount to be collected. If so, collect the pool liquidity and transfer it to the user from the contract. This change ensures that even if precision loss occurs, the user can still withdraw the available liquidity. Here is the recommended modification:


```solidity

  // withdrawAmt cannot be greater than the underlying pool liquidity
            uint256 poolLiquidity = POOL.getLiquidityOf(poolId);
            if (poolLiquidity < withdrawAmt) withdrawAmt = poolLiquidity;

            if (withdrawAmt > 0) {
                try POOL.withdraw(poolId, withdrawAmt, address(this), address(this)) {
                    assets -= withdrawAmt;
                } catch {
++    if (poolLiquidity > withdrawAmt) {
++         withdrawAmt = poolLiquidity;
++    POOL.withdraw(poolId, withdrawAmt, address(this), address(this));
++    assets = 0;}

 }
            }
```
This adjustment will allow withdrawals to succeed even when precision loss leads to zero shares being calculated, thus preventing the DoS vulnerability.

--- 
