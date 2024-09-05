Zesty Rainbow Wombat

High

# CREATE2 address collision against a position allows the position owner to drain all the lending pools.

### Summary

CREATE2 address collision against a position allows the position owner to drain all the collaterals from the position and get away with all the funds he loaned. 

### Root Cause

A user Bob can create 1) a large number of positions that he owns by providing different salts, 2) a long list of smart contract addresses that he can control. Once find the collision, Bob can drain the position since he is in control of the position address to transfer funds away. 

[https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L268-L286](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/PositionManager.sol#L268-L286)

### Internal pre-conditions

None

### External pre-conditions

Find the collision described above

### Attack Path

Once finding a collision address X, Bob can deploy a contract on X using create2, which sets the allowances for various assets for another attacker wallet address, and then self-destruct the contract.

Bob can then deploy the regular position contract on X, deposit a huge number of collateral and borrow a huge number of debt. Bob can then use the attacker wallet to transfer all the collateral away, along with the loan, Bob effectively can drain all the lending pools in the protocol. 

### Impact

The attacker can drain all the lending pools.

### PoC

This attack is similar to the following two findings, which have been rewarded by Sherlock. 

[1 ]Address colission atack, Issue 4: https://github.com/sherlock-audit/2024-01-napier-judging/issues/111 
[2] Issue 5: https://github.com/sherlock-audit/2023-12-arcadia-judging/issues/59

The feasibility of finding the collision that the script to launch the attack has been discussed in these two references  too. 

### Mitigation

Limit the number of positions that a user can owe. In this way, it is unlikely to have a collision. 