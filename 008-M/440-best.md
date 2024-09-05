Special Coconut Cow

Medium

# Faulty Fee Validation in `SuperPool::requestFeeUpdate()` Function Leads to Update Lockout

## Summary
The `SuperPool::requestFeeUpdate()` function is responsible for proposing new `fee` updates in the `SuperPool` contract, has a validation issue. The function incorrectly validates the current state variable `fee` instead of the new `_fee` parameter. This flawed logic causes the function to revert when the current `fee` exceeds 1e18, regardless of the `_fee` value. As a result, if the `fee` is ever set to a value greater than 1e18, no further `fee` updates can be proposed, leading to potential disruptions in the contract’s operations.

## Vulnerability Detail
The `SuperPool::requestFeeUpdate()` is used to propose a new `fee` update for the `SuperPool`. the current implementation of the `requestFeeUpdate()` function only checks the state variable `fee` and not the new parameter `_fee`. This check only considers the current state variable `fee`, not the `_fee` parameter. This means if the state variable fee is greater than 1e18, the function will revert regardless of the value of `_fee`.
 ```solidity
    function requestFeeUpdate(uint256 _fee) external onlyOwner {
@>     if (fee > 1e18) revert SuperPool_FeeTooHigh();
        pendingFeeUpdate = PendingFeeUpdate({ fee: _fee, validAfter: block.timestamp + TIMELOCK_DURATION });
        emit SuperPoolFeeUpdateRequested(_fee);
    }
```
Since the `requestFeeUpdate()` function only considers the current state variable `fee`, once it’s set to a value greater than 1e18, no new updates can be proposed. This means the contract will never allow a fee update to be requested, potentially breaking functionality that depends on the ability to update the fee.

<details><summary><strong>POC</strong></summary>
Extended from <a href="https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/test/core/Superpool.t.sol#L8" target="_blank">SuperPool.t.sol</a>

```solidity
    function testCannot_Change_Fee() public {
        
        uint256 fee = 0.01 ether;

        SuperPool superpool =
            new SuperPool(address(pool), address(asset1), feeTo, fee, 1_000_000 ether, "test", "test");

        // Update the fee to greater than 1e18
        superpool.requestFeeUpdate(1e19);

        vm.warp(block.timestamp + superpool.TIMELOCK_DURATION() + 2);
        superpool.acceptFeeUpdate();

        // Reverts once it is set to a value greater than 1e18, and no new updates can be proposed
        vm.expectRevert(SuperPool.SuperPool_FeeTooHigh.selector);
        superpool.requestFeeUpdate(0.01 ether);
        
     }
```
Run the following command to execute the POC: `forge test --match-test testCannot_Change_Fee`
</details>


## Impact
The inability to update the `fee` due to the incorrect validation in `requestFeeUpdate()` could lead to a breakdown in the contract’s intended operations, making the contract non-functional or less adaptable to future needs.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L366-L370

## Tool used
Manual Review

## Recommendation
Correct the validation in the `requestFeeUpdate()` function to check the `_fee` parameter:
```diff
    function requestFeeUpdate(uint256 _fee) external onlyOwner {
--      if (fee > 1e18) revert SuperPool_FeeTooHigh();
++      if (_fee > 1e18) revert SuperPool_FeeTooHigh();
        pendingFeeUpdate = PendingFeeUpdate({ fee: _fee, validAfter: block.timestamp + TIMELOCK_DURATION });
        emit SuperPoolFeeUpdateRequested(_fee);
    }
```