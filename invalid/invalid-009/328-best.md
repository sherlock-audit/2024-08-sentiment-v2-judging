Bouncy Banana Aardvark

High

# Owner Can Set Fee Rate Exceeding 100%, Causing Share Inflation

### Summary

The missing proper validation in the fee-setting mechanism of the `SuperPool` contract will cause a significant financial loss for depositors as the `SuperPool` owner can set the interest fee rate to more than 100%.

### Root Cause

In `SuperPool:157`, there is an incorrect check of fee setting on the constructor.
https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/SuperPool.sol#L157
In `SuperPool:367`, there is an incorrect check of fee setting on the `requestFeeUpdate` function.
https://github.com/sentimentxyz/protocol-v2/blob/04bf15565165396608cc0aedacf05897235518fd/src/SuperPool.sol#L367

### Internal pre-conditions

1. Admin needs to deploy `SuperPoolFactory`.

### External pre-conditions

No external pre-conditions are required.

### Attack Path

1. An attacker creates a `SuperPool` with a 1% fee.
2. The depositors deposit into the `SuperPool`.
3. The attacker sets the fee to greater than 100% in the constructor.
4. The `SuperPool` accrues interest, causing new shares to be minted for the fee recipient based on this inflated fee.
5. A few minutes later, the attacker withdraws most funds of the `SuperPool`.

### Impact

- The depositors suffer significant financial losses as the inflated share price reduces the number of shares they receive for their deposits.
- The `SuperPool` becomes locked into an incorrect fee structure, which damages trust in the protocol and its ability to manage fees correctly.

### PoC

```solidity
    function test() public {
        superPool = SuperPool(
            superPoolFactory.deploySuperPool(
                poolOwner, address(asset1), feeTo, 2e18, 1_000_000 ether, initialDepositAmt, "test", "test"
            )
        );
        assertEq(superPool.fee(), 2e18);    // fee set to 200%

        vm.expectRevert(SuperPool_FeeTooHigh.selector);
        vm.prank(poolOwner);
        superPool.requestFeeUpdate(1e17);    // Attempt to lower the fee to 10%
    }
```

### Mitigation

To mitigate this issue, the fee validation logic should be revised.
```solidity
    constructor(
        address pool_,
        address asset_,
        address feeRecipient_,
        uint256 fee_,
        uint256 superPoolCap_,
        string memory name_,
        string memory symbol_
    ) Ownable() ERC20(name_, symbol_) {
        ...
        if (fee_ > 1e18) revert SuperPool_FeeTooHigh();
        ...
    }

    function requestFeeUpdate(uint256 _fee) external onlyOwner {
        if (_fee > 1e18) revert SuperPool_FeeTooHigh();
        ...
    }
```