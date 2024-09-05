Clever Lead Dog

Medium

# Incorrect implementation allows the `SuperPool`'s `fee` variable to be set over the spec

## Summary

According to the sponsor's [comment](https://discord.com/channels/812037309376495636/1273304663277572096/1273643929954291786):
> SuperPool depositors should trust the owner when it comens to param changes and configs **but if there's a mechanism flaw it should be taken under consideration as an issue**

This report presents an issue regarding an incorrect implementation that is unaligned with the protocol's spec. More specifically, the vulnerability allows a `SuperPool` owner to mistakenly set the `fee` parameter to be greater than `1e18`.

With the vulnerability, all accrued interests and depositors' principal assets can be stolen (by mistakes). Or, the huge enough `fee` can block (DoS) the `SuperPool`'s functions (Please refer to the `coded PoC`). 

***Although the impact may be high or even critical, since the sponsor assumes the `SuperPool` owners are trustworthy, I raised this issue as only medium severity.***

## Vulnerability Detail

As per the protocol's spec, the `fee` parameter [cannot exceed `1e18`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L140) (`@1` in the snippet below):
> **The fee, out of 1e18, taken from interest earned**

I noticed that the [`SuperPool::constructor()`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L157) (`@2`) and [`SuperPool::requestFeeUpdate()`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L367) (`@3`) were implemented incorrectly. Specifically, both functions mistakenly validate the state variable, `fee`, instead of the inputted parameter `fee_`.

This allows the inputted `fee_` whose value > `1e18` to pass the checks and be assigned to the state variable `fee`.

```solidity
    /// @notice This function should only be called by the SuperPool Factory
    /// @param pool_ The address of the singelton pool contract
    /// @param asset_ The asset of the superpool, which should match all underling pools
    /// @param feeRecipient_ The address to initially receive the fee

@1  /// @param fee_ The fee, out of 1e18, taken from interest earned
        //@audit @1 -- As per the protocol's spec, the 'fee' parameter cannot exceed 1e18.

    /// @param superPoolCap_ The maximum amount of assets that can be deposited in the SuperPool
    /// @param name_ The name of the SuperPool
    /// @param symbol_ The symbol of the SuperPool
    constructor(
        address pool_,
        address asset_,
        address feeRecipient_,
        uint256 fee_,
        uint256 superPoolCap_,
        string memory name_,
        string memory symbol_
    ) Ownable() ERC20(name_, symbol_) {
        POOL = Pool(pool_);
        ASSET = IERC20(asset_);
        DECIMALS = _tryGetAssetDecimals(ASSET);

        //@audit @2 -- An incorrect validation on the state variable, fee, instead of the inputted parameter fee_.
@2      if (fee > 1e18) revert SuperPool_FeeTooHigh();

        fee = fee_;
        feeRecipient = feeRecipient_;
        superPoolCap = superPoolCap_;
    }

    function requestFeeUpdate(uint256 _fee) external onlyOwner {
        //@audit @3 -- An incorrect validation on the state variable, fee, instead of the inputted parameter _fee.
@3      if (fee > 1e18) revert SuperPool_FeeTooHigh();

        pendingFeeUpdate = PendingFeeUpdate({ fee: _fee, validAfter: block.timestamp + TIMELOCK_DURATION });
        emit SuperPoolFeeUpdateRequested(_fee);
    }
```
- `@1`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L140
- `@2`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L157
- `@3`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L367

Once the `fee` > `1e18` is set, the [`fee` will be used to compute the `feeAssets`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L658) (`@4`) for the `SuperPool` owner in the `SuperPool::simulateAccrue()`.

The following are the [impacts]( https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L660) (`@5`) of the vulnerability:
1. All accrued interests and depositors' principal assets can be stolen (by mistakes).
2. The huge enough `fee` can block (DoS) the `SuperPool`'s functions (Please refer to the `coded PoC`).

To elaborate on the first impact, the resulting unexpectedly large `feeAssets` will finally lead to the minting of the (fake) large `feeShares`, diluting all depositors' `shares` and gradually transferring the depositors' assets to the fee recipient (`SuperPool` owner).

To elaborate on the second impact, the gigantic `feeAssets` variable will be larger than the `newTotalAssets` variable (see [`@5`]( https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L660)). As a result, whenever the `SuperPool`'s functions invoke the `simulateAccrue()`, the transaction will revert (in [`@5`]( https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L660)) due to an arithmetic underflow error.

```solidity
    function simulateAccrue() internal view returns (uint256, uint256) {
        uint256 newTotalAssets = totalAssets();
        uint256 interestAccrued = (newTotalAssets > lastTotalAssets) ? newTotalAssets - lastTotalAssets : 0;
        if (interestAccrued == 0 || fee == 0) return (0, newTotalAssets);

        //@audit @4 -- The 'fee' is used to compute the feeAssets for the SuperPool owner.
@4      uint256 feeAssets = interestAccrued.mulDiv(fee, WAD);

        //@audit @5 -- With the 'fee' > 1e18,
        //                 1. All accrued interests and depositors' principal assets can be stolen (by mistakes).
        //                 2. The huge enough fee can block (DoS) the SuperPool's functions (Refer to the coded PoC).
        //
        // newTotalAssets already includes feeAssets
@5      uint256 feeShares = _convertToShares(feeAssets, newTotalAssets - feeAssets, totalSupply(), Math.Rounding.Down);

        return (feeShares, newTotalAssets);
    }
```
- `@4`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L658
- `@5`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L660

## Proof of Concept

This section provides two coded PoCs. 

Place the `testPoCSetSuperPoolFeeOver1e18()` and `testPoCSetSuperPoolFeeOver1e18_DoS()` in the `./protocol-v2/test/core/Superpool.t.sol` file.

There are two test functions. Execute the commands: 
1. `forge t --nmt "Fork|invariant" --mt testPoCSetSuperPoolFeeOver1e18`
2. `forge t --nmt "Fork|invariant" --mt testPoCSetSuperPoolFeeOver1e18_DoS`

`PoC #1` shows that the `SuperPool` owner can mistakenly set the `fee` over `1e18` (100%), i.e., to 50000000%.

`PoC #2` shows that the `fee` can be set to reach the maximum limit of the `uint256` (i.e., `type(uint256).max`), causing the `SuperPool`'s functions to be DoS'ed. Consequently, all deposited assets will get stuck in the pool.

```solidity
function testPoCSetSuperPoolFeeOver1e18() public { // PoC #1
    // Before the fee update (1%)
    assertEq(superPool.fee(), 0.01 ether); // 1%

    // Request for the fee update (1% -> 50000000%)
    vm.startPrank(poolOwner);
    superPool.requestFeeUpdate(500000 ether); // 50000000%

    vm.warp(24 hours + 1 seconds);
    superPool.acceptFeeUpdate();
    vm.stopPrank();

    // After the fee update (50000000%)
    // Incorrect implementation, not aligned with the spec
    assertEq(superPool.fee(), 500000 ether); // 50000000%
}

function testPoCSetSuperPoolFeeOver1e18_DoS() public { // PoC #2
    // --- Setup ---
    vm.prank(poolOwner);
    superPool.addPool(linearRatePool, 1 ether);

    // --- User deposits 1 ether of asset1 to the SuperPool ---
    vm.startPrank(user);
    asset1.mint(user, 1 ether);
    asset1.approve(address(superPool), 1 ether);

    uint256 expectedShares = superPool.previewDeposit(1 ether);
    uint256 shares = superPool.deposit(1 ether, user);
    assertEq(shares, expectedShares);

    assertEq(asset1.balanceOf(address(pool)), 1 ether);

    // --- User redeems 10% of deposited amount (0.1 ether) ---
    // Assets before withdrawal: 1 ether
    assertEq(superPool.convertToAssets(superPool.balanceOf(user)), 1 ether);

    superPool.redeem(shares / 10, user, user);
    vm.stopPrank();

    // Assets after withdrawal: 0.9 ether
    assertEq(superPool.convertToAssets(superPool.balanceOf(user)), 0.9 ether);

    // --- SuperPool owner requests for the fee update (1% -> MAX%) ---
    // Before the fee update (1%)
    assertEq(superPool.fee(), 0.01 ether); // 1%

    vm.startPrank(poolOwner);
    superPool.requestFeeUpdate(type(uint256).max); // MAX%

    vm.warp(24 hours + 1 seconds);
    superPool.acceptFeeUpdate();

    // After the fee update (MAX%)
    // Incorrect implementation, not aligned with the spec
    assertEq(superPool.fee(), type(uint256).max); // MAX%

    // --- Donate 1 wei to trigger the DoS ---
    asset1.mint(poolOwner, 1 wei);
    asset1.transfer(address(superPool), 1 wei);
    vm.stopPrank();

    // --- User tries to redeem another 10% of the deposited amount (0.1 ether) ---
    // Remaining deposited amount == 0.9 ether
    vm.startPrank(user);
    vm.expectRevert(); // Tx will revert with "Arithmetic Underflow error"
    superPool.redeem(shares / 10, user, user);
}
```

## Impact

**Although the impact may be high or even critical, since the sponsor assumes the `SuperPool` owners are trustworthy, I raised this issue as only medium severity.**

The following are the [impacts]( https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L660) (`@5`) of the vulnerability:
1. All accrued interests and depositors' principal assets can be stolen (by mistakes).
2. The huge enough `fee` can block (DoS) the `SuperPool`'s functions (Please refer to the `coded PoC`).

## Code Snippet

- `@1`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L140

- `@2`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L157

- `@3`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L367

- `@4`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L658

- `@5`: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/SuperPool.sol#L660

## Tool used

Manual Review

## Recommendation

Correct the vulnerable validations by checking the inputted `fee_` instead, like the snippet below.

```diff
    constructor(
        address pool_,
        address asset_,
        address feeRecipient_,
        uint256 fee_,
        uint256 superPoolCap_,
        string memory name_,
        string memory symbol_
    ) Ownable() ERC20(name_, symbol_) {
        POOL = Pool(pool_);
        ASSET = IERC20(asset_);
        DECIMALS = _tryGetAssetDecimals(ASSET);

-       if (fee > 1e18) revert SuperPool_FeeTooHigh();
+       if (fee_ > 1e18) revert SuperPool_FeeTooHigh();
        fee = fee_;
        feeRecipient = feeRecipient_;
        superPoolCap = superPoolCap_;
    }

    function requestFeeUpdate(uint256 _fee) external onlyOwner {
-       if (fee > 1e18) revert SuperPool_FeeTooHigh();
+       if (_fee > 1e18) revert SuperPool_FeeTooHigh();
        pendingFeeUpdate = PendingFeeUpdate({ fee: _fee, validAfter: block.timestamp + TIMELOCK_DURATION });
        emit SuperPoolFeeUpdateRequested(_fee);
    }
```