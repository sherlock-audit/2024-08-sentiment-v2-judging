Main Tiger Opossum

High

# Protocol does not account for fee on transfer tokens (USDT)

## Summary

When transferring USDT a fee is paid and the amount received is less than the amount sent. Because of that the protocol will be loosing funds or having some parts of it inaccessible as it will believe that it has received more funds than it actually has.

## Vulnerability Detail

One of the instances of this problem is in `SuperPool::_deposit`:

```solidity
    /// @dev Internal function to process ERC4626 deposits and mints
    /// @param receiver The address to receive the shares
    /// @param assets The amount of assets to deposit
    /// @param shares The amount of shares to mint, should be equivalent to assets

    function _deposit(address receiver, uint256 assets, uint256 shares) internal {
        // assume that lastTotalAssets are up to date
        if (lastTotalAssets + assets > superPoolCap) revert SuperPool_SuperPoolCapReached();
        // Need to transfer before minting or ERC777s could reenter.
@>      ASSET.safeTransferFrom(msg.sender, address(this), assets);
        ERC20._mint(receiver, shares);
@>      _supplyToPools(assets);
        lastTotalAssets += assets;
        emit Deposit(msg.sender, receiver, assets, shares);
    }
```

The amount received will not be the same as the amount specified in `assets` meaning that the contract will supply the pools with more funds than it has received which will lead to a constant loss of funds.

Another place where this issue arises is in `SuperPoolFactory::deploySuperPool`

```solidity
    /// @notice Deploy a new SuperPool
    /// @param owner Owner of the SuperPool, and tasked with allocation and adjusting Pool Caps
    /// @param asset The asset to be deposited in the SuperPool
    /// @param feeRecipient The address to initially receive the fee
    /// @param fee The fee, out of 1e18, taken from interest earned
    /// @param superPoolCap The maximum amount of assets that can be deposited in the SuperPool
    /// @param initialDepositAmt Initial amount of assets, deposited into the superpool and burned
    /// @param name The name of the SuperPool
    /// @param symbol The symbol of the SuperPool
    function deploySuperPool(
        address owner,
        address asset,
        address feeRecipient,
        uint256 fee,
        uint256 superPoolCap,
        uint256 initialDepositAmt,
        string calldata name,
        string calldata symbol
    ) external returns (address) {
        if (fee != 0 && feeRecipient == address(0)) revert SuperPoolFactory_ZeroFeeRecipient();
        SuperPool superPool = new SuperPool(POOL, asset, feeRecipient, fee, superPoolCap, name, symbol);
        superPool.transferOwnership(owner);
        isDeployerFor[address(superPool)] = true;

        // burn initial deposit
@>      IERC20(asset).safeTransferFrom(msg.sender, address(this), initialDepositAmt); // assume approval
        IERC20(asset).approve(address(superPool), initialDepositAmt);
 @>     uint256 shares = superPool.deposit(initialDepositAmt, address(this));
        if (shares < MIN_BURNED_SHARES) revert SuperPoolFactory_TooFewInitialShares(shares);
        IERC20(superPool).transfer(DEAD_ADDRESS, shares);

        emit SuperPoolDeployed(owner, address(superPool), asset, name, symbol);
        return address(superPool);
    }
```
The contract will receive less funds than specified and as a result the second transfer to the pool will most definitely revert, meaning that it is impossible to create a super pool with USDT as the asset.

## Impact

Loss of funds and access to some functionalities.

## Code Snippet

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L72-L74

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L497-L506

## Tool used

Manual Review

## Recommendation

Use the balance of the contract before and after the transfer to handle the fee on transfer tokens