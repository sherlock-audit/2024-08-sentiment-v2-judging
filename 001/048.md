Massive Slate Dalmatian

Medium

# Super pool uses `ERC20.approve` instead of safe approvals, causing it to always revert on some ERC20s

### Summary

Super pools that get created on a specific asset then leverage its positions and deposit them in the "main" pools. Super pools get created in `SuperPoolFactory::deploySuperPool`, where some initial amount is sent from the user, and then deposited in the deployed super pool. When the assets are sent from the user, the factory approves the deployed pool, to allow outbound transfers, this is done using https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L73:
```solidity
IERC20(asset).approve(address(superPool), initialDepositAmt);
```
And the "default" ERC20 behavior expects the `approve` function to return a boolean, however, some ERC20s on some chains don't return a value.
The most popular example is USDT on the main net, and as the docs mention it should be compatible on any EVM chain and will support USDT:
>Q: On what chains are the smart contracts going to be deployed?
Any EVM-compatbile network

>Q: If you are integrating tokens, are you allowing only whitelisted tokens to work with the codebase or any complying with the standard? Are they assumed to have certain properties, e.g. be non-reentrant? Are there any types of [weird tokens](https://github.com/d-xo/weird-erc20) you want to integrate?
Tokens are whitelisted, only tokens with valid oracles can be used to create Base Pools.
Protocol governance will ensure that oracles are only set for standard ERC-20 tokens (plus USDC/USDT)

Another occurrence of this is `SuperPool::reallocate`, [here](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L450).

This causes Super pool to never work on these chains/tokens.


### Root Cause

Some known tokens don't return a value on approvals, more info [here](https://github.com/d-xo/weird-erc20?tab=readme-ov-file#missing-return-values), an example of this is USDT, which is mentioned that the protocol will use it.

Standard ERC20s return a boolean on approval, https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol#L67.

USDT on the main net doesn't return a value, https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#code.

### Impact

Super pools can never be created and used for assets that don't return a value on approval, an example of this is USDT on Ethereum main net.

### PoC

Minimal mock USDT token:
```solidity
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

contract MockUSDT {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function approve(address spender, uint256 amount) public {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max)
            allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
```

Add the following test in `protocol-v2/test/core/Superpool.t.sol`.
```solidity
function testSuperPoolUSDT() public {
    MockUSDT USDT = new MockUSDT("USDT", "USDT", 6);
    FixedPriceOracle USDToracle = new FixedPriceOracle(1e18);

    vm.startPrank(protocolOwner);
    riskEngine.setOracle(address(USDT), address(USDToracle));
    pool.initializePool(
        poolOwner,
        address(USDT),
        type(uint128).max,
        0xeba2c14de8b8ca05a15d7673453a0a3b315f122f56770b8bb643dc4bfbcf326b
    );
    vm.stopPrank();

    uint256 amount = 100e6;

    deal(address(USDT), address(this), amount);

    USDT.approve(address(superPoolFactory), amount);

    vm.expectRevert();
    superPoolFactory.deploySuperPool(
        address(this),
        address(USDT),
        feeTo,
        0.01 ether,
        1_000_000 ether,
        amount,
        "test",
        "test"
    );
}
```

### Mitigation

Use `safeApprove` instead of `approve` in `SuperPoolFactory::deploySuperPool` and `SuperPool::reallocate`.