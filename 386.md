Rhythmic Cherry Starfish

Medium

# WETH incompatability on Blast L2 due to the contract not handling `safeTransferFrom()` when src is `msg.sender`

## Summary

The protocol cannot be deployed on Blast L2 if WETH is to be an approved token.

## Vulnerability Detail

The contest [readme](https://audits.sherlock.xyz/contests/349) indicates that the intention is to deploy the protocol on any EVM-compatible network:

>"Q: On what chains are the smart contracts going to be deployed? A: Any EVM-compatbile network"

Additionally, due to the following factors, it is assumed the protcol would be interested in handling WETH on any deployment:
- Weth is [listed for deployment](https://gist.github.com/ruvaag/58c9fc2e5c139451c83c21fda27b77a2) on the example Arbitrum deployment
- Collateral and debt value is denominated in the value of ETH, so having WETH as an approved asset within the system will be convenient

However the [WETH contract on Blast](https://blastscan.io/token/0x4300000000000000000000000000000000000004?a=0x7dec49d6ccd33486ad46e16207c29f5371492996#code) uses a different implementation than on other chains, and consequently will revert when `safeTransferFrom()` is called with `src` == `msg.sender`.


## Impact

- This will cause a [revert](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L72) if a SuperPool is attempted to be deployed with the `ASSET` as WETH due to the initial deposit reverting. Even if a SuperPool were to be deployed without using the factory, the `deposit` method is DOSed due to the same reason.
- This will also [prevent any deposit](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L318) into a base pool with `pool.asset` as WETH.
- Please also be aware that WETH is a rebasing token by default on Blast but this functionality can be disabled be by adjusting `YieldMode` (https://docs.blast.io/building/guides/weth-yield)

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPoolFactory.sol#L72
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L318

## POC 

Copy this test into a new file and run the test on https://rpc.blast.io

```javascript
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract BlastTransferTest is Test {
    address user1 = address(0x7dec49D6CCd33486aD46e16207C29F5371492996); // Find an address with sufficient balance on Blast
    address user2 = makeAddr('user2');
    IERC20 public constant WETH = IERC20(0x4300000000000000000000000000000000000004); // WETH on Blast

    function test_POC_TransferFromRevert() public {
        assert(WETH.balanceOf(user1) > 0.01 ether);
        vm.startPrank(user1);
        vm.expectRevert();
        WETH.transferFrom(user1, user2, 0.01 ether);
        vm.stopPrank();
    }
}
```

## Tool used

Manual Review

## Recommendation
- If WETH is required as an approved asset within the system, avoid deploying on Blast L2