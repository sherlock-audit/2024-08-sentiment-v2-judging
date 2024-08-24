Tricky Felt Lizard

High

# Interest fees shares are minted for the owner of Basepool even for insolvent Positions which eventually don't generate any interest to the LPs.

## Summary
```accrue()``` mints fee shares for the owner based on **expected** interest before actual repayment, leading to unfair losses for LPs if the borrowed amount is never repaid due to insolvent Position and ```rebalanceBadDebt()``` call.

## Vulnerability Detail
In Pool singleton contract the last interest accrued from borrows is calulcated and updated before every action by calling the ```accrue()``` function and passing the ```poolId```. We can see the implementation of the ```accrue()``` function here :

```solidity
/// @dev update pool state to accrue interest since the last time accrue() was called
    function accrue(PoolData storage pool, uint256 id) internal {
        (uint256 interestAccrued, uint256 feeShares) = simulateAccrue(pool);

        if (feeShares != 0) _mint(feeRecipient, id, feeShares);

        // update pool state
        pool.totalDepositShares += feeShares;
        pool.totalBorrowAssets += interestAccrued;
        pool.totalDepositAssets += interestAccrued;

        // store a timestamp for this accrue() call
        // used to compute the pending interest next time accrue() is called
        pool.lastUpdated = uint128(block.timestamp);
    }
```
[Link to code](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L400C5-L414C6)

As we can see, there is a minting of extra shares for this particular BasePool which represent the fee that - in theory - the owner will get from the interest accrued from the borrows. However, there is not sure that this interest will be generated and be repaid to the BasePool since there is a posibility for the Position to become insolvent and in this case, the whole borrowed amount will be just deleted. We can see the implementation of the ```rebalanceBadDebt()``` function here :

```solidity
    function rebalanceBadDebt(uint256 poolId, address position) external {
        PoolData storage pool = poolDataFor[poolId];
        accrue(pool, poolId);

        // revert if the caller is not the position manager
        if (msg.sender != positionManager) revert Pool_OnlyPositionManager(poolId, msg.sender);

        // compute pool and position debt in shares and assets
        uint256 totalBorrowShares = pool.totalBorrowShares;
        uint256 totalBorrowAssets = pool.totalBorrowAssets;
        uint256 borrowShares = borrowSharesOf[poolId][position];
        // [ROUND] round up against lenders
        uint256 borrowAssets = _convertToAssets(borrowShares, totalBorrowAssets, totalBorrowShares, Math.Rounding.Up);

        // rebalance bad debt across lenders
        pool.totalBorrowShares = totalBorrowShares - borrowShares;
        // handle borrowAssets being rounded up to be greater than totalBorrowAssets
        pool.totalBorrowAssets = (totalBorrowAssets > borrowAssets) ? totalBorrowAssets - borrowAssets : 0;
        uint256 totalDepositAssets = pool.totalDepositAssets;
        pool.totalDepositAssets = (totalDepositAssets > borrowAssets) ? totalDepositAssets - borrowAssets : 0;
        borrowSharesOf[poolId][position] = 0;
    }
```
[Link to code](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L528-L549)

In this case, when a Position has to be deleted due to insolvency, the LPs lose their deposited assets but the owner, still has still his shares generated from the "hypothetical" interest that the Position produced. This, of course, shouldn't be the case since it is unfair for the LPs who did not get any interest accrued for their deposits to have their shares slashed as if the interest got generated. We can imagine that this vulnerability of the contracts can be extremelly disadvantageous, if becomes on scale, for the LPs who will see their share to be minimized. They may lost some deposits(which is acceptable risk since they decided to lend them) but their assets should not be slashed furthermore on the "supposed" interest that they **would** have receive.

> TLDR : The fee shares are minted before the actual money be returned so in the case of the rebalance of a insolvent Position there is, eventually, not any interest generated so there shouldn't be any interest fee shares minted.

## Impact
This vulnerability results in the unfair dilution of LP shares because fee shares are minted based on expected interest that may never be realized if a ```Position``` becomes insolvent. LPs could suffer additional losses on top of their lost deposits due to the minting of these fee shares. The impact is especially severe when scaled, as it could systematically erode LPs' returns.

## Code Snippet
Here is the ```accrue``` function of ```Pool``` contract : 
```solidity
    /// @dev update pool state to accrue interest since the last time accrue() was called
    function accrue(PoolData storage pool, uint256 id) internal {
        (uint256 interestAccrued, uint256 feeShares) = simulateAccrue(pool);

@>        if (feeShares != 0) _mint(feeRecipient, id, feeShares);

        // update pool state
        pool.totalDepositShares += feeShares;
        pool.totalBorrowAssets += interestAccrued;
        pool.totalDepositAssets += interestAccrued;

        // store a timestamp for this accrue() call
        // used to compute the pending interest next time accrue() is called
        pool.lastUpdated = uint128(block.timestamp);
    }
```
[Link to code](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L400-L414)

## Tool used
Manual Review

## Recommendation
Consider minting the fee shares after the actual repay has been made and the interest has been paid.