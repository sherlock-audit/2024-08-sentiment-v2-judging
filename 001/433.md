Radiant Aquamarine Iguana

High

# Lenders can can deposit into full SuperPools

## Summary
The  _supplyToPools function loops through all BasePools in the queue and supplies funds to them as long as the cap is not reached,But this function does not revert if all the caps were reached and it was impossible to supply funds to any pool.Therefore lenders are still able to deposit funds into a full SuperPool and mint shares which is very capital inefficient and will reduce the yield per share of all lenders.


EXAMPLE:

> Xlenders deposit a sum Y USDC into pools with 5% APY over the SuperPool and reach the cap
>These lenders now receive 5% APY on their deposits.
> More lenders deposit into the SuperPool which is already full.
>The new lenders' funds are not put to work but they still receive shares of the SuperPool and therefore a share of the yield from the BasePools.
>Every lender now receives less than the 5% APY on their deposits.
## Vulnerability Detail
   function _supplyToPools(uint256 assets) internal {
        uint256 depositQueueLength = depositQueue.length;
        for (uint256 i; i < depositQueueLength; ++i) {
            uint256 poolId = depositQueue[i];
            uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));

            if (assetsInPool < poolCapFor[poolId]) {
                uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
                if (assets < supplyAmt) supplyAmt = assets;
                ASSET.forceApprove(address(POOL), supplyAmt);

                // skip and move to the next pool in queue if deposit reverts
                try POOL.deposit(poolId, supplyAmt, address(this)) {
                    assets -= supplyAmt;
                } catch { }

       @>>         if (assets == 0) return;
            }
        }
    }

   
## Impact
Reduce the yield per share of all lenders.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L540
## Tool used

Manual Review

## Recommendation

Revert at the end of the _supplyToPools function.