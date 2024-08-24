Skinny Olive Unicorn

Medium

# _deposit() function in SuperPool contract may update incorrectly lastTotalAssets

## Summary
_deposit() function in SuperPool contract may update incorrectly lastTotalAssets
## Vulnerability Detail
When _deposit() function is called in SuperPool.sol, internal function _supplyToPools() is called in order to deposit tokens in different pools. _supplyToPools() deposits in all the pools in the order they appear in depositQueue[] array. Problem happens if assets input parameter, which indicates how many tokens are to be deposited, is greater than the total number of tokens depositable at the moment. As _supplyToPools() does not revert under any circumstances due to the try/catch structure, the function will finish without all the assets being deposited.
After calling _supplyToPools(), _deposit() also updates the lastTotalAssets state variable by adding 'assets', without checking if all of them were deposited, which would make that this variable and the total amount of deposited assets do not match.

## Impact
lastTotalAssets variable will indicate a wrong amount of deposited assets, which will have effects when trying to convert a given amount of assets into shares or viceversa, or when calling accrue() function.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L497-L506
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L524-L543

## Tool used
Manual Review

## Recommendation
Modify _supplyToPools() function to return the number of un deposited assets, subtract the returned amount from the number of assets when updating the lastTotalAssets (as they are not really deposited). These assets should not be transferred from the user.

```solidity
- function _supplyToPools(uint256 assets) internal {
+ function _supplyToPools(uint256 assets) internal returns (uint256 undepositedAssets){
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

                if (assets == 0) return;
            }
        }
+       depositedAssets = assets;
    }
```
```solidity
function _deposit(address receiver, uint256 assets, uint256 shares) internal {
        // assume that lastTotalAssets are up to date
        if (lastTotalAssets + assets > superPoolCap) revert SuperPool_SuperPoolCapReached();
        // Need to transfer before minting or ERC777s could reenter.
-       ASSET.safeTransferFrom(msg.sender, address(this), assets);
        ERC20._mint(receiver, shares);
-       _supplyToPools(assets);
+      uint256 undepositedAssets = _supplyToPools(assets);
-       lastTotalAssets += assets;
+      lastTotalAssets += assets - undepositedAssets;
+      ASSET.safeTransferFrom(msg.sender, address(this), assets - undepositedAssets);
        emit Deposit(msg.sender, receiver, assets, shares);
    }
```