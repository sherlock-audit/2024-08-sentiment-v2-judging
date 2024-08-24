Soaring Malachite Trout

High

# Asset Accounting and Share Distribution Issues in SuperPool Deposit Function

## Summary
The `deposit` function in the `SuperPool` contract suffers from issues related to asset handling and accounting when distributing deposits across multiple pools. If assets cannot be fully distributed among the pools, the unutilized assets are still added to the `lastTotalAssets`, which affects the calculation of shares for new depositors. This can lead to incorrect share allocations and potentially cause the `SuperPool` to hit its cap prematurely, as it does not return how much amount of asset are depoisted in base pool.

## Vulnerability Detail
1. **Incorrect Asset Accounting:**
   - **Issue:** When assets are deposited and distributed across pools, any remaining unutilized assets that are not fully distributed still get added to `lastTotalAssets`. This can cause the `lastTotalAssets` to inaccurately reflect the total assets, leading to potential discrepancies in share calculations.
   - **Potential Impact:** New depositors may receive fewer shares than expected because the `lastTotalAssets` is inflated by unutilized assets. This can result in inequitable distribution of shares and prematurely hit the `superPoolCap`, causing issues for future depositors.

2. **Potential for Excessive Shares Issuance:**
   - **Issue:** If the deposit amount cannot be fully distributed among the pools (e.g., due to some pools reaching their cap), the `lastTotalAssets` will still include the full deposit amount even though only a portion of it was actually distributed. This can lead to more shares being issued than the actual value of the assets deposited.
   - **Potential Impact:** The share issuance will be skewed, potentially diluting the value of the shares and making the `SuperPool` cap hit earlier than intended.

3. **Handling of Partial Deposits:**
   - **Issue:** The `try`-`catch` block in `_supplyToPools` allows for partial deposits to be made, but it does not adjust the `assets` value correctly if the deposit to a pool fails. This can leave some assets undeposited and still count towards `lastTotalAssets`.
   - **Potential Impact:** If a deposit fails but assets are not correctly accounted for, this could result in an imbalance between actual assets held and those recorded, affecting the integrity of the pool and the accuracy of share calculations.

Example: 1. suppose the superPoolCap is 1.5M and currently LastTotalAsset = 450K 
2. USER  comes call `deposit` by for 1M as there is no limit how much user could deposit and to check whether base Pool could handle that much deposit asset
3. Assume there aren't enough Basepool added in superpool which could handle 1M asset, assume base pool could only handle 500K asset
4. So `asset == 0` will not execute, because it didn't not consume all the asset supply
5. As `for loop` ends and lasttotalSupply += asset , which is 1.45 M 
6. so quickly after few submission the `SuperPoolCap` will hit and stops further deposit
7. result -> prematurely hitting cap, without consuming all the asset and inflate the share for new deposit


## Impact
- **Share Calculation Issues:** Depositors may receive fewer shares than their deposited asset value due to incorrect accounting of `lastTotalAssets`.
- **Premature Cap Hit:** The `SuperPool` cap may be reached earlier than intended because unutilized assets still contribute to `lastTotalAssets`.
- **Diluted Value:** New depositors may experience reduced value per share, leading to an unfair distribution of assets.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L504

```solidity
function deposit(uint256 assets, address receiver) public nonReentrant returns (uint256 shares) {
    accrue();
    shares = _convertToShares(assets, lastTotalAssets, totalSupply(), Math.Rounding.Down);
    if (shares == 0) revert SuperPool_ZeroShareDeposit(address(this), assets);
    _deposit(receiver, assets, shares);
}

function _deposit(address receiver, uint256 assets, uint256 shares) internal {
    if (lastTotalAssets + assets > superPoolCap) revert SuperPool_SuperPoolCapReached();
    ASSET.safeTransferFrom(msg.sender, address(this), assets);
    ERC20._mint(receiver, shares);
    _supplyToPools(assets);
    lastTotalAssets += assets; // lastTotalAsset is total asset in super pool
    emit Deposit(msg.sender, receiver, assets, shares);
}

function _supplyToPools(uint256 assets) internal {
    uint256 depositQueueLength = depositQueue.length;
    for (uint256 i; i < depositQueueLength; ++i) {
        uint256 poolId = depositQueue[i];
        uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));
        if (assetsInPool < poolCapFor[poolId]) {
            uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
            if (assets < supplyAmt) supplyAmt = assets;
            ASSET.forceApprove(address(POOL), supplyAmt);

            try POOL.deposit(poolId, supplyAmt, address(this)) {
                assets -= supplyAmt;
            } catch { }

            if (assets == 0) return;
        }
    }
}
```

## Tool used

Manual Review

## Recommendation
1. **Update Asset Accounting:**
   - Ensure that `lastTotalAssets` is only updated with the amount of assets that have been successfully deposited into the pools. This may involve tracking the amount actually deposited and updating `lastTotalAssets` accordingly.

   ```solidity
   function _deposit(address receiver, uint256 assets, uint256 shares) internal {
       uint256 depositedAssets = assets - remainingAssets; // Calculate the amount actually deposited
       if (lastTotalAssets + depositedAssets > superPoolCap) revert SuperPool_SuperPoolCapReached();
       ASSET.safeTransferFrom(msg.sender, address(this), assets);
       ERC20._mint(receiver, shares);
       _supplyToPools(assets);
       lastTotalAssets += depositedAssets;
       emit Deposit(msg.sender, receiver, assets, shares);
   }
   ```

2. **Handle Partial Deposits More Rigorously:**
   - Adjust `assets` correctly in case of failed deposits, ensuring that any remaining assets are accounted for and not incorrectly reflected in `lastTotalAssets`.

   ```solidity
   function _supplyToPools(uint256 assets) internal {
       uint256 initialAssets = assets;
       for (uint256 i; i < depositQueue.length; ++i) {
           uint256 poolId = depositQueue[i];
           uint256 assetsInPool = POOL.getAssetsOf(poolId, address(this));
           if (assetsInPool < poolCapFor[poolId]) {
               uint256 supplyAmt = poolCapFor[poolId] - assetsInPool;
               if (assets < supplyAmt) supplyAmt = assets;
               ASSET.forceApprove(address(POOL), supplyAmt);

               try POOL.deposit(poolId, supplyAmt, address(this)) {
                   assets -= supplyAmt;
               } catch {
                   // Handle failed deposit, potentially retry or revert
               }

               if (assets == 0) break;
           }
       }
       // Update lastTotalAssets based on actual deposited assets
       if (initialAssets != assets) {
           lastTotalAssets += (initialAssets - assets);
       }
   }
   ```