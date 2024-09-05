Mammoth Rosewood Okapi

Medium

# Accrued interest is calculated incorrectly due to a continuous griefing attack.


## Summary
In the Arbitrum L2 environment, low transaction fees enable malicious users to exploit Pool::accrue() function, resulting in Accrued interest incorrect.
## Vulnerability Detail
```javascript
@>>    function accrue(uint256 id) external {
        PoolData storage pool = poolDataFor[id];
        accrue(pool, id);
    }
```
We can see that accrue can be called by any external user. The accrue() function calls accrue(pool, id), which internally calls simulateAccrue(). Ultimately, interest is calculated through the RateMode::getInterestAccrued() function.

```javascript
        function accrue(PoolData storage pool, uint256 id) internal {
@>        (uint256 interestAccrued, uint256 feeShares) = simulateAccrue(pool);

        if (feeShares != 0) _mint(feeRecipient, id, feeShares);

        // update pool state
        pool.totalDepositShares += feeShares;
        pool.totalBorrowAssets += interestAccrued;
        pool.totalDepositAssets += interestAccrued;

        // store a timestamp for this accrue() call
        // used to compute the pending interest next time accrue() is called
@>        pool.lastUpdated = uint128(block.timestamp);
    }
```

```javascript
    function simulateAccrue(PoolData storage pool) internal view returns (uint256, uint256) {
@>>        uint256 interestAccrued = IRateModel(pool.rateModel).getInterestAccrued(
            pool.lastUpdated, pool.totalBorrowAssets, pool.totalDepositAssets
        );
        //skip ......
        return (interestAccrued, feeShares);
    }
```
Let’s take the FixedRateModel as an example to examine the getInterestAccrued function. Other RateModel implementations follow a similar pattern.
```javascript
   function getInterestAccrued(uint256 lastUpdated, uint256 totalBorrows, uint256) external view returns (uint256) {
        // [ROUND] rateFactor is rounded up, in favor of the protocol
        // rateFactor = time delta * apr / secondsPerYear
@>>        uint256 rateFactor = ((block.timestamp - lastUpdated)).mulDiv(RATE, SECONDS_PER_YEAR, Math.Rounding.Up);

        // [ROUND] interest accrued is rounded up, in favor of the protocol
        // interestAccrued = borrows * rateFactor
@>>        return totalBorrows.mulDiv(rateFactor, 1e18, Math.Rounding.Up);
    }    
```
Since the internal calculations in getInterestAccrued use Math.Rounding.Up for approximations, this results in accrued interest being slightly higher than the actual interest. This issue becomes more pronounced for tokens like USDT and USDC, which have precision of 6 or lower. When subjected to continuous accrue() calls in a griefing attack, the problem can escalate, leading to an overestimation of interest.

#### POC
Assume the token is USDC, with a precision of 6, and the fixed annual interest rate is 5% (RATE = 5e16). The borrowed amount is 1,000,000.

```javascript
function testTimeIncreasesDebtIncorrect() public {
        uint96 assets = 5_000_000;
        testBorrowWorksAsIntended(assets);
        (,,,,,,, uint256 totalBorrowAssets, uint256 totalBorrowShares,,) = pool.poolDataFor(linearRatePool);
        console2.log("totalBorrowAssets is: ", totalBorrowAssets);
        
        //after 1 second
        vm.warp(block.timestamp+1);
        vm.roll(block.number + 1);

        pool.accrue(linearRatePool);

        (,,,,,,, uint256 newTotalBorrowAssets, uint256 newTotalBorrowShares,,) = pool.poolDataFor(linearRatePool);
        console2.log("newTotalBorrowAssets is: ", newTotalBorrowAssets);
        assertEq(newTotalBorrowShares, totalBorrowShares);
        assertGt(newTotalBorrowAssets, totalBorrowAssets);
    }

```
Add the above function to ./test/core/Pool.t.sol and modify two values in the BaseTest.t.sol file.
```diff
-   asset1 = new MockERC20("Asset1", "ASSET1", 6);
+   asset1 = new MockERC20("Asset1", "ASSET1", 18);


-   address fixedRateModel = address(new FixedRateModel(1e18));
+   address fixedRateModel = address(new FixedRateModel(5e16));
```
Then run the command:
`forge test --mt testTimeIncreasesDebtIncorrect -vv`
This will produce the test result output.

```bash
[PASS] testTimeIncreasesDebtIncorrect() (gas: 357566)
Logs:
  totalBorrowAssets is:  1000000
  newTotalBorrowAssets is:  1000001

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.47ms (599.29µs CPU time)
```
Thus, the actual generated annual interest rate is:  1*31557600/1000000 = 3155.76%, which is far greater than 5%.
## Impact
The borrower ends up paying significantly more interest, leading to financial losses.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L375

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L401

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L380

https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/irm/FixedRateModel.sol#L30
## Tool used

Manual Review

## Recommendation
Add access control to the accrue function.​