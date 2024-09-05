Magnificent Grape Pheasant

Medium

# position(s) will gain more costly overtime all the time regardless what the position manager does during borrow from pool. position manager role will be compromised many times by unpredictable interest accrued that are hard coded inside the protocol allowing the blockchain to inflate the interest - 0xaliyah

## Summary
0xaliyah
arabgodx

1. Delayed Transactions Will Cause Unintended Interest Accumulation Vulnerability

## Vulnerability Detail
1. The current implementation of the accrued interest calculation per Rate Model does not properly account for the impact of accumulation of delayed transactions time on interest accrued, and the associated loss for the borrower positions over time. Specifically, the interest calculation does not consider the compounding effect of multiple delays, which can result in a significant increase in the interest accrued. This vulnerability can be unintentionally exploited, and will accumulate a considerable amount of interest.
2. External Preconditions:
2.1 assume a payload of 1k borrow transaction per day, per year on average
2.2 assume around 5% of all borrow transactions will experience a delay
2.3 assume average 1 block per 11s on network
2.4 assume average 1 block per 11s + 1min on network, during delayed
2.5 then we need to calculate how long it will take in the worst case (sooner) for the accumulated block delay to be > 5% of the total available time in what would be considered an entire year.
2.6 we would compute the time delta based on the assumed accumulated delay given the total amount in borrowing token, or the, `totalBorrows,` that would have been successfully allocated in the time it has taken to accumulate a total in counted delays that is > 5% of a year. the number could be derived over a period of 4 years at 18 delays per day thus we may consider the, `totalBorrows,` sum of 4 years in total. 
3. Internal Preconditions: 
3.1 from the perspective of the protocol there would just need to be a discerning proportion of transactions that experience latency to be included in a given block regardless of the average borrows that can be handled per day, or the, `totalBorrows,` sum given as an amount.
4. Outcome:
4.1 here we took 5% of an entire year as sum of delays accumulated over longer than 1 year given in contrast how much interest may be expected normally in 1 year as a general example in an attempt to show that it may take a while for those delays to accumulate but the delay might accumulate overtime in a linear pattern to be > 5% of an entire year in sum total delay at the time delta computation. (i.e "normally," can be the abs(sum(time when block allocated) - sum(exact borrow request time))).
4.2 assume 5% may also be the min threshold for dust amount when evaluating any given vulnerability on Sherlock  . 
5. DOS
5.1 for the borrowing positions who will each expect to be filled on the borrow, earlier rather than later, as the preferred way.
5.2 for the protocol implementation who will expect role to afford higher fees in order to guarantee sooner block inclusion, but unable to gain control on the variable transactions delay during network congestion on the blockchain, due to the inadequately handled edge case possibly.

## Impact
1. This can result in a significant financial record keeping inefficiency for the protocol. Additionally, this vulnerability can also lead to a silent denial-of-service (DoS), as the design, or implementation of the system may become overwhelmed with a large number of delayed transactions without immediate detection.
2. This may affect all `IRateModel`.
3. Low impact High Likelihood (tbh there is a dust per alone each observed transaction, if ever it is valid, and it is a time sensitive function).

## Code Snippet
[poc](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/0b472f4bffdb2c7432a5d21f1636139cc01561a5/protocol-v2/src/Pool.sol#L420)

```python
import math

# Define the interest rate and principal amount
InterestRate =  # 10% per annum
TotalBorrows = # 1 ETH
SecondsPerYear = # seconds 365 * 24 * 60 * 60

# Define the time delta (51% of a year)
TimeDelta = 186.15  # approximately 51% of a year

# Calculate the interest accrued
InterestAccrued = TotalBorrows * (InterestRate * TimeDelta / SecondsPerYear )

print(f"Interest Accrued: {InterestAccrued :.2f} ETH")
```
## Tool used
Manual Review

## Recommendation
1. when calculating `rateFactor,` at `getInterestAccrued,` try to define the correct time delta by accounting for the delay if any. i.e block.timestamp - lastUpdated - blockDelayFactorRegarded = time delta