Spare Sepia Chinchilla

Medium

# Borrowers will avoid fees, causing a loss of revenue for the protocol

### Summary

The absence of a mandatory minimum borrow amount greater than zero will cause potential fee avoidance for the protocol, as borrowers can circumvent fees by borrowing extremely small amounts repeatedly.

### Root Cause

The choice to set the minimum borrow amount to a range that includes zero is a mistake, as it allows borrowers to avoid paying origination fees by borrowing amounts that do not reach the threshold where fees are charged.

### Internal pre-conditions

1. Should the protocol have the minBorrow variable set to exactly 0.
2. The borrower needs to initiate a borrowing transaction with an amount small enough that, after applying the origination fee calculation, the fee rounds down to 0.

### External pre-conditions

_No response_

### Attack Path

1. Whenever Pool that has its minBorrow value set to 0, it allows borrowers to attempt borrowing without any enforced minimum amount.
2. A borrower calls the borrow function with an amount that, when multiplied by the origination fee rate, results in a fee calculation that rounds down to zero.         
Pool.sol: 465: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/Pool.sol#L465
4. The borrower repeats this process multiple times, borrowing small amounts and effectively avoiding paying any origination fees.

### Impact

The protocol suffers a potential loss of revenue from borrowing fees, as borrowers can continuously borrow tiny amounts without incurring fees. This may result in negligible financial loss to the protocol but represents a loophole that could be exploited for malicious intent or to drain protocol resources over time.

### PoC

_No response_

### Mitigation

To prevent this issue, the protocol should enforce a non-zero minimum borrow amount to ensure all borrowings incur a fee. Alternatively, the protocol can modify the fee calculation to round up, ensuring every borrowing transaction, no matter how small, results in a fee.