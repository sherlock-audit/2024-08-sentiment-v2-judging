Nice Sangria Stallion

Medium

# Validation Missing: minLtv Can Be Set Higher Than maxLtv, Leading to Invalid Borrowing Limits

## Summary
The `RiskEngine::setLtvBounds` function does not check if `minLtv` is greater than `maxLtv`, which can lead to an invalid state where the minimum borrowing limit is higher than the maximum borrowing limit.
## Vulnerability Detail
The function `RiskEngine::setLtvBounds` allows setting `minLtv` and `maxLtv` without ensuring that `minLtv` is less than or equal to `maxLtv`. This can create a scenario where the system's borrowing logic is broken, causing critical functions to fail or revert.
## Impact
1.Breaks the logic of borrowing limits.
2.Functions relying on these values might fail or revert.
3.Users would be unable to understand or predict borrowing behaviour.
## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L222-L230
```solidity
function setLtvBounds(uint256 _minLtv, uint256 _maxLtv) external onlyOwner {

    if (_minLtv == 0) revert RiskEngine_MinLtvTooLow();
    if (_maxLtv >= 1e18) revert RiskEngine_MaxLtvTooHigh();

    minLtv = _minLtv;
    maxLtv = _maxLtv;

    emit LtvBoundsSet(_minLtv, _maxLtv);
}
```
## Tool used

Manual Review

## Recommendation
Add a check to ensure that minLtv is less than or equal to maxLtv before setting the values:
```solidity
function setLtvBounds(uint256 _minLtv, uint256 _maxLtv) external onlyOwner {
    if (_minLtv == 0) revert RiskEngine_MinLtvTooLow();
    if (_maxLtv >= 1e18) revert RiskEngine_MaxLtvTooHigh();
+   if (_minLtv > _maxLtv) revert RiskEngine_InvalidLtvBounds();

    minLtv = _minLtv;
    maxLtv = _maxLtv;

    emit LtvBoundsSet(_minLtv, _maxLtv);
}
```
Adding this check ensures that the minLtv is always less than or equal to maxLtv, maintaining the integrity of the borrowing logic