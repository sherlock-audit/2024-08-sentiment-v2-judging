Abundant Hazel Newt

Medium

# None of the functions in SuperPool checks pause state

## Summary
None of the functions in SuperPool checks pause state.

## Vulnerability Detail
`SuperPool` contract is `Pausable`.
[SuperPool.sol#L25](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L25):
```solidity
contract SuperPool is Ownable, Pausable, ReentrancyGuard, ERC20 {
```
`togglePause()` is implemented to toggle pause state of the `SuperPool`.
[SuperPool.sol#L163-L167](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L163-L167):
```solidity
    /// @notice Toggle pause state of the SuperPool
    function togglePause() external onlyOwner {
        if (Pausable.paused()) Pausable._unpause();
        else Pausable._pause();
    }
```
However, none of the functions in `SuperPool` checks the pause state, renders the pause functionality meaningless. As confirmed with sponsor, pause state checking should be implemented on some functions.

## Impact
None of the functions in `SuperPool` can be paused.

## Code Snippet
https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L25

## Tool used
Manual Review

## Recommendation
It is recommend to implemented pause state checking on some of the functions, for example, and `deposit()` and `mint()` functions:
[SuperPool.sol#L258](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L258):
```diff
-    function deposit(uint256 assets, address receiver) public nonReentrant returns (uint256 shares) {
+    function deposit(uint256 assets, address receiver) public whenNotPaused nonReentrant returns (uint256 shares) {
```


[SuperPool.sol#L269](https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/SuperPool.sol#L269):
```diff
-    function mint(uint256 shares, address receiver) public nonReentrant returns (uint256 assets) {
+    function mint(uint256 shares, address receiver) public whenNotPaused nonReentrant returns (uint256 assets) {
```
