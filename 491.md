Shiny Tartan Llama

High

# A malicious user can reset the riskModule contract in RiskEngine.sol

### Summary

In`RiskEngine.sol` there are 2 ways to set the `riskModule`. Either by using the `updateFromRegistry()` which has external  visibility or by using `setRiskModule()` which only owner can call. Now, when the owner set using `setRiskModule()` it doesn't ensure that the **registry** is also updated. In case the **registry** is not updated any user can call `updateFromRegistry()` and can reset the `riskModule` to previous address.

### Root Cause

`https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L114-L120` is public and `https://github.com/sherlock-audit/2024-08-sentiment-v2/blob/main/protocol-v2/src/RiskEngine.sol#L235-L239` doesn't check if the **registry** is also updated before updating the `riskModule`.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

1. **Risk Module** is set by calling `updateFromRegistry()`.
2. Owner updates **Risk Module** using `setRiskModule()`.
3. Alice resets  **Risk Module** by calling `updateFromRegistry()`.

### Impact

The owner will update the `riskModule` but an user can revert the change causing the expected changes to not reflect. It can have bigger impact if the owner changes other fields like **oracle** and **ltvs** as per new `riskModule` and then the user reverts to `riskModule`. 

### PoC

### Test
Add the following test in `RiskEngine.t.sol`
```solidity
function testCanUpdateRiskModule() public {
    vm.startPrank(protocolOwner);
    console.log("Initial address of risk Module in Risk Engine: ",riskEngine.getRiskModule());
    
    riskEngine.setRiskModule(address(0x3828342));
    console.log("Address of risk Module after setRiskModule(): ",riskEngine.getRiskModule());
    assertEq(address(riskEngine.riskModule()), address(0x3828342));
    vm.stopPrank();

    vm.startPrank(address(0x21));
    riskEngine.updateFromRegistry();
    console.log("Any user calls updateFromRegistry() now: ",riskEngine.getRiskModule());
}   
```

### Log
```LOG
Logs:
  Initial address of risk Module in Risk Engine:  0xA11d35fE4b9Ca9979F2FF84283a9Ce190F60Cd00
  Address of risk Module after setRiskModule():  0x0000000000000000000000000000000003828342
  Any user calls updateFromRegistry() now:  0xA11d35fE4b9Ca9979F2FF84283a9Ce190F60Cd00
```

### Mitigation

Either add access modifier on `updateFromRegistry()` or update the value of **riskModule** in the **registry** too when `setRiskModule()` is called.