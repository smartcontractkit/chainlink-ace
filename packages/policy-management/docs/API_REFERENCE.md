> **Note for Developers:** This file provides a complete, auto-generated list of all functions and interfaces. For a more practical, task-oriented guide with code examples, please see the **[API Guide](API_GUIDE.md)** first.

# API Reference: Policy Management

This document provides the complete, formal interface specifications for the Policy Management component.

## Core Interfaces

### IPolicyEngine

**File:** [`src/interfaces/IPolicyEngine.sol`](../src/interfaces/IPolicyEngine.sol)

The `IPolicyEngine` interface defines the core functions for the central orchestrator that manages and executes policies.

#### Enums and Structs

```solidity
enum PolicyResult {
    None,
    Allowed,
    Continue
}

struct Parameter {
    bytes32 name;
    bytes value;
}

struct Payload {
    bytes4 selector;
    address sender;
    bytes data;
    bytes context;
}
```

#### Key Functions

```solidity
interface IPolicyEngine is IERC165 {
    function attach() external;
    function detach() external;

    function setExtractor(bytes4 selector, address extractor) external;
    function setExtractors(bytes4[] calldata selectors, address extractor) external;
    function getExtractor(bytes4 selector) external view returns (address);

    function setPolicyMapper(address policy, address mapper) external;
    function getPolicyMapper(address policy) external view returns (address);

    function addPolicy(address target, bytes4 selector, address policy, bytes32[] calldata policyParameterNames) external;
    function addPolicyAt(address target, bytes4 selector, address policy, bytes32[] calldata policyParameterNames, uint256 position) external;
    function removePolicy(address target, bytes4 selector, address policy) external;
    function getPolicies(address target, bytes4 selector) external view returns (address[] memory);

    function setDefaultPolicyAllow(bool defaultAllow) external;
    function setTargetDefaultPolicyAllow(address target, bool defaultAllow) external;

    function check(Payload calldata payload) external view;
    function run(Payload calldata payload) external;
}
```

### IPolicy

**File:** [`src/interfaces/IPolicy.sol`](../src/interfaces/IPolicy.sol)

The `IPolicy` interface is the standard for all policy contracts. Each policy must implement this interface to be compatible with the `PolicyEngine`.

#### Key Functions

```solidity
interface IPolicy is IERC165 {
  function run(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] calldata parameters,
    bytes calldata context
  ) external view returns (IPolicyEngine.PolicyResult);

  function postRun(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] calldata parameters,
    bytes calldata context
  ) external;

  function onInstall(bytes4 selector) external;
  function onUninstall(bytes4 selector) external;
}
```

### IPolicyProtected

**File:** [`src/interfaces/IPolicyProtected.sol`](../src/interfaces/IPolicyProtected.sol)

The `IPolicyProtected` interface must be implemented by any contract that wishes to be protected by a `PolicyEngine`.

#### Key Functions

```solidity
interface IPolicyProtected is IERC165 {
  function attachPolicyEngine(address policyEngine) external;
  function getPolicyEngine() external view returns (address);
  function setContext(bytes calldata context) external;
  function getContext() external view returns (bytes memory);
  function clearContext() external;
}
```

## Helper Interfaces

### IExtractor

**File:** [`src/interfaces/IExtractor.sol`](../src/interfaces/IExtractor.sol)

The `IExtractor` interface is the standard for contracts that parse transaction calldata into named parameters for the `PolicyEngine`.

#### Key Functions

```solidity
interface IExtractor is IERC165 {
  function extract(IPolicyEngine.Payload calldata payload) external view returns (IPolicyEngine.Parameter[] memory);
}
```

### IMapper

**File:** [`src/interfaces/IMapper.sol`](../src/interfaces/IMapper.sol)

The `IMapper` interface is the standard for custom mapper contracts. A custom mapper is only needed for advanced scenarios where parameter data needs to be transformed before being passed to a policy.

#### Key Functions

```solidity
interface IMapper is IERC165 {
  function map(
    IPolicyEngine.Parameter[] calldata extractedParameters
  ) external view returns (bytes[] memory mappedParameters);
}
```

## Events

```solidity
event TargetAttached(address indexed target);
event TargetDetached(address indexed target);
event PolicyAdded(address indexed target, bytes4 indexed selector, address policy);
event PolicyRemoved(address indexed target, bytes4 indexed selector, address policy);
event ExtractorSet(bytes4 indexed selector, address indexed extractor);
event PolicyParametersSet(address indexed policy, bytes[] parameters);
event DefaultPolicyAllowSet(bool defaultAllow);
event TargetDefaultPolicyAllowSet(address indexed target, bool defaultAllow);
```

## Errors

```solidity
error TargetNotAttached(address target);
error TargetAlreadyAttached(address target);
error PolicyEngineUndefined();
error PolicyRunRejected(bytes4 selector, address policy, string rejectReason);
error PolicyRejected(string rejectReason);
error PolicyMapperError(address policy, bytes errorReason);
error PolicyRunError(bytes4 selector, address policy, bytes errorReason);
error PolicyRunUnauthorizedError(address account);
error PolicyPostRunError(bytes4 selector, address policy, bytes errorReason);
error UnsupportedSelector(bytes4 selector);
error InvalidConfiguration(string errorReason);
error ExtractorError(bytes4 selector, address extractor, bytes errorReason);
```
