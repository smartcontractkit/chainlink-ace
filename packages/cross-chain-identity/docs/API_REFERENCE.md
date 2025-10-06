> **Note for Developers:** This file provides a complete, auto-generated list of all functions and interfaces. For a more practical, task-oriented guide with code examples, please see the **[API Guide](API_GUIDE.md)** first.

# API Reference: Cross-Chain Identity

This document provides the complete, formal interface specifications for the Cross-Chain Identity component.

## Core Interfaces

### IIdentityRegistry

**File:** [`src/interfaces/IIdentityRegistry.sol`](../src/interfaces/IIdentityRegistry.sol)

The `IIdentityRegistry` manages how each local blockchain address maps to a Cross-Chain Identifier (CCID). By interacting with this registry, applications can link multiple addresses to a single identity.

#### Key Functions

```solidity
interface IIdentityRegistry {
    function registerIdentity(bytes32 ccid, address account, bytes calldata context) external;
    function registerIdentities(bytes32[] calldata ccids, address[] calldata accounts, bytes calldata context) external;
    function removeIdentity(bytes32 ccid, address account, bytes calldata context) external;
    function getIdentity(address account) external view returns (bytes32);
    function getAccounts(bytes32 ccid) external view returns (address[] memory);
}
```

#### Events

```solidity
event IdentityRegistered(bytes32 indexed ccid, address indexed account);
event IdentityRemoved(bytes32 indexed ccid, address indexed account);
```

#### Errors

```solidity
error IdentityAlreadyRegistered(bytes32 ccid, address account);
error IdentityNotFound(bytes32 ccid, address account);
error InvalidConfiguration(bytes errorReason);
```

### ICredentialRegistry

**File:** [`src/interfaces/ICredentialRegistry.sol`](../src/interfaces/ICredentialRegistry.sol)

The `ICredentialRegistry` manages the lifecycle of credentials linked to a CCID, including registration, removal, and renewal processes.

#### Credential Struct

```solidity
struct Credential {
    uint40 expiresAt;
    bytes credentialData;
}
```

#### Key Functions

```solidity
interface ICredentialRegistry {
    function registerCredential(
        bytes32 ccid,
        bytes32 credentialTypeId,
        uint40 expiresAt,
        bytes calldata credentialData,
        bytes calldata context
    ) external;

    function registerCredentials(
        bytes32 ccid,
        bytes32[] calldata credentialTypeIds,
        uint40 expiresAt,
        bytes[] calldata credentialDatas,
        bytes calldata context
    ) external;

    function removeCredential(bytes32 ccid, bytes32 credentialTypeId, bytes calldata context) external;

    function renewCredential(bytes32 ccid, bytes32 credentialTypeId, uint40 expiresAt, bytes calldata context) external;

    function isCredentialExpired(bytes32 ccid, bytes32 credentialTypeId) external view returns (bool);

    function getCredentialTypes(bytes32 ccid) external view returns (bytes32[] memory);

    function getCredential(bytes32 ccid, bytes32 credentialTypeId) external view returns (Credential memory);

    function getCredentials(
        bytes32 ccid,
        bytes32[] calldata credentialTypeIds
    ) external view returns (Credential[] memory);
}
```

#### Events

```solidity
event CredentialRegistered(
    bytes32 indexed ccid, bytes32 indexed credentialTypeId, uint40 expiresAt, bytes credentialData
);
event CredentialRemoved(bytes32 indexed ccid, bytes32 indexed credentialTypeId);
event CredentialRenewed(
    bytes32 indexed ccid,
    bytes32 indexed credentialTypeId,
    uint40 previousExpiresAt,
    uint40 expiresAt
);
```

#### Errors

```solidity
error CredentialAlreadyRegistered(bytes32 ccid, bytes32 credentialTypeId);
error CredentialNotFound(bytes32 ccid, bytes32 credentialTypeId);
error InvalidConfiguration(string errorReason);
```

### ICredentialRegistryValidator

**File:** [`src/interfaces/ICredentialRegistryValidator.sol`](../src/interfaces/ICredentialRegistryValidator.sol)

The `ICredentialRegistryValidator` provides validation functionality to check whether credentials exist and are valid for a given CCID.

#### Key Functions

```solidity
interface ICredentialRegistryValidator {
    function validate(bytes32 ccid, bytes32 credentialTypeId, bytes calldata context) external view returns (bool);

    function validateAll(
        bytes32 ccid,
        bytes32[] calldata credentialTypeIds,
        bytes calldata context
    ) external view returns (bool);
}
```

#### Critical Requirements

**Non-Reverting Guarantee:** The `validate` and `validateAll` functions, along with all other view functions in `ICredentialRegistryValidator` implementations **MUST NOT revert under any circumstances**. This requirement is critical to ensure reliable interactions with credential registry validator contracts.

## Application Integration Interfaces

### ICredentialRequirements

**File:** [`src/interfaces/ICredentialRequirements.sol`](../src/interfaces/ICredentialRequirements.sol)

The `ICredentialRequirements` interface allows applications to define complex credential requirements using multiple sources and validation rules.

#### Key Structs

```solidity
struct CredentialRequirement {
    bytes32[] credentialTypeIds;
    uint256 minValidations;
    bool invert;
}

struct CredentialSource {
    address identityRegistry;
    address credentialRegistry;
    address dataValidator;
}

struct CredentialRequirementInput {
    bytes32 requirementId;
    bytes32[] credentialTypeIds;
    uint256 minValidations;
    bool invert;
}

struct CredentialSourceInput {
    bytes32 credentialTypeId;
    address identityRegistry;
    address credentialRegistry;
    address dataValidator;
}
```

#### Key Functions

```solidity
interface ICredentialRequirements {
    function addCredentialRequirement(CredentialRequirementInput memory input) external;
    function removeCredentialRequirement(bytes32 requirementId) external;
    function getCredentialRequirement(bytes32 requirementId) external view returns (CredentialRequirement memory);
    function getCredentialRequirementIds() external view returns (bytes32[] memory);

    function addCredentialSource(CredentialSourceInput memory input) external;
    function removeCredentialSource(
        bytes32 credentialTypeId,
        address identityRegistry,
        address credentialRegistry
    ) external;
    function getCredentialSources(bytes32 credentialTypeId) external view returns (CredentialSource[] memory);
}
```

#### Events

```solidity
event CredentialRequirementAdded(bytes32 indexed requirementId, bytes32[] credentialTypeIds, uint256 minValidations, bool invert);
event CredentialRequirementRemoved(bytes32 indexed requirementId, bytes32[] credentialTypeIds, uint256 minValidations, bool invert);
event CredentialSourceAdded(
    bytes32 indexed credentialTypeId,
    address indexed identityRegistry,
    address indexed credentialRegistry,
    address dataValidator
);
event CredentialSourceRemoved(
    bytes32 indexed credentialTypeId,
    address indexed identityRegistry,
    address indexed credentialRegistry,
    address dataValidator
);
```

#### Errors

```solidity
error RequirementExists(bytes32 requirementId);
error RequirementNotFound(bytes32 requirementId);
error SourceExists(bytes32 credentialTypeId, address identityRegistry, address credentialRegistry);
error SourceNotFound(bytes32 credentialTypeId, address identityRegistry, address credentialRegistry);
error InvalidConfiguration(string errorReason);
```

### IIdentityValidator

**File:** [`src/interfaces/IIdentityValidator.sol`](../src/interfaces/IIdentityValidator.sol)

The `IIdentityValidator` provides a unified interface for applications to validate user accounts against defined credential requirements.

#### Key Functions

```solidity
interface IIdentityValidator {
    function validate(address account, bytes calldata context) external view returns (bool);
}
```

#### Critical Requirements

**Non-Reverting Guarantee:** The `validate` function and all other view functions in `IIdentityValidator` implementations **MUST NOT revert under any circumstances**. This requirement is critical to ensure reliable interactions with IdentityValidator contracts.

Implementations must use defensive programming patterns such as try-catch blocks around external calls to gracefully handle failures and return appropriate boolean results rather than allowing reverts to propagate.

## Data Validation Interface

### ICredentialDataValidator

**File:** [`src/interfaces/ICredentialDataValidator.sol`](../src/interfaces/ICredentialDataValidator.sol)

The `ICredentialDataValidator` is an optional interface for implementing custom validation rules on the data attached to a credential.

#### Key Functions

```solidity
interface ICredentialDataValidator {
    function validateCredentialData(
        bytes32 ccid,
        address account,
        bytes32 credentialTypeId,
        bytes calldata credentialData,
        bytes calldata context
    ) external view returns (bool);
}
```

#### Critical Requirements

**Non-Reverting Guarantee:** The `validateCredentialData` function and all other view functions in `ICredentialDataValidator` implementations **MUST NOT revert under any circumstances**. This requirement is critical to ensure reliable interactions with data validator contracts.
