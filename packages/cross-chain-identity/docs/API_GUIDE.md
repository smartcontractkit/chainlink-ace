# API Guide: Cross-Chain Identity

This guide provides practical, task-oriented examples for using the Cross-Chain Identity component as part of the integrated Chainlink ACE, secured by the Policy Management component.

## 1. Setting Up the Identity Infrastructure

The first step is to deploy the core contracts. The recommended pattern is to create a secure system where the `IdentityRegistry` and `CredentialRegistry` are governed by a `PolicyEngine`.

Here is how you would write the deployment script code:

```solidity
// --- In your deployment script ---
import { PolicyEngine } from "@chainlink/policy-management/core/PolicyEngine.sol";
import { IdentityRegistry } from "@chainlink/cross-chain-identity/src/IdentityRegistry.sol";
import { CredentialRegistry } from "@chainlink/cross-chain-identity/src/CredentialRegistry.sol";

// 1. Deploy the engine that will act as the guardian
PolicyEngine policyEngine = new PolicyEngine();
bool defaultAllow = true;
policyEngine.initialize(defaultAllow, address(this)); // Recommended default

// 2. Deploy the registries and transfer their ownership to the engine
IdentityRegistry identityRegistry = new IdentityRegistry();
identityRegistry.initialize(address(policyEngine));

CredentialRegistry credentialRegistry = new CredentialRegistry();
credentialRegistry.initialize(address(policyEngine));
```

With this setup, all administrative actions on the registries (like issuing credentials) are now under the control of the `PolicyEngine`.

## Task 2: Performing Validation with `CredentialRegistryIdentityValidatorPolicy`

The primary way to check for credentials in an integrated system is with the `CredentialRegistryIdentityValidatorPolicy`. This is a specialized policy that contains all the logic needed to query the registries.

### Step 2.1: Deploy and Configure the Policy

First, deploy an instance of `CredentialRegistryIdentityValidatorPolicy`. Its `initialize` function takes the credential sources and requirements as ABI-encoded arguments.

```solidity
// --- In your deployment script ---
import { CredentialRegistryIdentityValidatorPolicy } from "@chainlink/cross-chain-identity/src/CredentialRegistryIdentityValidatorPolicy.sol";
import { ICredentialRequirements } from "@chainlink/cross-chain-identity/src/interfaces/ICredentialRequirements.sol";

// e.g.: Define the KYC credential type we will be checking for
bytes32 kycCredential = keccak256("common.kyc");

// 1. Define the Credential Source
// This tells the policy which registries to use for the "common.kyc" type.
ICredentialRequirements.CredentialSourceInput[] memory sources = new ICredentialRequirements.CredentialSourceInput[](1);
sources[0] = ICredentialRequirements.CredentialSourceInput(kycCredential, address(identityRegistry), address(credentialRegistry), address(0));

// 2. Define the Credential Requirement
// This specifies that an identity must have at least one "common.kyc" credential.
bytes32[] memory requiredCredentials = new bytes32[](1);
requiredCredentials[0] = kycCredential;
ICredentialRequirements.CredentialRequirementInput[] memory requirements = new ICredentialRequirements.CredentialRequirementInput[](1);
requirements[0] = ICredentialRequirements.CredentialRequirementInput(keccak256("requirement.KYC"), requiredCredentials, 1, false);

// 3. Deploy and initialize the policy
CredentialRegistryIdentityValidatorPolicy kycCheckPolicy = new CredentialRegistryIdentityValidatorPolicy();
kycCheckPolicy.initialize(address(policyEngine), address(this), abi.encode(sources, requirements));
```

### Step 2.2: Attach the Policy to Your Application

Next, use the `PolicyEngine` to apply your `kycCheckPolicy` to a protected function, such as an ERC20 token's `transfer` method.

```solidity
// --- In your deployment script ---
import { ERC20TransferExtractor } from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";

// 1. Register an extractor to parse the 'to' address from the transfer function
ERC20TransferExtractor transferExtractor = new ERC20TransferExtractor();
policyEngine.setExtractor(myToken.transfer.selector, address(transferExtractor));

// 2. Specify that our policy needs the 'to' parameter from the extractor
bytes32[] memory transferParams = new bytes32[](1);
transferParams[0] = transferExtractor.PARAM_TO();

// 3. Add the policy to the engine for the token's transfer function
policyEngine.addPolicy(
    address(myToken),
    myToken.transfer.selector,
    address(kycCheckPolicy),
    transferParams
);
```

Your token is now protected. All calls to `transfer()` will be automatically checked to ensure the recipient has a valid KYC credential.

## Task 3: Authorizing a Credential Issuer

The final step is to grant a trusted offchain entity (the **Credential Issuer**) permission to write to the `CredentialRegistry`.

**The Goal:** You want to allow a specific address (`verificationIssuer`) to call `registerCredential` on the `CredentialRegistry`, but no one else.

**The Action:** You deploy a simple access control policy (like `OnlyAuthorizedSenderPolicy`) and apply it to the `registerCredential` function on the registry contract itself.

```solidity
// --- In your deployment script ---
import { OnlyAuthorizedSenderPolicy } from "@chainlink/policy-management/policies/OnlyAuthorizedSenderPolicy.sol";

address verificationIssuer = 0x...; // The address of your trusted KYC provider

// 1. Deploy a policy that manages a list of authorized senders
OnlyAuthorizedSenderPolicy issuerPolicy = new OnlyAuthorizedSenderPolicy();
issuerPolicy.initialize(address(policyEngine), address(this), new bytes(0));
issuerPolicy.authorizeSender(verificationIssuer);

// 2. Apply this policy to the CredentialRegistry's `registerCredential` function
policyEngine.addPolicy(
    address(credentialRegistry),
    credentialRegistry.registerCredential.selector,
    address(issuerPolicy),
    new bytes32[](0) // No parameters needed for this policy
);
```

Your system is now fully configured. The `verificationIssuer` is the only entity that can issue KYC credentials, and your `myToken` contract will automatically enforce that all recipients of a transfer possess one.
