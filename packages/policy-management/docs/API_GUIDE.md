# API Guide: Policy Management

This guide provides practical, task-oriented examples for the most common operations you'll perform with the Policy Management component.

## 1. Protecting a Contract Function

To protect a smart contract function with the policy system, you must perform two steps:

1.  In your contract's code, add the `runPolicy` modifier to the function.
2.  Connect your contract instance to a `PolicyEngine` instance.

### Step 1.1: Applying the `runPolicy` Modifier

In your contract, import `PolicyProtected`, inherit from it, and add `runPolicy` to any function you want to secure.

```solidity
import { PolicyProtected } from "@chainlink/policy-management/core/PolicyProtected.sol";

contract MyGuardedContract is PolicyProtected {
    event ActionCompleted(address indexed caller);

    // This function is now protected by the Policy Engine.
    function protectedAction() public runPolicy {
        emit ActionCompleted(msg.sender);
    }

    function unprotectedAction() public {
        // This function is not protected and can be called freely.
    }
}
```

### Step 1.2: Connecting the Policy Engine

After deploying your contract, you must attach it to a `PolicyEngine`. This is typically done in the contract's `initialize` function.

Here is how you would write the deployment script code:

```solidity
// --- In your deployment script ---
PolicyEngine policyEngine = new PolicyEngine();
policyEngine.initialize(IPolicyEngine.PolicyResult.Allowed); // Recommended default

MyGuardedContract myContract = new MyGuardedContract();

// The initialize function calls __PolicyProtected_init to set the engine
myContract.initialize(OWNER_ADDRESS, address(policyEngine));
```

## 2. Configuring Policies for a Function

Once the engine is attached, you can add one or more policies to any protected function. A policy can either be self-contained or it can be designed to receive parameters extracted from the function call.

### Step 2.1: Adding a Policy Without Parameters

**The Goal:** You want to add a policy that does not require any data from the function it is protecting (e.g., checking the `msg.sender` against an internal access list).

**The Action:** In your deployment script, deploy the policy and use `policyEngine.addPolicy()`. The final argument, `policyParameterNames`, will be an empty array.

```solidity
// --- In your deployment script ---

// Deploy a policy that doesn't need parameters, like OnlyOwnerPolicy
OnlyOwnerPolicy onlyOwnerPolicy = new OnlyOwnerPolicy();
onlyOwnerPolicy.initialize(address(policyEngine), OWNER_ADDRESS, "");

// Get the function selector
bytes4 selector = myContract.protectedAction.selector;

// Add the policy to the engine's registry for that function
policyEngine.addPolicy(
    address(myContract),      // The target contract
    selector,                 // The function selector
    address(onlyOwnerPolicy), // The policy contract address
    new bytes32[](0)          // An empty array for parameter names
);
```

### Step 2.2: Adding a Policy That Requires Parameters

**The Goal:** You want to add a policy that makes a decision based on the arguments of the function call (e.g., checking the `value` of an ERC20 `transfer`).

**The Actions:** This is a two-step process in your deployment script.

1.  First, you must register an `Extractor` contract that knows how to parse the parameters for that function's signature.
2.  Second, when you call `addPolicy`, you must specify which of the extracted parameters your policy needs.

Here is how you would write the deployment script code:

```solidity
// --- In your deployment script ---

// Action 1: Set the Extractor for the transfer function
ERC20TransferExtractor transferExtractor = new ERC20TransferExtractor();
bytes4 transferSelector = myToken.transfer.selector;
policyEngine.setExtractor(transferSelector, address(transferExtractor));

// Action 2: Add a policy that uses an extracted parameter
VolumePolicy volumePolicy = new VolumePolicy();
// ... initialize volumePolicy with a volume limit ...

// Create a list of the parameter names this policy needs.
// These names MUST match the names defined in the ERC20TransferExtractor.
bytes32[] memory policyParams = new bytes32[](1);
policyParams[0] = transferExtractor.PARAM_VALUE(); // e.g., keccak256("value")

// Add the policy and specify the parameters it requires
policyEngine.addPolicy(
    address(myToken),
    transferSelector,
    address(volumePolicy),
    policyParams
);
```

The `PolicyEngine` will now automatically call the `ERC20TransferExtractor`, find the `value` parameter, and pass it to the `VolumePolicy` for every `transfer` call.

### Step 2.3: Reusing a Policy on a Different Function

A powerful feature of the system is policy reuse. You can apply the same policy contract to multiple different functions, even if those functions have different parameters.

**The Goal:** Imagine you have a [`SanctionsPolicy`](../../../getting_started//SanctionsPolicy.sol) already checking the `to` address on `transfer` calls. Now, you also want to block minting directly to a sanctioned address.

**The Action:** You will call `addPolicy` again, this time targeting the `mint` selector. You will provide the name of the parameter from the `mint` function's extractor that corresponds to the address you want to check.

```solidity
// --- In your deployment script ---

// Assume `sanctionsPolicy` and `mintBurnExtractor` are already deployed.

// 1. Define WHICH parameter the SanctionsPolicy needs for THIS attachment.
//    The mint function's extractor calls the recipient parameter "account".
bytes32[] memory mintSanctionsParams = new bytes32[](1);
mintSanctionsParams[0] = mintBurnExtractor.PARAM_ACCOUNT(); // This is keccak256("account")

// 2. Add the SAME sanctionsPolicy to the MINT selector.
policyEngine.addPolicy(
    address(myToken),
    myToken.mint.selector,     // Applying to the MINT function
    address(sanctionsPolicy),  // Re-using the same deployed policy instance
    mintSanctionsParams        // Specifying the "account" parameter is needed here
);
```

The same `sanctionsPolicy` instance now protects both the `transfer` and `mint` functions, receiving the correct address to check from two different extractors, all configured through the `PolicyEngine`.

## 3. Setting a Default Result

**The Goal:** You want to define the engine's behavior for the case where a transaction passes through all of a function's policies without any of them returning a definitive `Allowed` or `Rejected`.

**The Recommendation:** For most development and production scenarios, it is **recommended to set the default to `Allowed`**.

**The Action:** In your deployment script, call `policyEngine.setDefaultResult()`.

```solidity
// --- In your deployment script ---

// Set the default result for the entire engine.
policyEngine.setDefaultResult(IPolicyEngine.PolicyResult.Allowed);
```

### Rationale and Alternative Approaches

There are two primary philosophies for the default behavior of a policy system.

1.  **Default `Allowed` (Recommended):**

    - **Pros:** This approach maintains the regular, expected behavior of your contract's functions until you decide which specific protections are required. It allows you to start with a working system and progressively layer on restrictions (`Reject` policies) as needed.
    - **Cons:** You must be diligent in protecting all new, sensitive functions. If you add a protected function but forget to add a policy, it will be open by default.

2.  **Default `Rejected` (Alternative "Fail-Safe" Approach):**
    - **Pros:** This is a more aggressive security posture. It ensures that no transaction can pass unless a policy explicitly permits it, which prevents new or misconfigured functions from being accidentally exposed.
    - **Cons:** This model forces you to have at least one policy in every chain that returns `Allowed`, which can add complexity.

## 4. Using the `context` Parameter

**The Goal:** You need to pass arbitrary, transaction-specific data (like an offchain signature or Merkle proof) to a policy for validation.

**The Actions:** There are two methods to achieve this, depending on your use case. The recommended method is to pass the `context` directly as a function argument.

### Step 4.1: The Custom Policy (Common to Both Methods)

First, write a policy that is designed to receive and decode data from the `context` argument of its `run()` function. This `SignaturePolicy` is a common example.

```solidity
// Assumes usage of OpenZeppelin's ECDSA library
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignaturePolicy is Policy {
    address public requiredSigner;

    // ... constructor to set the requiredSigner ...

    function run(
        address caller,
        address, // subject
        bytes4, // selector
        bytes[] calldata, // parameters
        bytes calldata context
    ) public view virtual override returns (IPolicyEngine.PolicyResult) {
        require(context.length > 0, "SignaturePolicy: context cannot be empty");

        // Create the same message hash that was signed offchain
        bytes32 messageHash = keccak256(abi.encodePacked("I approve this transaction for:", caller));
        bytes32 signedHash = ECDSA.toEthSignedMessageHash(messageHash);

        address recoveredSigner = ECDSA.recover(signedHash, context);

        if (recoveredSigner == requiredSigner) {
            return IPolicyEngine.PolicyResult.Continue;
        }

        return IPolicyEngine.PolicyResult.Rejected;
    }
}
```

### Step 4.2: Passing Context Directly (Recommended Pattern)

For your own custom functions, the cleanest and safest pattern is to pass the `context` directly as a function argument using the `runPolicyWithContext` modifier.

**The Action:** Create a custom function that accepts `context` as its final argument and protect it with the `runPolicyWithContext` modifier.

```solidity
// In your custom contract...
contract MyCustomContract is PolicyProtected {
    // ...
    function doSomethingSpecialWithApproval(
        uint256 arg1,
        bytes calldata context // The extra data is a direct argument
    )
        public
        runPolicyWithContext(context) // The modifier receives the context directly
    {
        // Your core logic here...
    }
}

// In your calling transaction (e.g., a script or front-end):
// The context (e.g., a signature) is prepared offchain
bytes memory signature = getSignatureFromOffChainService(sender);

// Make a single call to the protected function
myCustomContract.doSomethingSpecialWithApproval(123, signature);
```

This approach is recommended for new, custom functions as it is more explicit and gas-efficient.

### Step 4.3: Passing Context via `setContext` (For Standard Interfaces)

If you need to protect a function with a standard, unchangeable signature (like ERC20 `transfer`), you **must** use the two-step `setContext` method.

**The Action:** The offchain client or calling contract must set the context for the `msg.sender` and then call the protected function within the same transaction.

```solidity
// In a test or script, using a multicall pattern:

// 1. Offchain: A trusted party signs a message approving the transaction for the sender.
//    (This signature is the `context` bytes)
bytes memory signature = getSignatureFromOffChainService(sender);

// 2. Onchain: In a single atomic transaction:
//    a. Set the context for the sender
myContract.setContext(signature);
//    b. Call the protected function
myContract.protectedAction();
```

The `PolicyProtected` contract provides the `setContext` and `clearContext` functions. After a transaction that uses `setContext`, it is the responsibility of the caller or a subsequent process to clear the context to prevent it from being reused.

> **Security Note:** This method stores the context on a per-sender basis. It is **strongly recommended** to set and consume the context in the same atomic transaction to avoid potential race conditions or stale context being reused. **[Learn more about the security implications.](./SECURITY.md#4-context-handling-and-race-conditions)**

## Common Design Patterns

The Policy Management component enables several powerful, high-level design patterns for building robust and flexible systems.

### Pattern: Securing Core Infrastructure with Policies

The `PolicyEngine` is not just for protecting your main application contract (e.g., your token). You can and should use it to govern the administrative functions of the other components in your system, such as the `IdentityRegistry` and `CredentialRegistry` (learn more about the [Cross-Chain Identity](../../cross-chain-identity/README.md) component).

This creates a unified, consistent security model for your entire dApp ecosystem.

- **The Goal:** Ensure that only authorized addresses can add or remove credentials in the `CredentialRegistry`.
- **The Implementation:**
  1.  When you deploy the `CredentialRegistry`, you set its owner to be the `PolicyEngine` contract. This means all administrative actions must now pass through the engine.
  2.  You deploy a policy, such as `OnlyAuthorizedSenderPolicy`, which maintains a list of trusted addresses (e.g., your KYC provider).
  3.  In the `PolicyEngine`, you use `addPolicy` to apply this `OnlyAuthorizedSenderPolicy` to the administrative functions of the `CredentialRegistry` (e.g., `registerCredential`, `removeCredential`).
  4.  **The Result:** The `CredentialRegistry` is now fully protected. No one, not even the original deployer, can manage credentials unless they are explicitly added to the authorized senders list in the policy, creating a robust and auditable separation of roles.
