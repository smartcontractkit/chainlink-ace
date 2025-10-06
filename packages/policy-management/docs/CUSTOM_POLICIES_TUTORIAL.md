# Tutorial: Creating a Custom Policy

This tutorial will guide you through the process of creating your own custom policy from scratch. We will build a simple `LockoutPolicy` that blocks transactions from an address for a specified period of time.

This will teach you the core principles of policy development and provide a template for your own, more complex policies.

> **Note:** A clean, copy-pasteable boilerplate template is available at the end of this tutorial for you to use as a starting point.

## Step 1: The Policy Contract Boilerplate

Every policy must inherit from the base `Policy` contract and implement the `run` function. Let's create our file `LockoutPolicy.sol` with the basic structure.

**`LockoutPolicy.sol`**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Policy } from "@chainlink/policy-management/core/Policy.sol";
import { IPolicyEngine } from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";

contract LockoutPolicy is Policy {
    // Our policy's logic will go here.

    function run(
        address caller,
        address subject,
        bytes4 selector,
        bytes[] calldata parameters,
        bytes calldata context
    ) public view virtual override returns (IPolicyEngine.PolicyResult) {
        // Our enforcement logic will go here.
        return IPolicyEngine.PolicyResult.Continue; // Default to Continue
    }
}
```

This is the simplest possible policy. It doesn't do anything yet, but it's a valid, compilable policy contract.

## Step 2: Adding State and Logic

Our `LockoutPolicy` needs to store two pieces of information for each locked-out address: the address itself, and the Unix timestamp when their lockout period expires. We'll use a `mapping` for this.

We also need a public function that the policy owner can call to add or update a lockout.

```solidity
// ... imports ...

contract LockoutPolicy is Policy {
    mapping(address => uint256) public lockoutExpiresAt;

    /// @notice The policy owner can call this to lock an address.
    /// @param account The address to lock out.
    /// @param duration The duration of the lockout, in seconds.
    function setLockout(address account, uint256 duration) public onlyOwner {
        lockoutExpiresAt[account] = block.timestamp + duration;
    }

    function run(
        address caller,
        address, // subject
        bytes4, // selector
        bytes[] calldata, // parameters
        bytes calldata // context
    ) public view virtual override returns (IPolicyEngine.PolicyResult) {
        // We only care about the original sender of the transaction.
        if (lockoutExpiresAt[caller] > block.timestamp) {
            // If the sender's lockout period is still active, reject.
            return IPolicyEngine.PolicyResult.Rejected;
        }

        // Otherwise, continue to the next policy.
        return IPolicyEngine.PolicyResult.Continue;
    }
}
```

Our policy now has logic! It checks if the `sender` of the transaction is trying to transact before their `lockoutExpiresAt` timestamp has been reached. If they are, it rejects the transaction. Otherwise, it takes no action and lets the `PolicyEngine` continue to the next policy.

## Step 3: Input Validation (A Critical Best Practice)

What if our policy needed to check a parameter from the transaction data? For example, what if we wanted to lock out the `recipient` of a transfer instead of the `sender`?

The policy would receive the recipient's address in the `parameters` array. It is a **critical best practice to always validate the inputs** your policy receives.

Let's modify our `run` function to expect the `recipient` as a parameter and add the necessary `require` check.

```solidity
// ...
    function run(
        address, // caller
        address, // subject
        bytes4, // selector
        bytes[] calldata parameters,
        bytes calldata // context
    ) public view virtual override returns (IPolicyEngine.PolicyResult) {
        // BEST PRACTICE: Always validate your expected inputs.
        // This prevents reverts and ensures your policy is used correctly.
        require(parameters.length == 1, "LockoutPolicy: Expected 1 parameter");

        // Decode the address from the parameters array.
        address recipient = abi.decode(parameters[0], (address));

        if (lockoutExpiresAt[recipient] > block.timestamp) {
            return IPolicyEngine.PolicyResult.Rejected;
        }

        return IPolicyEngine.PolicyResult.Continue;
    }
// ...
```

This `require` statement makes our policy more robust. It provides a clear error message if the policy is ever misconfigured in the `PolicyEngine` without the required parameter, which makes debugging much easier.

## Step 4: Using Your Custom Policy

Now your `LockoutPolicy` is complete. Using it follows the same pattern as any pre-built policy.

In your deployment script:

1.  **Deploy it**: `LockoutPolicy lockoutPolicy = new LockoutPolicy();`
2.  **Initialize it**: `lockoutPolicy.initialize(address(policyEngine), OWNER_ADDRESS, new bytes(0));`
    > **What is the `new bytes(0)` parameter?**
    >
    > The third argument of the `initialize` function is a `bytes` array called `configParams`. It's a the feature for passing initial setup data to more complex policies (e.g., setting a volume limit for a [`VolumePolicy`](../src/policies/VolumePolicy.sol)). Since our `LockoutPolicy` doesn't need any initial configuration, we pass an empty byte array to explicitly provide no parameters. The `initialize` function passes these bytes to an internal `configure` function, which you can override to handle this data in your own policies.
3.  **Add it to the engine**: To use the version of our policy that checks the `recipient`, you must specify the parameter name. Assume we have an [`ERC20TransferExtractor`](../src/extractors/ERC20TransferExtractor.sol) registered for our target function.

    ```solidity
    // Define the parameter name your policy needs
    bytes32[] memory policyParams = new bytes32[](1);
    policyParams[0] = keccak256("to"); // This must match the name from the Extractor

    // Add the policy to the engine and specify its required parameter
    policyEngine.addPolicy(
        address(myContract),
        myContract.transfer.selector,
        address(lockoutPolicy),
        policyParams
    );
    ```

You can then call `lockoutPolicy.setLockout(LOCKED_ADDRESS, 3600)` to block a recipient for one hour. Any transfer to that address will be rejected.

You now have a complete, secure, and reusable custom policy and the knowledge needed to create many more!

## Boilerplate Template for Custom Policies

Here is a clean, commented template that you can use as a starting point for your own custom policies.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { Policy } from "@chainlink/policy-management/core/Policy.sol";
import { IPolicyEngine } from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";

contract MyCustomPolicy is Policy {
    /**
     * @notice Use the `configure` function to decode and store any initial
     * setup data passed into the `configParams` of the `initialize` function.
     */
    // function configure(bytes calldata parameters) internal override onlyInitializing {
    //     // Your custom initialization logic here...
    // }

    function run(
        address caller,
        address subject,
        bytes4 selector,
        bytes[] calldata parameters,
        bytes calldata context
    ) public view virtual override returns (IPolicyEngine.PolicyResult) {
        // Your custom validation logic here...
        //
        // Based on your logic, return one of the three possible results.

        // Use REJECTED to definitively block the transaction.
        // This HALTS execution and bypasses all subsequent policies.
        // if (condition_for_rejection) {
        //     return IPolicyEngine.PolicyResult.Rejected;
        // }

        // Use ALLOWED to definitively approve the transaction.
        // This ALSO HALTS execution and bypasses all subsequent policies.
        // This is powerful and should be used with care (e.g., for an admin bypass).
        // if (condition_for_allowance) {
        //     return IPolicyEngine.PolicyResult.Allowed;
        // }

        // Use CONTINUE if your check passes but other policies in the chain should still be executed.
        // This is the most common return value for a passing check.
        return IPolicyEngine.PolicyResult.Continue;
    }
}
```
