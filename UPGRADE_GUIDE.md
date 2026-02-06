# Upgrading Existing Contracts to Use Chainlink ACE

This guide helps you upgrade an existing deployed contract to use Chainlink ACE compliance capabilities. By following this guide, you can add dynamic, policy-based compliance to your production contracts without disrupting existing functionality.

## Overview

Upgrading your contract to use ACE involves three main steps:

1. **Update your implementation contract** — Add ACE integration code
1. **Set up ACE infrastructure** — Deploy PolicyEngine, policies, and extractors (if needed)
1. **Execute the upgrade** — Deploy and upgrade via your proxy

**What You'll Learn:**

- How to safely upgrade your contract to include ACE
- Two architectural approaches for integration
- Step-by-step implementation with code examples

**Who This Is For:**

- Teams with existing deployed contracts (tokens, vaults, DEXs, etc.)
- Development teams planning compliance upgrades

> **Note:** This guide uses an ERC-20 token as the primary example, but the same patterns apply to any contract you want to policy-protect.

> **Not deployed yet?** If your contract isn't deployed, you don't need an upgrade — just integrate ACE directly. See the [Getting Started Guide](./getting_started/GETTING_STARTED.md).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Update Your Implementation Contract](#step-1-update-your-implementation-contract)
  - [Key Concept: Storage Safety (ERC-7201)](#key-concept-storage-safety-erc-7201)
  - [Choosing Your Approach](#choosing-your-approach)
  - [Approach 1: Extend PolicyProtectedUpgradeable](#approach-1-extend-policyprotectedupgradeable)
  - [Approach 2: Implement IPolicyProtected](#approach-2-implement-ipolicyprotected)
- [Step 2: Set Up ACE Infrastructure](#step-2-set-up-ace-infrastructure)
- [Step 3: Execute the Upgrade](#step-3-execute-the-upgrade)
  - [Pre-Upgrade Checklist](#pre-upgrade-checklist)
  - [Upgrade Execution](#upgrade-execution)
  - [Post-Upgrade Verification](#post-upgrade-verification)
- [FAQ](#faq)
- [Next Steps](#next-steps)

## Prerequisites

### Familiarity with ACE Concepts

This guide assumes you understand some basic ACE concepts:

- **PolicyEngine** — The central orchestrator that manages policies
- **Policies** — Modular contracts that define compliance rules
- **Extractors** — Contracts that parse function calldata into named parameters

If these concepts are new to you, start with the [Policy Management Guide](./packages/policy-management/README.md).

### Your Contract Must Be Upgradeable

This guide focuses on upgradeable contracts using a [proxy pattern](https://docs.openzeppelin.com/contracts/5.x/api/proxy) (UUPS, Transparent Proxy, or Beacon Proxy).

**Required:**

- Contract uses a proxy pattern
- You have upgrade authority over the contract

### Non-Upgradeable Contracts

If your contract is **not upgradeable**, integration requires alternative approaches. Examples:

- **Wrapped Contract** — Issue an ACE-compliant wrapper
- **Contract Migration** — Re-issue as an ACE-native contract with a migration path
- **Edge Protection** — Apply ACE controls at integration points rather than the contract itself

These approaches involve significant tradeoffs. **Please [contact the Chainlink team](https://chain.link/ace-early-access)** to discuss which option fits your requirements.

> The remainder of this guide focuses on upgradeable contracts.

## Step 1: Update Your Implementation Contract

This step modifies your implementation contract to integrate ACE. Before choosing an approach, understand this key concept:

### Key Concept: Storage Safety (ERC-7201)

When upgrading a contract, you need to avoid storage collisions — new variables overwriting existing state. [`PolicyProtectedUpgradeable`](./packages/policy-management/src/core/PolicyProtectedUpgradeable.sol) uses [ERC-7201 namespaced storage](https://eips.ethereum.org/EIPS/eip-7201), which stores ACE data in an isolated storage slot that cannot collide with your existing state.

```solidity
// ACE storage is isolated in a deterministic slot
bytes32 private constant STORAGE_LOCATION =
    keccak256(abi.encode(uint256(keccak256("chainlink.ace.PolicyProtected")) - 1))
    & ~bytes32(uint256(0xff));
```

This formula is designed to produce a storage location that **cannot** overlap with Solidity's default storage layout, guaranteeing collision-free storage. The new ACE variables won't overwrite any of your existing storage slots.

### Choosing Your Approach

**Approach 1: Extend `PolicyProtectedUpgradeable`**

Inherit from [`PolicyProtectedUpgradeable`](./packages/policy-management/src/core/PolicyProtectedUpgradeable.sol) and use built-in modifiers. This gives you:

- `runPolicy` and `runPolicyWithContext` modifiers
- Automatic storage management (ERC-7201)
- Automatic context handling

**Best for:** Most teams. Lower effort, proven patterns. Adds ~5-6KB to bytecode (varies based on number of protected functions).

**Approach 2: Implement IPolicyProtected**

Implement the [`IPolicyProtected`](./packages/policy-management/src/interfaces/IPolicyProtected.sol) interface yourself. This gives you:

- Full control over storage, context, and policy execution
- Minimal bytecode impact (~1-2KB)

**Best for:** Teams near the 24KB bytecode limit or needing custom behavior.

### Which Should You Choose?

> **Recommendation:** Use Approach 1 unless you have a specific reason not to. Approach 2 requires more code, is more error-prone, and should only be used when bytecode constraints or custom requirements demand it.

**Use Approach 1** unless one of these applies:

- Your contract is near the 24KB limit and bytecode size is a concern (can't afford ~5-6KB of additional bytecode)
- You need full control over how [context](./packages/policy-management/docs/CONCEPTS.md#the-context-parameter-a-flexible-data-channel) is stored or policies are executed (advanced)

### Comparison

| Aspect              | Approach 1: Extend PolicyProtectedUpgradeable                         | Approach 2: Implement IPolicyProtected |
| ------------------- | --------------------------------------------------------------------- | -------------------------------------- |
| **Bytecode Impact** | +5-6KB (depending on optimizer level and number of protected methods) | +1-2KB                                 |
| **Implementation**  | Add inheritance + modifiers                                           | Write storage, context, execution      |
| **Maintenance**     | Inherit ACE updates automatically                                     | You maintain all custom code           |
| **Risk**            | Lower (proven patterns)                                               | Higher (custom code = custom bugs)     |

---

### Approach 1: Extend `PolicyProtectedUpgradeable`

This is the recommended approach for most use cases. Your contract inherits from `PolicyProtectedUpgradeable`, which provides the built-in modifiers and storage management described above.

#### Implementation Steps

##### 1. Update Contract Inheritance

Add `PolicyProtectedUpgradeable` to your inheritance chain.

Before:

```solidity
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract MyToken is ERC20Upgradeable, OwnableUpgradeable {
    // ...
}
```

After:

```solidity
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {PolicyProtectedUpgradeable} from "@chainlink/policy-management/core/PolicyProtectedUpgradeable.sol";

contract MyToken is PolicyProtectedUpgradeable, ERC20Upgradeable {
    // ...
}
```

> **Inheritance note:** `PolicyProtectedUpgradeable` already inherits from `Initializable` and `OwnableUpgradeable`. If your contract explicitly lists these, **remove them** from your inheritance list to avoid a "Linearization of inheritance graph impossible" error.

##### 2. Add Migration Function

For an already-deployed contract, you cannot modify `initialize()` — it has already been called. Instead, add a migration function using `reinitializer`:

```solidity
/// @notice Migrates the contract to use ACE policy protection.
/// @dev Can only be called once. Call this after upgrading the implementation.
/// @param policyEngine The address of the PolicyEngine contract.
function migrateToACE(address policyEngine) public reinitializer(2) onlyOwner {
    __PolicyProtected_init_unchained(policyEngine);
}
```

**Why `reinitializer(2)`?**

- Your original `initialize()` used version 1
- `reinitializer(2)` ensures this migration runs exactly once
- If you've had previous upgrades with reinitializers, increment accordingly
- Available for all proxy types (UUPS, Transparent, Beacon)

**What does `__PolicyProtected_init_unchained()` do?**

This function internally calls `_attachPolicyEngine()`, which:

- Stores the PolicyEngine address in namespaced storage
- Registers your contract with the PolicyEngine

**Changing PolicyEngine later:**

If you need to switch to a different PolicyEngine after migration, use `attachPolicyEngine()` (`onlyOwner`):

```solidity
myContract.attachPolicyEngine(newPolicyEngineAddress);
```

##### 3. Add runPolicy to Protected Functions

Add the `runPolicy` modifier to functions that need policy protection. Example:

Before:

```solidity
function mint(address to, uint256 amount) public onlyOwner {
    _mint(to, amount);
}

function transfer(address to, uint256 amount) public virtual override returns (bool) {
    return super.transfer(to, amount);
}
```

After:

```solidity
function mint(address to, uint256 amount) public runPolicy {
    _mint(to, amount);
}

function transfer(address to, uint256 amount) public virtual override runPolicy returns (bool) {
    return super.transfer(to, amount);
}
```

> **Note:** Access control (e.g., restricting who can mint) is enforced through policies like [`OnlyOwnerPolicy`](./packages/policy-management/src/policies/OnlyOwnerPolicy.sol), not through traditional `onlyOwner` modifiers. This gives you flexibility to change access rules without upgrading your contract.

**For functions that need additional [context](./packages/policy-management/docs/CONCEPTS.md#the-context-parameter-a-flexible-data-channel)** (signatures, proofs), use `runPolicyWithContext`:

```solidity
function forceTransfer(
    address from,
    address to,
    uint256 amount,
    bytes calldata context
)
    public
    runPolicyWithContext(context)
{
    _update(from, to, amount);
    emit ForceTransfer(from, to, amount);
}
```

#### Complete Before/After Example

**Before (existing token implementation — example from OpenZeppelin):**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract MyToken is Initializable, ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) public initializer {
        __ERC20_init("MyToken", "MTK");
        __Ownable_init(initialOwner);
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
```

**After (with ACE integration):**

In this example, we protect `mint`, `transfer`, and `transferFrom`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PolicyProtectedUpgradeable} from "@chainlink/policy-management/core/PolicyProtectedUpgradeable.sol";

contract MyToken is PolicyProtectedUpgradeable, ERC20Upgradeable, UUPSUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) public initializer {
        __ERC20_init("MyToken", "MTK");
        __Ownable_init(initialOwner);
    }

    /// @notice Migrates to ACE. Call once after upgrading implementation.
    function migrateToACE(address policyEngine) public reinitializer(2) onlyOwner {
        __PolicyProtected_init_unchained(policyEngine);
    }

    function mint(address to, uint256 amount) public runPolicy {
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount)
        public
        virtual
        override
        runPolicy
        returns (bool)
    {
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount)
        public
        virtual
        override
        runPolicy
        returns (bool)
    {
        return super.transferFrom(from, to, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
```

**Key changes:**

1. Import and inherit `PolicyProtectedUpgradeable` (if your contract explicitly inherits from `Initializable` or `OwnableUpgradeable`, remove them — they're inherited through `PolicyProtectedUpgradeable`)
1. Add `migrateToACE()` function with `reinitializer(n)` (where `n` is your next version number — see [Add Migration Function](#2-add-migration-function))
1. Add `runPolicy` or `runPolicyWithContext` modifier to functions that need policy protection

**Next step:** Your implementation contract is ready. Proceed to [Step 2: Set Up ACE Infrastructure](#step-2-set-up-ace-infrastructure).

### Approach 2: Implement IPolicyProtected

Choose this approach if you need minimal bytecode impact or custom policy execution patterns.

#### What You're Responsible For

Instead of inheriting `PolicyProtectedUpgradeable` ([Approach 1](#approach-1-extend-policyprotectedupgradeable)), you implement the `IPolicyProtected` interface directly:

```solidity
import {IPolicyProtected} from "@chainlink/policy-management/interfaces/IPolicyProtected.sol";

contract MyToken is ERC20Upgradeable, OwnableUpgradeable, IPolicyProtected {
    // You must implement all interface methods
}
```

**You must implement:**

1. **Storage** — Storing PolicyEngine address and context
1. **Policy execution** — Calling `policyEngine.run()` in protected functions
1. **Context handling** — Managing context storage and clearing
1. **Attach/detach** — Registering with PolicyEngine
1. **ERC-165 support** — `supportsInterface()` (required by `IPolicyProtected`)

#### Interface Methods

```solidity
interface IPolicyProtected {
    function attachPolicyEngine(address policyEngine) external;
    function getPolicyEngine() external view returns (address);
    function setContext(bytes calldata context) external;
    function getContext() external view returns (bytes memory);
    function clearContext() external;
}
```

| Method               | Purpose                                                              |
| -------------------- | -------------------------------------------------------------------- |
| `attachPolicyEngine` | Registers your contract with a PolicyEngine                          |
| `getPolicyEngine`    | Returns the current PolicyEngine address                             |
| `setContext`         | Stores context data (signatures, proofs) for the next protected call |
| `getContext`         | Retrieves stored context for the current caller                      |
| `clearContext`       | Clears context after use (prevents replay)                           |

#### Implementation Skeleton

The skeleton below shows a complete implementation using the same ERC-20 token example from [Approach 1's "Before" code](#complete-beforeafter-example). You'll need two imports:

- **`IPolicyProtected`** — the interface your contract implements
- **`IPolicyEngine`** — needed to call `run()` for policy checks and `attach()` for registration

> **Storage Warning:** When upgrading an existing contract, you must avoid storage collisions. The safest approach is to use ERC-7201 namespaced storage (shown below). If you use regular storage variables, they must be declared **after** all existing variables in your contract.

```solidity
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IPolicyProtected} from "@chainlink/policy-management/interfaces/IPolicyProtected.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

contract MyToken is Initializable, ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable, IPolicyProtected {

    // =========== ERC-7201 Namespaced Storage ===========

    /// @custom:storage-location erc7201:mytoken.ace.storage
    struct ACEStorage {
        address policyEngine;
        mapping(address => bytes) senderContext;
    }

    // Storage slot calculated using ERC-7201 formula (see note below)
    bytes32 private constant ACE_STORAGE_LOCATION =
        0x...; // Replace with your calculated value

    function _getACEStorage() private pure returns (ACEStorage storage $) {
        assembly {
            $.slot := ACE_STORAGE_LOCATION
        }
    }

    // =========== Constructor ===========

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) public initializer {
        __ERC20_init("MyToken", "MTK");
        __Ownable_init(initialOwner);
    }

    // =========== Migration ===========

    /// @notice Migrates to ACE. Call once after upgrading implementation.
    function migrateToACE(address policyEngine) public reinitializer(2) onlyOwner {
        _attachPolicyEngine(policyEngine);
    }

    // =========== IPolicyProtected Implementation ===========

    function attachPolicyEngine(address policyEngine) external onlyOwner {
        _attachPolicyEngine(policyEngine);
    }

    function _attachPolicyEngine(address policyEngine) internal {
        require(policyEngine != address(0), "Policy engine is zero address");
        ACEStorage storage $ = _getACEStorage();
        $.policyEngine = policyEngine;
        IPolicyEngine(policyEngine).attach();
        emit PolicyEngineAttached(policyEngine);
    }

    function getPolicyEngine() public view returns (address) {
        return _getACEStorage().policyEngine;
    }

    function setContext(bytes calldata context) external {
        _getACEStorage().senderContext[msg.sender] = context;
    }

    function getContext() public view returns (bytes memory) {
        return _getACEStorage().senderContext[msg.sender];
    }

    function clearContext() public {
        delete _getACEStorage().senderContext[msg.sender];
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IPolicyProtected).interfaceId ||
               interfaceId == type(IERC165).interfaceId;
    }

    // =========== Policy Execution ===========
    // Use _runPolicy() when context is pre-stored via setContext()
    // Use _runPolicyWithContext() when context is passed directly as a parameter

    function _runPolicy() internal {
        ACEStorage storage $ = _getACEStorage();
        require($.policyEngine != address(0), "PolicyEngine undefined");

        bytes memory context = getContext();
        IPolicyEngine($.policyEngine).run(
            IPolicyEngine.Payload({
                selector: msg.sig,
                sender: msg.sender,
                data: msg.data[4:],
                context: context
            })
        );

        if (context.length > 0) {
            clearContext();
        }
    }

    function _runPolicyWithContext(bytes calldata context) internal {
        ACEStorage storage $ = _getACEStorage();
        require($.policyEngine != address(0), "PolicyEngine undefined");

        IPolicyEngine($.policyEngine).run(
            IPolicyEngine.Payload({
                selector: msg.sig,
                sender: msg.sender,
                data: msg.data[4:],
                context: context
            })
        );
    }

    // =========== Protected Functions ===========

    function mint(address to, uint256 amount) public {
        _runPolicy();
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        _runPolicy();
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        _runPolicy();
        return super.transferFrom(from, to, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
```

> **Calculating your ERC-7201 storage location:**
>
> The `ACE_STORAGE_LOCATION` constant ensures your new storage variables don't collide with existing contract storage. To calculate it:
>
> 1. Choose a unique namespace string (e.g., `"mycompany.mytoken.ace.storage"`)
> 2. Apply the [ERC-7201](https://eips.ethereum.org/EIPS/eip-7201) formula:
>    ```
>    keccak256(abi.encode(uint256(keccak256("your.namespace.here")) - 1)) & ~bytes32(uint256(0xff))
>    ```
> 3. See [`PolicyProtectedUpgradeable.sol`](./packages/policy-management/src/core/PolicyProtectedUpgradeable.sol) for a working reference implementation
>
> The `@custom:storage-location` NatSpec comment should match your namespace string.

This is more complex than Approach 1, which handles all of this automatically.

#### Tradeoffs

| Benefit                   | Tradeoff                        |
| ------------------------- | ------------------------------- |
| Minimal bytecode (+1-2KB) | More code to write and maintain |
| Maximum flexibility       | No automatic updates from ACE   |
| Custom optimizations      | Greater testing responsibility  |

**Next step:** Your implementation contract is ready. Proceed to [Step 2: Set Up ACE Infrastructure](#step-2-set-up-ace-infrastructure).

## Step 2: Set Up ACE Infrastructure

At this point, you've updated your implementation contract:

- Added inheritance (`PolicyProtectedUpgradeable` or `IPolicyProtected`)
- Created a `migrateToACE()` function that will attach a PolicyEngine
- Added policy checks to functions that need protection (via `runPolicy` modifier with Approach 1 or manual `_runPolicy()` calls with Approach 2)

Now, before deploying and calling `migrateToACE()`, you need ACE infrastructure in place.

> **Already have ACE infrastructure?** If your organization has an existing PolicyEngine with policies configured, you just need its address for `migrateToACE()`. Skip to [Step 3: Execute the Upgrade](#step-3-execute-the-upgrade).

> **Note:** This guide focuses on upgrading your contract, not on deploying ACE infrastructure. The links below point to dedicated guides that cover infrastructure setup in detail.

Your `migrateToACE()` function will attach your contract to a PolicyEngine. You need:

1. **PolicyEngine** — The central orchestrator that manages policies. Your `migrateToACE()` function needs this address.
   - [What is a PolicyEngine?](./packages/policy-management/README.md#core-components)

1. **Policies** — Define your compliance rules. They must be deployed and added to the PolicyEngine.
   - [Available policies](./packages/policy-management/src/policies/README.md)
   - [Custom policy tutorial](./packages/policy-management/docs/CUSTOM_POLICIES_TUTORIAL.md)

1. **Extractors (if needed)** — Parse function calldata into named parameters. You need them if your policies inspect function arguments (e.g., transfer amounts, recipient addresses).
   - [Available extractors](./packages/policy-management/src/extractors/) (covers common ERC20/ERC3643 operations)
   - [How extractors work](./packages/policy-management/docs/CONCEPTS.md#the-extractor-and-mapper-pattern)

**For deployment instructions, see the examples in the Getting Started Guides:**

- [Getting Started Guide](./getting_started/GETTING_STARTED.md) — Deploy PolicyEngine and simple policies (e.g., PausePolicy)
- [Advanced Getting Started](./getting_started/advanced/GETTING_STARTED_ADVANCED.md) — Deploy extractors and policies that inspect function parameters

## Step 3: Execute the Upgrade

You now have:

- An updated implementation contract (from Step 1)
- A deployed PolicyEngine with policies and extractors (if needed) configured (from Step 2)

Time to execute the upgrade.

### Pre-Upgrade Checklist

Before executing the upgrade, verify:

**Development:**

- [ ] Updated contract compiles successfully
- [ ] Final bytecode under 24KB limit
- [ ] Unit tests passing
- [ ] Integration tests with PolicyEngine passing

**Infrastructure:**

- [ ] PolicyEngine deployed (you have the address for `migrateToACE()`)
- [ ] Policies deployed and attached to PolicyEngine
- [ ] Extractors configured (if your policies need function parameters)
- [ ] Policy chains tested end-to-end

### Upgrade Execution

1. **Deploy new implementation**
1. **Verify implementation** on block explorer
1. **Execute upgrade + migration** (see examples per proxy type below):

   **UUPS:**

   ```solidity
   bytes memory data = abi.encodeCall(MyToken.migrateToACE, (policyEngineAddress));
   MyToken(proxyAddress).upgradeToAndCall(newImplementationAddress, data);
   ```

   **Transparent Proxy:**

   ```solidity
   bytes memory data = abi.encodeCall(MyToken.migrateToACE, (policyEngineAddress));
   ProxyAdmin(proxyAdminAddress).upgradeAndCall(proxyAddress, newImplementationAddress, data);
   ```

   **Beacon Proxy:**

   ```solidity
   // Beacon doesn't support "andCall" — do separately
   UpgradeableBeacon(beaconAddress).upgradeTo(newImplementationAddress);
   MyToken(proxyAddress).migrateToACE(policyEngineAddress);
   ```

1. **Verify state preservation** — check balances, allowances unchanged, etc.
1. **Verify policy enforcement** — test that policies are active

### Post-Upgrade Verification

**Policy integration:**

- [ ] `getPolicyEngine()` returns correct address
- [ ] Protected functions trigger policy checks
- [ ] Policies allow and reject transactions as expected

## FAQ

### Storage Collisions

**Q: Will this upgrade overwrite my existing state?**

No. `PolicyProtectedUpgradeable` uses [ERC-7201 namespaced storage](https://eips.ethereum.org/EIPS/eip-7201), which stores data in an isolated slot. Your existing state remains untouched.

**Q: How do I verify no collisions?**

If you're using Foundry:

```bash
forge inspect <contract-path>:<contract-name> storageLayout
```

Review the layout and confirm PolicyProtected uses a separate namespace.

### Bytecode Size

**Q: My contract is near the 24KB limit.**

Options:

- Use Approach 2 (IPolicyProtected) — adds only ~1-2KB
- Enable optimizer with higher runs
- Move logic to external libraries
- Split functionality into separate contracts

### Upgrade Process

**Q: What happens to existing token balances and allowances?**

All state is preserved. The upgrade replaces the implementation contract (the code), but all state — balances, allowances, etc. — lives in the proxy's storage and remains untouched. Users don't need to re-approve.

**Q: What about tokens held in external contracts (DEXs, protocols)?**

Unaffected. Your contract address doesn't change, so all integrations continue working.

### Policy Configuration

**Q: Can I protect only some functions?**

Yes. You only add `runPolicy` or `runPolicyWithContext` modifiers (or `_runPolicy()` calls in Approach 2) to functions you want to protect. Other functions continue working normally without policy checks.

**Q: Can I update policies after upgrade?**

Yes. You can add, remove, reorder, and update policies without touching your contract.

**Q: What if I need to switch to a different PolicyEngine?**

Call `attachPolicyEngine(newAddress)` (owner only). This re-registers your contract with the new PolicyEngine. Note: you cannot set the PolicyEngine to the zero address — once ACE is integrated, a PolicyEngine is always required.

**Q: How many policies can I add?**

PolicyEngine supports up to 8 policies per function.

### Compatibility

**Q: Will this break integrations?**

No. Your contract still implements standard interfaces (ERC-20, etc.). External contracts see no difference except:

- Transactions may revert if policies reject them
- Gas costs may be higher

## Next Steps

### Set Up Cross-Chain Identity

→ [Cross-Chain Identity Guide](./packages/cross-chain-identity/README.md)

### Create Custom Policies

Build policies for your specific requirements:

→ [Custom Policies Tutorial](./packages/policy-management/docs/CUSTOM_POLICIES_TUTORIAL.md)

### Review Security

Understand security implications:

→ [Policy Management Security](./packages/policy-management/docs/SECURITY.md)

## Additional Resources

- [Main README](./README.md) — ACE overview
- [Policy Management](./packages/policy-management/README.md) — Core concepts
- [Policy Ordering Guide](./packages/policy-management/docs/POLICY_ORDERING_GUIDE.md) — Managing policy chains
- [Available Policies](./packages/policy-management/src/policies/README.md) — Pre-built policies
- [ComplianceTokenERC20](./packages/tokens/erc-20/src/ComplianceTokenERC20.sol) — Reference implementation
