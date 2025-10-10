# ACE Getting Started: Integrate Policy-Based Compliance

This guide provides a fast path to integrating your smart contract with Chainlink Automated Compliance Engine (ACE).

**Why integrate ACE?** Prepare your contracts for future regulatory requirements without rewriting your core logic. Add, remove, or update compliance rules after deployment through modular policies.

**What you'll learn:** The 3-step pattern to make any contract policy-protected.

**What you'll build:** A simple vault with pauseable functions.

> **Building a token?** The pattern is identical—just use our audited [tokens](../packages/tokens) instead. We use a vault here to keep the example focused on ACE integration, not token complexity.

## A quick note before you start

This guide gets you hands-on fast. But if you find yourself asking "why?", these quick reads will help:

- **[What is Policy Management?](../packages/policy-management/README.md)** - Core concepts
- **[How do policies execute?](../packages/policy-management/docs/POLICY_ORDERING_GUIDE.md)** - Understanding `Allowed`, `Continue`, and `PolicyRejected` error

## Part 1: What you need to integrate ACE

Integrating ACE into your contract requires three key steps. Each step is simple and modular, allowing you to adopt ACE without rewriting your contract's core business logic.

### Step 1: Inherit from `PolicyProtected`

**What it is:** [`PolicyProtected`](../packages/policy-management/src/core/PolicyProtected.sol) is an abstract contract that provides the connection between your contract and the ACE compliance system.

**What you need to do:** Add `PolicyProtected` to your contract's inheritance list.

```solidity
import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";

contract YourContract is PolicyProtected {
    // Your contract code...
}
```

> **Note on Imports:** In this repo, the `@chainlink/...` imports work via Foundry remappings defined in `remappings.txt`. These point to the local `packages/` directory in this repository, not npm packages. If you're integrating ACE into your own project, ensure your `remappings.txt` includes:
>
> ```
> @chainlink/policy-management/=packages/policy-management/src/
> @chainlink/cross-chain-identity/=packages/cross-chain-identity/src/
> ```

**What this gives you:**

- Access to the `runPolicy` and `runPolicyWithContext` modifiers, which are the hooks into the policy system.
- Functions to attach and manage your contract's connection to a `PolicyEngine`.
- The ability to pass additional context data (like off-chain signatures) to your policies.

> **Important:** `PolicyProtected` is an upgradeable base contract, which means **your contract must be deployed through a proxy** (like `ERC1967Proxy`). See the [deployment script example](#the-deployment-script) below for the pattern.

### Step 2: Protect your functions with the `runPolicy` modifier

**What it is:** The `runPolicy` modifier is a function modifier that intercepts calls to your contract's functions and routes them through the `PolicyEngine` for validation before executing your core logic.

**What you need to do:** Add the `runPolicy` modifier to any function you want to protect with onchain compliance rules.

```solidity
function transfer(address to, uint256 amount) public runPolicy returns (bool) {
    // Your transfer logic...
}

function mint(address to, uint256 amount) public runPolicy {
    // Your minting logic...
}
```

**What this gives you:**

- **Flexible compliance enforcement:** Before your function's code runs, the `PolicyEngine` will check all registered policies for that function.
- **Zero core logic changes:** You don't modify your business logic. The modifier handles all compliance checks separately.
- **Dynamic updates:** You can add, remove, or reorder policies without ever touching this function again.

> **Note:** You can add the `runPolicy` modifier to any function in your contract. It works for standard functions (like `transfer`), administrative functions (like `mint`), or any custom function you define.

### Step 3: Deploy and configure a `PolicyEngine`

**What it is:** The [`PolicyEngine`](../packages/policy-management/src/core/PolicyEngine.sol) is the central orchestrator of your compliance system. It stores all your policies and executes them in order whenever a protected function is called.

**What you need to do:** Deploy and configure a `PolicyEngine`, then connect it to your contract and attach policies.

**Step 3a: Deploy and initialize the PolicyEngine**

```solidity
// Deploy the PolicyEngine implementation
PolicyEngine policyEngineImpl = new PolicyEngine();

// Encode the initialization data
bytes memory initData = abi.encodeWithSelector(
    PolicyEngine.initialize.selector,
    true,  // defaultAllow: true = allow by default, false = reject by default
    owner
);

// Deploy the proxy and initialize in one step
ERC1967Proxy proxy = new ERC1967Proxy(address(policyEngineImpl), initData);
PolicyEngine policyEngine = PolicyEngine(address(proxy));
```

The `defaultAllow` parameter (boolean) sets what happens when no policies are attached or when all policies return `Continue`:

- `true` - Transaction proceeds (permissive default, recommended for gradual adoption)
- `false` - Transaction is blocked (restrictive default)

> **Note:** When policies return `Allowed`, the engine immediately allows the transaction and stops evaluating further policies. When a policy reverts with a `PolicyRejected` error, the entire transaction reverts immediately. Only `Continue` results proceed to the next policy in the chain. Learn more in [How It Works](../packages/policy-management/README.md#how-it-works-an-overview).

**Step 3b: Deploy your contract and connect it to the PolicyEngine**

```solidity
// Deploy your contract implementation
MyContract contractImpl = new MyContract();

// Encode the initialization data (connects to PolicyEngine)
bytes memory contractInitData = abi.encodeWithSelector(
    MyContract.initialize.selector,
    owner,
    address(policyEngine)
);

// Deploy the proxy
ERC1967Proxy contractProxy = new ERC1967Proxy(address(contractImpl), contractInitData);
MyContract myContract = MyContract(address(contractProxy));
```

Your contract is now connected to the `PolicyEngine`, and the `runPolicy` modifiers will route function calls through this engine for validation.

**Step 3c: Deploy and attach policies to specific functions**

```solidity
// 1. Deploy a policy through a proxy
PausePolicy policyImpl = new PausePolicy();
bytes memory policyData = abi.encodeWithSelector(
    Policy.initialize.selector,
    address(policyEngine),
    owner,
    configData
);
ERC1967Proxy policyProxy = new ERC1967Proxy(address(policyImpl), policyData);
PausePolicy pausePolicy = PausePolicy(address(policyProxy));

// 2. Attach it to a specific function on your contract
policyEngine.addPolicy(
    address(yourContract),           // The protected contract
    yourContract.transfer.selector,  // The function to protect
    address(pausePolicy),             // The policy to enforce
    new bytes32[](0)                  // Parameter names (if the policy needs them)
);
```

You can attach multiple policies to the same function—they'll execute in the order you add them.

**What this gives you:**

- **A modular compliance system:** Policies are separate contracts that can be added, removed, or upgraded independently. See a list of [ready-to-use policies](../packages/policy-management/src/policies/README.md) for common use cases or [create your own](../packages/policy-management/docs/CUSTOM_POLICIES_TUTORIAL.md).
- **Composable rules and fine-grained control:** Chain multiple policies together to create sophisticated compliance logic, and attach different policies to different functions. See the [Policy Ordering Guide](../packages/policy-management/docs/POLICY_ORDERING_GUIDE.md) for details on how policy ordering works and why it matters.

## Part 2: An example implementation

Now that you understand the integration requirements, here's a complete, working example. This example shows how to protect a simple vault contract's `deposit` and `withdraw` functions with a `PausePolicy`.

This example includes:

1. A simple vault contract that inherits from `PolicyProtected` ([`MyVault.sol`](./MyVault.sol)).
2. A deployment script that sets up the `PolicyEngine` and attaches a `PausePolicy` ([`DeployGettingStarted.s.sol`](../script/getting_started/DeployGettingStarted.s.sol)).
3. Test commands to demonstrate pausing and unpausing vault operations.

### The vault contract

Here's the vault contract ([`getting_started/MyVault.sol`](./MyVault.sol)):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";

contract MyVault is PolicyProtected {
    mapping(address => uint256) public deposits;

    function initialize(address initialOwner, address policyEngine) public initializer {
        __PolicyProtected_init(initialOwner, policyEngine);
    }

    // The runPolicy modifier protects this function
    function deposit(uint256 amount) public runPolicy {
        deposits[msg.sender] += amount;
    }

    // The runPolicy modifier protects this function too
    function withdraw(uint256 amount) public runPolicy {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        deposits[msg.sender] -= amount;
    }
}
```

**Key takeaways:**

- Inheritance from `PolicyProtected` (an upgradeable base contract)
- `initialize()` function sets up the owner and connects to the `PolicyEngine`
- Multiple functions can be protected with the `runPolicy` modifier
- Each function can have different policies attached via the `PolicyEngine`

### The deployment script

Here's the deployment script ([`DeployGettingStarted.s.sol`](../script/getting_started/DeployGettingStarted.s.sol)):

> **Note on Proxy Deployment:** All ACE components must be deployed behind a proxy because they use OpenZeppelin's upgradeable contracts pattern (disabled constructors with initializers). This guide uses `ERC1967Proxy`, which enables upgradeability—you can update contract logic while preserving state and addresses. In production, you may also encounter minimal proxies (clones) for components that don't require upgradeability.

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MyVault} from "../getting_started/MyVault.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {PausePolicy} from "@chainlink/policy-management/policies/PausePolicy.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";

contract DeployGettingStarted is Script {
    function run() external {
        uint256 deployerPK = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPK);

        vm.startBroadcast(deployerPK);

        // 1. Deploy the PolicyEngine through a proxy
        PolicyEngine policyEngineImpl = new PolicyEngine();
        bytes memory policyEngineData = abi.encodeWithSelector(
            PolicyEngine.initialize.selector,
            true,  // defaultAllow = true (allow by default)
            deployer
        );
        ERC1967Proxy policyEngineProxy = new ERC1967Proxy(address(policyEngineImpl), policyEngineData);
        PolicyEngine policyEngine = PolicyEngine(address(policyEngineProxy));

        // 2. Deploy your vault through a proxy
        MyVault vaultImpl = new MyVault();
        bytes memory vaultData = abi.encodeWithSelector(
            MyVault.initialize.selector,
            deployer,
            address(policyEngine)
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultData);
        MyVault vault = MyVault(address(vaultProxy));

        // 3. Deploy the PausePolicy through a proxy
        PausePolicy pausePolicyImpl = new PausePolicy();
        bytes memory pausePolicyConfig = abi.encode(false); // Not paused by default
        bytes memory pausePolicyData = abi.encodeWithSelector(
            Policy.initialize.selector,
            address(policyEngine),
            deployer,
            pausePolicyConfig
        );
        ERC1967Proxy pausePolicyProxy = new ERC1967Proxy(address(pausePolicyImpl), pausePolicyData);
        PausePolicy pausePolicy = PausePolicy(address(pausePolicyProxy));

        // 4. Add the PausePolicy to both deposit and withdraw functions
        policyEngine.addPolicy(
            address(vault),
            vault.deposit.selector,
            address(pausePolicy),
            new bytes32[](0) // No parameters needed for PausePolicy
        );

        policyEngine.addPolicy(
            address(vault),
            vault.withdraw.selector,
            address(pausePolicy),
            new bytes32[](0)
        );

        vm.stopBroadcast();

        console.log("--- Deployed Contracts ---");
        console.log("MyVault deployed at:", address(vault));
        console.log("PolicyEngine deployed at:", address(policyEngine));
        console.log("PausePolicy deployed at:", address(pausePolicy));
    }
}
```

### Testing your compliant vault

You can now test your policy-protected vault on a local Anvil chain.

#### Prerequisites

- [Node.js](https://nodejs.org/en/download/) (v18 or later)
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (v0.3.0 or later)
- [pnpm](https://pnpm.io/installation)

#### Setup

1. **Clone and enter the repository:**

   ```bash
   git clone https://github.com/smartcontractkit/chainlink-ace.git
   cd chainlink-ace
   ```

2. **Install dependencies:**

   ```bash
   pnpm install
   ```

3. **Build the project:**

   ```bash
   pnpm build
   ```

#### Start Anvil Chain

From a new terminal, start a new anvil chain by running:

```bash
anvil
```

**Note:** Keep this terminal open - anvil runs on `http://localhost:8545` by default.

#### Deploy the System

Now you're ready to deploy your policy-protected vault:

```bash
export ETH_RPC_URL=http://localhost:8545
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

forge script script/getting_started/DeployGettingStarted.s.sol:DeployGettingStarted --rpc-url $ETH_RPC_URL --private-key $PRIVATE_KEY --broadcast
```

#### Test the compliance system

**Set up your environment** (replace with your deployed addresses from the logs above):

```bash
export VAULT_ADDRESS=<Your_Deployed_MyVault_Address>
export PAUSE_POLICY_ADDRESS=<Your_Deployed_PausePolicy_Address>
```

> **Tip:** After running the deploy command, you'll see the deployed addresses in the output logs:
>
> ```
> == Logs ==
>   --- Deployed Contracts ---
>   MyVault deployed at: 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
>   PolicyEngine deployed at: 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
>   PausePolicy deployed at: 0x5FC8d32690cc91D4c39d9d3abcBD16989F875707
> ```
>
> Use these addresses for `VAULT_ADDRESS` and `PAUSE_POLICY_ADDRESS`.

**Run the tests:**

1. **Make a deposit of 100:**

   ```bash
   cast send $VAULT_ADDRESS "deposit(uint256)" 100 --private-key $PRIVATE_KEY
   ```

   **Expected:** Success!

2. **Check your deposit:**

   ```bash
   cast call $VAULT_ADDRESS "deposits(address)" 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 | cast --to-dec
   ```

   **Expected:** 100

3. **Pause the vault:**

   ```bash
   cast send $PAUSE_POLICY_ADDRESS "pause()" --private-key $PRIVATE_KEY
   ```

   **Expected:** Success!

4. **Attempt a deposit:**

   ```bash
   cast send $VAULT_ADDRESS "deposit(uint256)" 50 --private-key $PRIVATE_KEY
   ```

   **Expected:** `Error: PolicyRunRejected` with reason "contract is paused"

5. **Attempt a withdrawal:**

   ```bash
   cast send $VAULT_ADDRESS "withdraw(uint256)" 10 --private-key $PRIVATE_KEY
   ```

   **Expected:** `Error: PolicyRunRejected` with reason "contract is paused"

6. **Unpause the vault:**

   ```bash
   cast send $PAUSE_POLICY_ADDRESS "unpause()" --private-key $PRIVATE_KEY
   ```

   **Expected:** Success!

7. **Withdraw funds:**

   ```bash
   cast send $VAULT_ADDRESS "withdraw(uint256)" 10 --private-key $PRIVATE_KEY
   ```

   **Expected:** Success!

8. **Verify the updated balance:**

   ```bash
   cast call $VAULT_ADDRESS "deposits(address)" 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 | cast --to-dec
   ```

   **Expected:** 90 (100 - 10)

## Next steps

You now understand the core ACE integration pattern:

1. Inherit from `PolicyProtected`
2. Protect functions with the `runPolicy` modifier
3. Deploy a `PolicyEngine` and attach policies

### Where to go from here

Choose your path based on what you want to build:

#### **Learn more about Policy Management**

You've seen one policy (`PausePolicy`) on two functions. Ready to level up?

**Understand the system:**

- **[How the Policy Flow Works](../packages/policy-management/README.md#how-it-works-an-overview)** - Understand `Allowed`, `Continue`, and `PolicyRejected` error
- **[Policy Ordering Matters](../packages/policy-management/docs/POLICY_ORDERING_GUIDE.md)** - Learn how policy execution order affects security

**Use Policies:**

- **[Policy Library](../packages/policy-management/src/policies/README.md)** - Explore ready-to-use policies: `MaxPolicy`, `VolumePolicy`, `OnlyOwnerPolicy`, `RoleBasedAccessControlPolicy`, and more
- **[Create a Custom Policy](../packages/policy-management/docs/CUSTOM_POLICIES_TUTORIAL.md)** - Step-by-step tutorial with boilerplate template

---

#### **Build a compliant token**

Don't reinvent the wheel. Use our audited, production-ready token implementations:

- **[ComplianceTokenERC20](../packages/tokens/erc-20/src/ComplianceTokenERC20.sol)**
- **[ComplianceTokenERC3643](../packages/tokens/erc-3643/src/ComplianceTokenERC3643.sol)**
- **[Example Deployment Scripts](../script/)** - See how to deploy and configure these tokens

---

#### **Add Cross-Chain Identity & credentials**

Ready to add identity and credential verification (KYC, AML, accreditation, etc.)? Integrate the Cross-Chain Identity component:

**Start with the advanced tutorial:**

- **[Advanced Getting Started: Tokenized Fund](./advanced/GETTING_STARTED_ADVANCED.md)** - Build a complete system with KYC checks, sanctions screening, and identity management across multiple roles

**Deep dive into identity:**

- **[Cross-Chain Identity Overview](../packages/cross-chain-identity/README.md)** - Understand CCIDs, credentials, and credential issuers
- **[Credential Flow Diagram](../packages/cross-chain-identity/docs/CREDENTIAL_FLOW.md)** - Visual walkthrough of the complete issuance process
- **[Security Considerations](../packages/cross-chain-identity/docs/SECURITY.md)** - Privacy, CCID correlation, and data protection
