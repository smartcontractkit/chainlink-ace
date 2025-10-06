# Security Considerations: Policy Management

The Policy Management component provides a powerful and flexible way to enforce on-chain rules, but this flexibility requires careful attention to security during implementation and administration.

## 1. Policy Administration is a Critical Control

The ability to add, remove, or reorder policies in the `PolicyEngine` is the most sensitive administrative power in the system. An attacker who gains control over these functions can effectively disable or bypass all compliance rules.

- **Access Control:** Only highly trusted roles, such as a DAO, a multi-sig wallet, or a designated `owner`, MUST be able to call `addPolicy`, `removePolicy`, `setExtractor`, `setPolicyMapper`, and `setDefaultResult`.
- **Timelocks:** It is RECOMMENDED that all administrative changes to the `PolicyEngine` are passed through a timelock contract. This creates a delay between the proposal of a change and its execution, giving users time to review the change and exit the system if they do not agree with it.

## 2. Policy Order Matters

The `PolicyEngine` executes policies for a given function in a specific, ordered sequence. The outcome of the entire chain can change dramatically based on this order.

- **`Allowed` as a Bypass:** A policy that returns `PolicyResult.Allowed` will immediately halt execution and bypass all subsequent policies in the chain. For this reason, permissive policies (like a `BypassPolicy` for admins) should be placed with extreme care, typically at the beginning of the policy chain.
- **Ordering for Restriction:** Restrictive policies should generally be placed before more lenient ones. For example, a `RejectPolicy` for a hard-coded denylist should come before a `VolumePolicy` to ensure the denied user cannot transact at all.

## 3. Trust in Policy, Extractor, and Mapper Contracts

The `PolicyEngine` delegates trust to the individual `Policy`, `Extractor`, and `Mapper` contracts it is configured to use. A vulnerability in any one of these components can compromise the entire system.

- **Policy Trust:** Malicious or poorly written policies can introduce vulnerabilities. Only install trusted, audited policies.
- **`postRun` State Changes:** The `postRun` function on a policy can modify state. This is a powerful feature that could be used for malicious purposes if the policy is not trustworthy (e.g., draining funds, changing ownership).
- **Extractor/Mapper Trust:** The `PolicyEngine` relies on `Extractors` to correctly and honestly parse transaction data. If an extractor is compromised or misrepresents data, policies may make decisions based on false information, potentially leading to a bypass. For example, an extractor could lie about the `value` of a transfer to circumvent a `VolumePolicy`.

## 4. External Call Risks in Policy Logic

Policies that make external calls during execution can introduce certain risks, though the specific risks depend on whether the policy functions are `view` or state-changing.

- **External Calls in Policies:** Many policies make external calls during their `run()` function execution. Examples include:
  - Data source queries (e.g., `SanctionsPolicy` calling `dataRegistry.getDataSource()` and `sanctionsList.isSanctioned()`)
  - Identity verification (e.g., `CredentialRegistryIdentityValidatorPolicy` calling multiple registry contracts)
  - Price feeds, oracles, or other external data sources
- **Risks for `view` Policy Functions:** Since most policy `run()` functions are `view` (read-only), traditional reentrancy attacks are **not possible** because no state can be modified. However, other risks exist:
  - **Denial of Service** - malicious external contracts could revert or consume excessive gas
  - **Inconsistent reads** - external contract state could change between multiple calls within the same policy
  - **Gas exhaustion** - deep call chains could cause transaction failures
- **Risks for State-Changing Policy Functions:** Policies with non-view functions (like `postRun()`) could be vulnerable to traditional reentrancy if they make external calls and modify state
- **Architectural Considerations:** Since protected contracts are **decoupled** from policy logic and policies can be changed dynamically:
  - **Protected contract developers** cannot predict which policies will be applied to their functions
  - **Policy administrators** bear the responsibility for ensuring safe policy combinations
  - **External call risks** should be considered at the policy composition level, not forced onto every protected function
- **Mitigation Strategies:**
  - **Use trusted external contracts** - only interact with well-established, audited external contracts in policy logic to minimize DoS and manipulation risks
  - **Implement proper error handling** - ensure policies gracefully handle external contract failures rather than causing transaction reverts
  - **Consider gas limits** - external calls in policies consume gas and could cause transaction failures if gas limits are exceeded
  - **For non-view policies** - if a policy's `postRun()` or other functions modify state and make external calls, consider reentrancy protection
  - **Policy administrators should assess risk** - when adding policies with external calls, evaluate the trustworthiness of the external contracts being called

## 5. `context` Handling and Race Conditions

The `context` field in the `PolicyEngine.Payload` is a powerful feature for passing arbitrary data, but it must be managed carefully to avoid race conditions and incorrect usage.

- **Context is Per-Sender, Not Per-Transaction:** The standard implementation of `PolicyProtected` stores context in a mapping (`sender` => `context`). It is **not** automatically cleared after every transaction. If context is set but not consumed in the same transaction by a protected method, the stale context may be incorrectly reused by a subsequent call from the same sender.
- **Atomic Operations Recommended:** To mitigate this, it is **strongly recommended** to set and consume `context` within the same atomic transaction. The caller should first call `setContext(bytes)` and then immediately call the protected function. The `runPolicy` modifier will then consume the context and clear it.
- **Re-entrancy & Multi-User Scenarios:** In contracts that can be used by multiple users (like relayers or governance contracts), context from one user could potentially be overwritten by another before it is consumed. Implementations must ensure that context cannot be mismatched, especially in scenarios involving re-entrancy.
