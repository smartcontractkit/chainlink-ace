# Policy Ordering Guide

## Why Order Matters

Policies execute sequentially in the exact order they were added to the `PolicyEngine`. The execution order is critical because:

- **reverts `PolicyRejected`** - Immediately stops execution and reverts the transaction
- **`Allowed`** - Immediately stops execution and allows the transaction (skips all remaining policies)
- **`Continue`** - Proceeds to the next policy in the chain, or applies the default engine behavior if no more policies remain

This means the position of each policy in the chain directly affects which policies get executed.

## Adding Policies

### `addPolicy()` - Append to End

Adds a policy to the end of the existing policy chain.

```solidity
// Current chain: []
policyEngine.addPolicy(target, selector, address(policyA), params);
// Result: [PolicyA]

policyEngine.addPolicy(target, selector, address(policyB), params);
// Result: [PolicyA, PolicyB]

policyEngine.addPolicy(target, selector, address(policyC), params);
// Result: [PolicyA, PolicyB, PolicyC]
```

### `addPolicyAt()` - Insert at Specific Position

Inserts a policy at a specific position, shifting existing policies to the right.

```solidity
// Current chain: [PolicyA, PolicyB, PolicyC]

// Insert PolicyD at position 1
policyEngine.addPolicyAt(target, selector, address(policyD), params, 1);
// Result: [PolicyA, PolicyD, PolicyB, PolicyC]

// Insert PolicyE at position 0 (first position)
policyEngine.addPolicyAt(target, selector, address(policyE), params, 0);
// Result: [PolicyE, PolicyA, PolicyD, PolicyB, PolicyC]
```

## Removing Policies

### `removePolicy()` - Remove by Address

Removes a specific policy from the chain, shifting remaining policies to maintain order.

```solidity
// Current chain: [PolicyA, PolicyB, PolicyC, PolicyD]

policyEngine.removePolicy(target, selector, address(policyB));
// Result: [PolicyA, PolicyC, PolicyD]

policyEngine.removePolicy(target, selector, address(policyA));
// Result: [PolicyC, PolicyD]
```

## Checking Current Order

Use `getPolicies()` to view the current policy chain in execution order:

```solidity
address[] memory policies = policyEngine.getPolicies(target, selector);
// Returns: [policy1Address, policy2Address, policy3Address, ...]
// Array index 0 executes first, then index 1, then index 2, etc.
```

## Reordering Existing Policies

To change the position of an existing policy:

1. Remove the policy from its current position
2. Add it back at the desired position

```solidity
// Current: [PolicyA, PolicyB, PolicyC]
// Goal: Move PolicyC to first position

// Step 1: Remove PolicyC
policyEngine.removePolicy(target, selector, address(policyC));
// Result: [PolicyA, PolicyB]

// Step 2: Add PolicyC at position 0
policyEngine.addPolicyAt(target, selector, address(policyC), params, 0);
// Result: [PolicyC, PolicyA, PolicyB]
```
