<div align="center">
  <img src="assets/chainlink-logo.svg" alt="Chainlink" width="300" height="130"/>
</div>

# Chainlink ACE Core Contracts

**Build the next generation of financial applications with programmable, cross‑chain compliance—powered by the Chainlink Automated Compliance Engine (ACE).**

## What Problems Does This Solve?

Building compliant applications on the blockchain requires handling:

- **Dynamic policy enforcement** that evolves with regulations—without redeploying your core application contracts
- **Identity verification** across chains, without fragmented credentials
- **Trusted external data** (KYC providers, sanctions lists, price feeds, Proof of Reserves, etc.) delivered onchain

## Your Modular Toolkit

| Component                | Description                                                                        |
| ------------------------ | ---------------------------------------------------------------------------------- |
| **Policy Management**    | Dynamic engine to create and enforce onchain rules.                                |
| **Cross-Chain Identity** | Portable identity system for EVM chains; attach credentials once, verify anywhere. |

## Key Features

- **Modular & Composable**: Use one component or all three. They're designed to work together seamlessly.
- **Future-Proof**: Adapt to new regulations by updating policies, not your core application logic.
- **Cross-Chain Ready**: Manage identity and compliance consistently across multiple EVM networks.
- **Privacy-Preserving by Design**: Keep sensitive user data offchain while verifying credentials onchain.
- **Ready-to-Use Policies**: Plug-and-play modules for common compliance scenarios like volume limits and authorization.
- **EVM Compatible**: Works with existing tooling and supports future innovations like ZK proofs.

## How It Works: A Real-World Example

Here's how these three components work together. Imagine **Emma** (an institutional investor) wants to buy **$50,000** of a **Tokenized Bond** on a DEX.

```mermaid
graph TB
    subgraph "External World"
        KYC["<b>KYC Provider</b><br/>✅ Emma: Verified"]
        Oracle["<b>Bond Price Feed</b><br/>📊 Current: $1.02"]
        AML["<b>AML Watchlist</b><br/>🔍 Emma: Clean"]
    end

    subgraph "Chainlink ACE Modular Toolkit"
        subgraph "Cross-Chain Identity"
            CCID["<b>Emma's Identity</b><br/>ID: 0x1a2b... (Portable)"]
            CredReg["<b>Credentials</b><br/>✅ KYC ✅ Accredited"]
        end

        subgraph "Policy Management ⚙️"
            PE["<b>Policy Engine</b><br/>🧠 Decision Maker"]
            P1["<b>Access Policy</b><br/>❓ Verified & not sanctioned?"]
            P2["<b>Volume Rate Policy</b><br/>❓ $50k within daily limit?"]
        end

    end

    subgraph "Emma's Transaction"
        Emma["<b>👩‍💼 Emma</b><br/>Wants: $50k bonds"]
        BondDEX["<b>Bond DEX</b><br/>🏦 Tokenized Bonds"]
        Result["<b>✅ Trade Approved</b>"]
    end

    %% Data flows
    KYC -.->|"<b>Issues Credential</b>"| CredReg
    Oracle -.->|"<b>Provides Data</b>"| Registry
    AML -.->|"<b>Provides Data</b>"| Registry

    %% Transaction flow
    Emma -->|"<b>1. Buy Bonds</b>"| BondDEX
    BondDEX -->|"<b>2. Validate Tx</b>"| PE

    %% Policy Engine orchestration
    PE --> P1
    PE --> P2

    %% Policy checks using other components
    P1 -->|"Checks"| CredReg
    P1 -->|"Uses"| Registry
    P2 -->|"Uses"| Registry

    %% Completion
    PE -->|"<b>3. All checks pass</b>"| BondDEX
    BondDEX -->|"<b>4. Execute Trade</b>"| Result

    classDef default fill:#2b2f37,stroke:#c0c5ce,stroke-width:1px,color:#c0c5ce
    classDef external fill:#4338ca,stroke:#a5b4fc,stroke-width:1px,color:#e0e7ff
    classDef user fill:#166534,stroke:#4ade80,stroke-width:1px,color:#dcfce7
    classDef result fill:#be123c,stroke:#fda4af,stroke-width:1px,color:#ffe4e6

    class KYC,Oracle,AML external
    class Emma,Result user
```

### The Compliance Journey: Step-by-Step

1.  **Transaction Initiated**: Emma submits her buy order on the DEX. Before executing, the DEX's smart contract calls the **Policy Engine** to validate the transaction.
2.  **Access Policy Executes**: The Policy Engine executes the `Access Policy`, which uses the **Cross-Chain Identity** component to verify Emma has the required credentials (`✅ KYC`, `✅ Accredited`).
    _Crucially, this same identity and credential would be valid even if Emma were using a different wallet address on a different EVM chain._
3.  **Volume Rate Policy Executes**: Next, the engine runs the `Volume Rate Policy`, which tracks Emma's trading volume over time and confirms the $50,000 trade is within her daily limit.
4.  **Transaction Approved**: With all policies passing, the Policy Engine allows the transaction to proceed. The DEX executes the trade, and Emma receives her tokenized bonds.
    _The power of this model is that if regulations change tomorrow, the DEX's owners could add a new policy (e.g., a 'Time-of-Day Policy') without having to redeploy or alter the main DEX contract._

If any policy check had failed, the **Policy Engine would have reverted the transaction directly**, preventing a non-compliant trade.

## 🚀 Ready to Build?

### Want to get your hands dirty immediately?

Build with confidence using our reference implementations as your foundation.

- **Study the reference implementation for each component:**
  - [Policy Management](./packages/policy-management/src)
  - [Cross-Chain Identity](./packages/cross-chain-identity/src)
- **See full integrations in the [example tokens](./packages/tokens)**

### Want to learn more first?

Understand the architecture and design before diving into implementation.

**→ Continue reading about the components below**

## Explore the Components

### 🛡️ [Policy Management](./packages/policy-management/)

Use this component to enforce onchain rules that can be updated without redeploying your core contracts.

- **Policy Engine**: Pluggable, composable policy enforcement.
- **Zero Downtime Updates**: Add, remove, or modify rules dynamically.
- **Ready-to-Use Policies**: AllowPolicy, VolumePolicy, OnlyOwnerPolicy, and more.

→ **[📋 Quick Guide](./packages/policy-management/README.md)** | **[🏗️ Reference Implementation](./packages/policy-management/src/)** | **[📚 Deep Dive Docs](./packages/policy-management/docs/)** | **[📋 Ready-to-Use Policies](./packages/policy-management/src/policies/README.md)**

### 🔗 [Cross-Chain Identity](./packages/cross-chain-identity/)

Use this component to link wallet addresses to a single identity and manage credentials like KYC/AML.

- **Cross-Chain ID (CCID)**: Single identifier linking addresses across multiple chains.
- **Credential Registry**: Manage credentials (e.g., KYC, AML) that are tied directly to a user's CCID.
- **Privacy-First**: Store sensitive data offchain, only hashes onchain.

→ **[📋 Quick Guide](./packages/cross-chain-identity/README.md)** | **[🏗️ Reference Implementation](./packages/cross-chain-identity/src/)** | **[📚 Deep Dive Docs](./packages/cross-chain-identity/docs/)**

### [Example Tokens](./packages/tokens/)

Explore our example token contracts to see how these components work together in a real application.

- **[ERC-20 Compliance Token](./packages/tokens/erc-20)** - A policy-protected ERC-20 implementation with advanced frozen token handling
- **[ERC-3643 Compliance Token](./packages/tokens/erc-3643)** - A compliant implementation of the ERC-3643 T-REX standard

> **📝 Important Note on Frozen Token Behavior:**  
> These two token implementations handle frozen tokens differently during burns and forced transfers:
>
> - **ERC-20**: Frozen tokens remain frozen during burns/force transfers. The `_checkFrozenBalance()` function ensures sufficient unfrozen tokens are available before operations proceed.
> - **ERC-3643**: Automatically unfreezes tokens as needed during burns/force transfers to complete the operation.
>
> Both approaches are valid design choices depending on your compliance requirements. Choose the implementation that best fits your use case.

## Contributing & Feedback

We welcome community **feedback, audits, and contributions**. If you have additional compliance requirements or ideas for new features, please feel free to propose expansions or new modules.
