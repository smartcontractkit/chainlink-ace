# Glossary

- [AML (Anti-Money Laundering)](#aml-anti-money-laundering)
- [CCID (Cross-Chain Identifier)](#ccid-cross-chain-identifier)
- [Composability](#composability)
- [Context Parameters](#context-parameters)
- [Credential](#credential)
- [Credential Registry](#credential-registry)
- [ERC-20](#erc-20)
- [ERC-165](#erc-165)
- [Extractors and Mappers](#extractors-and-mappers)
- [KYC (Know Your Customer)](#kyc-know-your-customer)
- [Offchain Proofs](#offchain-proofs)
- [PII (Personally Identifiable Information)](#pii-personally-identifiable-information)
- [Policy](#policy)
- [Policy Engine](#policy-engine)
- [Policy Management](#policy-management)
- [Proof-of-Reserves (PoR)](#proof-of-reserves-por)
- [Quota Policy](#quota-policy)
- [Real-World Assets (RWA)](#real-world-assets-rwa)
- [Trusted Verifier](#trusted-verifier)
- [Validators](#validators)
  - [Identity Validator](#identity-validator)
  - [Credential Registry Validator](#credential-registry-validator)
  - [Credential Data Validator](#credential-data-validator)

---

### **AML (Anti-Money Laundering)**

A set of laws, regulations, and procedures designed to prevent criminals from disguising illegally obtained funds as
legitimate income.

### **CCID (Cross-Chain Identifier)**

A 32-byte identifier used in the [**Cross-Chain Identity**](/packages/cross-chain-identity) standard to uniquely
represent an entity across multiple blockchains. It maps local blockchain addresses to a unified identity, facilitating
credential management and cross-chain interoperability.

### **Composability**

The ability to integrate and combine modular components or standards in a flexible manner. For example, the [**Policy
Management**](/packages/policy-management) standard enables dynamic rule enforcement by chaining multiple policies.

### **Context Parameters**

Additional data passed as a `bytes` array to certain functions for compliance or authorization purposes. E.g.:
cryptographic proofs, regulatory authorizations, or external references.

### **Credential**

A verifiable attribute (e.g., KYC, AML compliance, Accredited Investor status) linked to a **CCID** in the [**Cross-Chain Identity**](/packages/cross-chain-identity) standard. Credentials are stored in registries and can be
validated by external entities without revealing sensitive information.

### **Credential Registry**

A component of the [**Cross-Chain Identity**](/packages/cross-chain-identity) standard that manages the lifecycle of
credentials linked to CCIDs. It supports registration, validation, removal, and renewal of credentials.

### **ERC-20**

[ERC20](https://eips.ethereum.org/EIPS/eip-20) is a widely used Ethereum token standard defining rules for fungible
tokens.

### **ERC-165**

[ERC165](https://eips.ethereum.org/EIPS/eip-165) is an Ethereum standard that enables contracts to declare the
interfaces they implement, facilitating interface detection.

### **Extractors and Mappers**

Components in the [**Policy Management**](/packages/policy-management) standard that process raw transaction data into
structured formats for policy consumption. Extractors parse inputs, while mappers transform them into policy-specific
formats.

### **KYC (Know Your Customer)**

[KYC](https://www.swift.com/your-needs/financial-crime-cyber-security/know-your-customer-kyc/meaning-kyc) is a
compliance process requiring financial institutions to verify the identity of their clients and the nature of their
activities.

### **Offchain Proofs**

Verification mechanisms (e.g., zk-proofs) performed outside the blockchain to ensure compliance or authenticity without
revealing sensitive information.

### **PII (Personally Identifiable Information)**

[PII](https://www.dol.gov/general/ppii) is information that can identify an individual, such as a name, address, or
national ID number. The [**Cross-Chain Identity**](/packages/cross-chain-identity) standard avoids storing PII onchain,
using hashed references instead.

### **Policy**

A self-contained module in the [**Policy Management**](/packages/policy-management) standard that enforces specific
rules, such as access control or compliance quotas.

### **Policy Engine**

A central component of the [**Policy Management**](/packages/policy-management) standard that manages the execution of
multiple policies for a method selector. It coordinates the evaluation of policies in sequence and enforces dynamic
outcomes.

### **Policy Management**

A [standard](/packages/policy-management) defining a modular policy engine for enforcing compliance, business rules, and
access control in smart contracts. It supports dynamic policy updates without redeploying the core contract.

### **Proof-of-Reserves (PoR)**

[Proof-of-Reserves](https://chain.link/education-hub/proof-of-reserves) is a mechanism for verifying that a custodian
holds sufficient reserves to back assets it has issued.

### **Quota Policy**

A policy module in the [**Policy Management**](/packages/policy-management) standard that restricts the use of a method
to a predefined limit. It enforces compliance by rejecting transactions that exceed the allowed quota.

### **Real-World Assets (RWA)**

[Real-World Assets](https://chain.link/education-hub/real-world-assets-rwas-explained) are physical or traditional
financial assets tokenized on blockchain platforms, such as real estate or securities. The **Permissioned Token**
standard supports regulatory compliance for tokenized RWAs.

### **Trusted Verifier**

A trusted verifier within the [**Cross-Chain Identity**](/packages/cross-chain-identity) standard is an offchain entity
authorized to conduct external checks (e.g., KYC, AML) and to register the resulting credentials onchain. This approach
ensures privacy by storing only PII-redacted data onchain.

### **Validators**

Smart contracts in the [**Cross-Chain Identity**](/packages/cross-chain-identity) standard that verifies whether a given
identity or credential meets certain criteria:

- **Identity Validator**: Confirms an account has a valid CCID mapping and contains all the required credentials,
  utilizing one or more sets of registries.
- **Credential Registry Validator**: Inspects a single registry to confirm whether a credential is present, valid, or
  unexpired for a given CCID.
- **Credential Data Validator**: Examines the data attached to a credential for correctness, integrity, or adherence to
  specific formats.
