// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

// Core Contracts
import {ComplianceTokenERC20} from "../../../packages/tokens/erc-20/src/ComplianceTokenERC20.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {IdentityRegistry} from "@chainlink/cross-chain-identity/IdentityRegistry.sol";
import {CredentialRegistry} from "@chainlink/cross-chain-identity/CredentialRegistry.sol";

// Policies
import {OnlyOwnerPolicy} from "@chainlink/policy-management/policies/OnlyOwnerPolicy.sol";
import {CredentialRegistryIdentityValidatorPolicy} from
  "@chainlink/cross-chain-identity/CredentialRegistryIdentityValidatorPolicy.sol";
import {SanctionsPolicy} from "../../../getting_started/advanced/SanctionsPolicy.sol";
import {OnlyAuthorizedSenderPolicy} from "@chainlink/policy-management/policies/OnlyAuthorizedSenderPolicy.sol";

// Extractors
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {ComplianceTokenMintBurnExtractor} from
  "@chainlink/policy-management/extractors/ComplianceTokenMintBurnExtractor.sol";
import {ComplianceTokenFreezeUnfreezeExtractor} from
  "@chainlink/policy-management/extractors/ComplianceTokenFreezeUnfreezeExtractor.sol";
import {ComplianceTokenForceTransferExtractor} from
  "@chainlink/policy-management/extractors/ComplianceTokenForceTransferExtractor.sol";

// Interfaces
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ICredentialRequirements} from "@chainlink/cross-chain-identity/interfaces/ICredentialRequirements.sol";

contract DeployAdvancedGettingStarted is Script {
  function run() external {
    // --- 0. Setup ---
    // Load the deployer's private key from the environment.
    // This is the primary account that will own and configure the system.
    uint256 tokenOwnerPK = vm.envUint("PRIVATE_KEY");
    address tokenOwner = vm.addr(tokenOwnerPK);

    vm.startBroadcast(tokenOwnerPK);

    // --- 1. Deploy Core Infrastructure ---
    // The PolicyEngine is the central orchestrator for all compliance rules.
    // We set its default to allow (true) for this tutorial, meaning any action
    // not explicitly rejected by a policy will be permitted.
    PolicyEngine policyEngineImpl = new PolicyEngine();
    bytes memory policyEngineData = abi.encodeWithSelector(PolicyEngine.initialize.selector, true, tokenOwner);
    ERC1967Proxy policyEngineProxy = new ERC1967Proxy(address(policyEngineImpl), policyEngineData);
    PolicyEngine policyEngine = PolicyEngine(address(policyEngineProxy));

    // --- 2. Deploy Identity & Credential Registries and Secure Them ---
    // These registries are the databases for our identity system.
    // Crucially, we set the PolicyEngine as their owner, so all administrative
    // actions MUST go through the policy system.
    IdentityRegistry identityRegistryImpl = new IdentityRegistry();
    bytes memory identityRegistryData =
      abi.encodeWithSelector(IdentityRegistry.initialize.selector, address(policyEngine), tokenOwner);
    ERC1967Proxy identityRegistryProxy = new ERC1967Proxy(address(identityRegistryImpl), identityRegistryData);
    IdentityRegistry identityRegistry = IdentityRegistry(address(identityRegistryProxy));

    CredentialRegistry credentialRegistryImpl = new CredentialRegistry();
    bytes memory credentialRegistryData =
      abi.encodeWithSelector(CredentialRegistry.initialize.selector, address(policyEngine), tokenOwner);
    ERC1967Proxy credentialRegistryProxy = new ERC1967Proxy(address(credentialRegistryImpl), credentialRegistryData);
    CredentialRegistry credentialRegistry = CredentialRegistry(address(credentialRegistryProxy));

    // We use OnlyAuthorizedSenderPolicy to allow the owner to delegate registry management.
    OnlyAuthorizedSenderPolicy identityOnlyAuthorizedSenderPolicyImpl = new OnlyAuthorizedSenderPolicy();
    bytes memory identityOnlyAuthorizedSenderPolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, address(policyEngine), tokenOwner, new bytes(0));
    ERC1967Proxy identityOnlyAuthorizedSenderPolicyProxy =
      new ERC1967Proxy(address(identityOnlyAuthorizedSenderPolicyImpl), identityOnlyAuthorizedSenderPolicyData);
    OnlyAuthorizedSenderPolicy identityOnlyAuthorizedSenderPolicy =
      OnlyAuthorizedSenderPolicy(address(identityOnlyAuthorizedSenderPolicyProxy));
    identityOnlyAuthorizedSenderPolicy.authorizeSender(tokenOwner); // Authorize the deployer by default

    // All administrative functions on the registries will now require that the
    // caller is on the authorized list of the identityOnlyAuthorizedSenderPolicy.
    policyEngine.addPolicy(
      address(identityRegistry),
      identityRegistry.registerIdentity.selector,
      address(identityOnlyAuthorizedSenderPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(identityRegistry),
      identityRegistry.registerIdentities.selector,
      address(identityOnlyAuthorizedSenderPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(identityRegistry),
      identityRegistry.removeIdentity.selector,
      address(identityOnlyAuthorizedSenderPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(credentialRegistry),
      credentialRegistry.registerCredential.selector,
      address(identityOnlyAuthorizedSenderPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(credentialRegistry),
      credentialRegistry.registerCredentials.selector,
      address(identityOnlyAuthorizedSenderPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(credentialRegistry),
      credentialRegistry.removeCredential.selector,
      address(identityOnlyAuthorizedSenderPolicy),
      new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(credentialRegistry),
      credentialRegistry.renewCredential.selector,
      address(identityOnlyAuthorizedSenderPolicy),
      new bytes32[](0)
    );

    // --- 3. Deploy MMF Token and Secure It ---
    // This is our main application contract. It inherits from PolicyProtected.
    ComplianceTokenERC20 mmfTokenImpl = new ComplianceTokenERC20();
    bytes memory mmfTokenData = abi.encodeWithSelector(
      ComplianceTokenERC20.initialize.selector,
      vm.envOr("TOKEN_NAME", string("Tokenized MMF")),
      vm.envOr("TOKEN_SYMBOL", string("MMF")),
      18,
      address(policyEngine)
    );
    ERC1967Proxy mmfTokenProxy = new ERC1967Proxy(address(mmfTokenImpl), mmfTokenData);
    ComplianceTokenERC20 mmfToken = ComplianceTokenERC20(address(mmfTokenProxy));

    // a. Protect critical admin functions (e.g., freeze, forceTransfer) with a strict OnlyOwnerPolicy.
    OnlyOwnerPolicy tokenOnlyOwnerPolicyImpl = new OnlyOwnerPolicy();
    bytes memory tokenOnlyOwnerPolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, address(policyEngine), tokenOwner, new bytes(0));
    ERC1967Proxy tokenOnlyOwnerPolicyProxy =
      new ERC1967Proxy(address(tokenOnlyOwnerPolicyImpl), tokenOnlyOwnerPolicyData);
    OnlyOwnerPolicy tokenOnlyOwnerPolicy = OnlyOwnerPolicy(address(tokenOnlyOwnerPolicyProxy));
    policyEngine.addPolicy(
      address(mmfToken), mmfToken.forceTransfer.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(address(mmfToken), mmfToken.freeze.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0));
    policyEngine.addPolicy(
      address(mmfToken), mmfToken.unfreeze.selector, address(tokenOnlyOwnerPolicy), new bytes32[](0)
    );

    // b. Protect minting and burning with a more flexible OnlyAuthorizedSenderPolicy.
    // This allows the owner to delegate minting rights to other contracts or addresses if needed.
    OnlyAuthorizedSenderPolicy tokenMinterBurnerPolicyImpl = new OnlyAuthorizedSenderPolicy();
    bytes memory tokenMinterBurnerPolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, address(policyEngine), tokenOwner, new bytes(0));
    ERC1967Proxy tokenMinterBurnerPolicyProxy =
      new ERC1967Proxy(address(tokenMinterBurnerPolicyImpl), tokenMinterBurnerPolicyData);
    OnlyAuthorizedSenderPolicy tokenMinterBurnerPolicy =
      OnlyAuthorizedSenderPolicy(address(tokenMinterBurnerPolicyProxy));
    tokenMinterBurnerPolicy.authorizeSender(tokenOwner); // The deployer can mint/burn by default.
    policyEngine.addPolicy(
      address(mmfToken), mmfToken.mint.selector, address(tokenMinterBurnerPolicy), new bytes32[](0)
    );
    policyEngine.addPolicy(
      address(mmfToken), mmfToken.burnFrom.selector, address(tokenMinterBurnerPolicy), new bytes32[](0)
    );

    // c. Protect `transfer` with KYC and Sanctions policies
    CredentialRegistryIdentityValidatorPolicy identityValidatorPolicy =
      createCredentialRegistryIdentityValidatorPolicy(policyEngine, tokenOwner, identityRegistry, credentialRegistry);

    // Read the Sanctions List address from environment (deployed by Sanctions Provider)
    address sanctionsListAddress = vm.envAddress("SANCTIONS_LIST_ADDRESS");

    // Deploy SanctionsPolicy with the sanctions list address configured during initialization
    SanctionsPolicy sanctionsPolicyImpl = new SanctionsPolicy();
    bytes memory sanctionsPolicyData = abi.encodeWithSelector(
      Policy.initialize.selector,
      address(policyEngine),
      tokenOwner,
      abi.encode(sanctionsListAddress) // Pass sanctions list address via configData
    );
    ERC1967Proxy sanctionsPolicyProxy = new ERC1967Proxy(address(sanctionsPolicyImpl), sanctionsPolicyData);
    SanctionsPolicy sanctionsPolicy = SanctionsPolicy(address(sanctionsPolicyProxy));

    // --- Set up Extractors ---
    // An extractor is required for any function whose parameters need to be inspected by a policy.
    // While the Getting Started guide only adds policies to `transfer`, we set up extractors for all critical
    // functions to make this script a more robust starting point for your own experiments.

    // This extractor is used for both `transfer` and `transferFrom` functions.
    ERC20TransferExtractor erc20TransferExtractor = new ERC20TransferExtractor();
    policyEngine.setExtractor(mmfToken.transfer.selector, address(erc20TransferExtractor));
    policyEngine.setExtractor(mmfToken.transferFrom.selector, address(erc20TransferExtractor));

    // These extractors are included for your convenience if you wish to add policies
    // to other functions.
    ComplianceTokenMintBurnExtractor mintBurnExtractor = new ComplianceTokenMintBurnExtractor();
    policyEngine.setExtractor(mmfToken.mint.selector, address(mintBurnExtractor));
    policyEngine.setExtractor(mmfToken.burnFrom.selector, address(mintBurnExtractor));

    ComplianceTokenFreezeUnfreezeExtractor freezeUnfreezeExtractor = new ComplianceTokenFreezeUnfreezeExtractor();
    policyEngine.setExtractor(mmfToken.freeze.selector, address(freezeUnfreezeExtractor));
    policyEngine.setExtractor(mmfToken.unfreeze.selector, address(freezeUnfreezeExtractor));

    ComplianceTokenForceTransferExtractor forceTransferExtractor = new ComplianceTokenForceTransferExtractor();
    policyEngine.setExtractor(mmfToken.forceTransfer.selector, address(forceTransferExtractor));

    /*
        ================================================================
        Extractor Parameter Reference
        ================================================================
        For your convenience, here are the parameter names available
        from the extractors configured above. You will need these names
        when calling `policyEngine.addPolicy(...)` for these functions.

        - ERC20TransferExtractor:
            - For `transfer`:
                - "to" (address)
                - "amount" (uint256)
            - For `transferFrom`:
                - "from" (address)
                - "to" (address)
                - "amount" (uint256)

        - ComplianceTokenMintBurnExtractor (`mint`, `burnFrom`):
            - "account" (address)
            - "amount" (uint256)

        - ComplianceTokenFreezeUnfreezeExtractor (`freeze`, `unfreeze`):
            - "account" (address)
            - "amount" (uint256)

        - ComplianceTokenForceTransferExtractor (`forceTransfer`):
            - "from" (address)
            - "to" (address)
            - "amount" (uint256)
    */

    // --- Configure Policies for `transfer` and `transferFrom` ---
    // Now we can configure policies that use the extracted parameters.
    // Our KYC and Sanctions policies need to know the `to` address from inside the transfer() calldata.
    bytes32[] memory transferParams = new bytes32[](1);
    transferParams[0] = erc20TransferExtractor.PARAM_TO(); // Get the "to" parameter name from the extractor

    policyEngine.addPolicy(
      address(mmfToken), mmfToken.transfer.selector, address(identityValidatorPolicy), transferParams
    );
    policyEngine.addPolicy(address(mmfToken), mmfToken.transfer.selector, address(sanctionsPolicy), transferParams);

    // Apply the same policies to transferFrom
    policyEngine.addPolicy(
      address(mmfToken), mmfToken.transferFrom.selector, address(identityValidatorPolicy), transferParams
    );
    policyEngine.addPolicy(address(mmfToken), mmfToken.transferFrom.selector, address(sanctionsPolicy), transferParams);

    vm.stopBroadcast();

    // --- 4. Log Deployed Addresses ---
    console.log("--- Core Contracts ---");
    console.log("MMF Token deployed at:", address(mmfToken));
    console.log("Policy Engine deployed at:", address(policyEngine));
    console.log("Identity Registry deployed at:", address(identityRegistry));
    console.log("Credential Registry deployed at:", address(credentialRegistry));
    console.log("Sanctions List configured at:", sanctionsListAddress);
    console.log("\n--- Policies ---");
    console.log("Token OnlyOwnerPolicy (for admin functions) deployed at:", address(tokenOnlyOwnerPolicy));
    console.log("Token Minter/Burner Policy deployed at:", address(tokenMinterBurnerPolicy));
    console.log("Identity OnlyAuthorizedSenderPolicy deployed at:", address(identityOnlyAuthorizedSenderPolicy));
    console.log("CredentialRegistryIdentityValidatorPolicy deployed at:", address(identityValidatorPolicy));
    console.log("SanctionsPolicy deployed at:", address(sanctionsPolicy));
  }

  /// @notice Helper function to create and configure the CredentialRegistryIdentityValidatorPolicy.
  function createCredentialRegistryIdentityValidatorPolicy(
    PolicyEngine policyEngine,
    address tokenOwner,
    IdentityRegistry identityRegistry,
    CredentialRegistry credentialRegistry
  )
    internal
    returns (CredentialRegistryIdentityValidatorPolicy)
  {
    // This policy will require that any recipient has a valid KYC credential.
    bytes32 kycCredential = keccak256("common.kyc");

    // Define the source: where to look for credentials.
    ICredentialRequirements.CredentialSourceInput[] memory sources =
      new ICredentialRequirements.CredentialSourceInput[](1);
    sources[0] = ICredentialRequirements.CredentialSourceInput(
      kycCredential, address(identityRegistry), address(credentialRegistry), address(0)
    );

    // Define the requirement: what credentials must be present.
    bytes32[] memory requiredCredentials = new bytes32[](1);
    requiredCredentials[0] = kycCredential;
    ICredentialRequirements.CredentialRequirementInput[] memory requirements =
      new ICredentialRequirements.CredentialRequirementInput[](1);
    requirements[0] =
      ICredentialRequirements.CredentialRequirementInput(keccak256("requirement.KYC"), requiredCredentials, 1, false);

    CredentialRegistryIdentityValidatorPolicy identityValidatorPolicyImpl =
      new CredentialRegistryIdentityValidatorPolicy();
    bytes memory identityValidatorPolicyData = abi.encodeWithSelector(
      Policy.initialize.selector, address(policyEngine), tokenOwner, abi.encode(sources, requirements)
    );
    ERC1967Proxy identityValidatorPolicyProxy =
      new ERC1967Proxy(address(identityValidatorPolicyImpl), identityValidatorPolicyData);
    CredentialRegistryIdentityValidatorPolicy identityValidatorPolicy =
      CredentialRegistryIdentityValidatorPolicy(address(identityValidatorPolicyProxy));
    return identityValidatorPolicy;
  }

  function deployPolicy(
    address impl,
    address policyEngine,
    address initialOwner,
    bytes memory configData
  )
    internal
    returns (address)
  {
    return deployProxy(impl, abi.encodeWithSelector(Policy.initialize.selector, policyEngine, initialOwner, configData));
  }

  function deployProxy(address impl, bytes memory initData) internal returns (address) {
    ERC1967Proxy proxy = new ERC1967Proxy(impl, initData);
    return address(proxy);
  }
}
