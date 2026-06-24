// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PolicyEngine} from "../../../policy-management/src/core/PolicyEngine.sol";
import {PolicyFactory} from "../../../policy-management/src/core/PolicyFactory.sol";
import {IdentityRegistry} from "../../src/IdentityRegistry.sol";
import {CredentialRegistry} from "../../src/CredentialRegistry.sol";
import {CredentialRegistryIdentityValidator} from "../../src/CredentialRegistryIdentityValidator.sol";
import {CredentialRegistryIdentityValidatorPolicy} from "../../src/CredentialRegistryIdentityValidatorPolicy.sol";
import {ICredentialRequirements} from "../../src/interfaces/ICredentialRequirements.sol";
import {TrustedIssuerRegistry} from "../../src/TrustedIssuerRegistry.sol";
import {PolicyEngineFactory} from "../../../policy-management/src/core/PolicyEngineFactory.sol";
import {IdentityRegistryFactory} from "../../src/IdentityRegistryFactory.sol";
import {CredentialRegistryFactory} from "../../src/CredentialRegistryFactory.sol";
import {TrustedIssuerRegistryFactory} from "../../src/TrustedIssuerRegistryFactory.sol";

/**
 * @title BaseProxyTest
 * @notice Base contract for tests that need to deploy upgradeable contracts through proxies
 * @dev Provides helper functions to deploy common contracts with proper proxy pattern
 */
abstract contract BaseProxyTest is Test {
  PolicyEngineFactory internal s_policyEngineFactory = new PolicyEngineFactory();
  IdentityRegistryFactory internal s_identityRegistryFactory = new IdentityRegistryFactory();
  CredentialRegistryFactory internal s_credentialRegistryFactory = new CredentialRegistryFactory();
  TrustedIssuerRegistryFactory internal s_trustedIssuerRegistryFactory = new TrustedIssuerRegistryFactory();
  PolicyFactory internal s_policyFactory = new PolicyFactory();

  PolicyEngine internal s_policyEngineImpl = new PolicyEngine();
  IdentityRegistry internal s_identityRegistryImpl = new IdentityRegistry();
  CredentialRegistry internal s_credentialRegistryImpl = new CredentialRegistry();
  TrustedIssuerRegistry internal s_trustedIssuerRegistryImpl = new TrustedIssuerRegistry();

  uint256 internal s_policyEngineNonce = 0;
  uint256 internal s_identityRegistryNonce = 0;
  uint256 internal s_credentialRegistryNonce = 0;
  uint256 internal s_trustedIssuerRegistryNonce = 0;
  uint256 internal s_policyNonce = 0;

  /**
   * @notice Deploy PolicyEngine through proxy
   * @param defaultAllow Whether the default policy engine rule will allow or reject the transaction
   * @param initialOwner The address of the initial owner of the policy engine
   * @return The deployed PolicyEngine proxy instance
   */
  function _deployPolicyEngine(bool defaultAllow, address initialOwner) internal returns (PolicyEngine) {
    address policyEngine = s_policyEngineFactory.createUpgradeablePolicyEngine(
      address(s_policyEngineImpl), bytes32(s_policyEngineNonce++), defaultAllow, initialOwner
    );
    return PolicyEngine(policyEngine);
  }

  /**
   * @notice Deploy IdentityRegistry through proxy
   * @param policyEngine The address of the policy engine contract
   * @return The deployed IdentityRegistry proxy instance
   */
  function _deployIdentityRegistry(address policyEngine) internal returns (IdentityRegistry) {
    address identityRegistry = s_identityRegistryFactory.createUpgradeableIdentityRegistry(
      address(s_identityRegistryImpl), bytes32(s_identityRegistryNonce++), policyEngine, address(this)
    );
    return IdentityRegistry(identityRegistry);
  }

  /**
   * @notice Deploy CredentialRegistry through proxy
   * @param policyEngine The address of the policy engine contract
   * @return The deployed CredentialRegistry proxy instance
   */
  function _deployCredentialRegistry(address policyEngine) internal returns (CredentialRegistry) {
    address credentialRegistry = s_credentialRegistryFactory.createUpgradeableCredentialRegistry(
      address(s_credentialRegistryImpl), bytes32(s_credentialRegistryNonce++), policyEngine, address(this)
    );
    return CredentialRegistry(credentialRegistry);
  }

  function _deployTrustedIssuerRegistry(address policyEngine) internal returns (TrustedIssuerRegistry) {
    address trustedIssuerRegistry = s_trustedIssuerRegistryFactory.createUpgradeableTrustedIssuerRegistry(
      address(s_trustedIssuerRegistryImpl), bytes32(s_trustedIssuerRegistryNonce++), policyEngine, address(this)
    );
    return TrustedIssuerRegistry(trustedIssuerRegistry);
  }

  /**
   * @notice Deploy IdentityValidator through proxy
   * @param credentialSources Initial credential sources
   * @param credentialRequirements Initial credential requirements
   * @return The deployed IdentityValidator proxy instance
   */
  function _deployCredentialRegistryIdentityValidator(
    ICredentialRequirements.CredentialSourceInput[] memory credentialSources,
    ICredentialRequirements.CredentialRequirementInput[] memory credentialRequirements
  )
    internal
    returns (CredentialRegistryIdentityValidator)
  {
    CredentialRegistryIdentityValidator identityValidatorImpl = new CredentialRegistryIdentityValidator();
    bytes memory identityValidatorData = abi.encodeWithSelector(
      CredentialRegistryIdentityValidator.initialize.selector, credentialSources, credentialRequirements
    );
    ERC1967Proxy identityValidatorProxy = new ERC1967Proxy(address(identityValidatorImpl), identityValidatorData);
    return CredentialRegistryIdentityValidator(address(identityValidatorProxy));
  }

  /**
   * @notice Deploy CredentialRegistryIdentityValidatorPolicy through proxy
   * @param policyEngine The address of the policy engine contract
   * @param owner The address of the policy owner
   * @param parameters ABI-encoded parameters for policy initialization
   * @return The deployed CredentialRegistryIdentityValidatorPolicy proxy instance
   */
  function _deployCredentialRegistryIdentityValidatorPolicy(
    address policyEngine,
    address owner,
    bytes memory parameters
  )
    internal
    returns (CredentialRegistryIdentityValidatorPolicy)
  {
    CredentialRegistryIdentityValidatorPolicy policyImpl = new CredentialRegistryIdentityValidatorPolicy();
    address policy = s_policyFactory.createUpgradeablePolicy(
      address(policyImpl), bytes32(s_policyNonce++), policyEngine, owner, parameters
    );
    return CredentialRegistryIdentityValidatorPolicy(policy);
  }
}
