// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {IdentityRegistry} from "../../src/IdentityRegistry.sol";
import {CredentialRegistry} from "../../src/CredentialRegistry.sol";
import {CredentialRegistryIdentityValidator} from "../../src/CredentialRegistryIdentityValidator.sol";
import {CredentialRegistryIdentityValidatorPolicy} from "../../src/CredentialRegistryIdentityValidatorPolicy.sol";
import {ICredentialRequirements} from "../../src/interfaces/ICredentialRequirements.sol";
import {TrustedIssuerRegistry} from "../../src/TrustedIssuerRegistry.sol";
/**
 * @title BaseProxyTest
 * @notice Base contract for tests that need to deploy upgradeable contracts through proxies
 * @dev Provides helper functions to deploy common contracts with proper proxy pattern
 */

abstract contract BaseProxyTest is Test {
  /**
   * @notice Deploy PolicyEngine through proxy
   * @param defaultAllow Whether the default policy engine rule will allow or reject the transaction
   * @param initialOwner The address of the initial owner of the policy engine
   * @return The deployed PolicyEngine proxy instance
   */
  function _deployPolicyEngine(bool defaultAllow, address initialOwner) internal returns (PolicyEngine) {
    PolicyEngine policyEngineImpl = new PolicyEngine();
    bytes memory policyEngineData = abi.encodeWithSelector(PolicyEngine.initialize.selector, defaultAllow, initialOwner);
    ERC1967Proxy policyEngineProxy = new ERC1967Proxy(address(policyEngineImpl), policyEngineData);
    return PolicyEngine(address(policyEngineProxy));
  }

  /**
   * @notice Deploy IdentityRegistry through proxy
   * @param policyEngine The address of the policy engine contract
   * @return The deployed IdentityRegistry proxy instance
   */
  function _deployIdentityRegistry(address policyEngine) internal returns (IdentityRegistry) {
    IdentityRegistry identityRegistryImpl = new IdentityRegistry();
    bytes memory identityRegistryData =
      abi.encodeWithSelector(IdentityRegistry.initialize.selector, policyEngine, address(this));
    ERC1967Proxy identityRegistryProxy = new ERC1967Proxy(address(identityRegistryImpl), identityRegistryData);
    return IdentityRegistry(address(identityRegistryProxy));
  }

  /**
   * @notice Deploy CredentialRegistry through proxy
   * @param policyEngine The address of the policy engine contract
   * @return The deployed CredentialRegistry proxy instance
   */
  function _deployCredentialRegistry(address policyEngine) internal returns (CredentialRegistry) {
    CredentialRegistry credentialRegistryImpl = new CredentialRegistry();
    bytes memory credentialRegistryData =
      abi.encodeWithSelector(CredentialRegistry.initialize.selector, policyEngine, address(this));
    ERC1967Proxy credentialRegistryProxy = new ERC1967Proxy(address(credentialRegistryImpl), credentialRegistryData);
    return CredentialRegistry(address(credentialRegistryProxy));
  }

  function _deployTrustedIssuerRegistry(address policyEngine) internal returns (TrustedIssuerRegistry) {
    TrustedIssuerRegistry impl = new TrustedIssuerRegistry();
    bytes memory data = abi.encodeWithSelector(TrustedIssuerRegistry.initialize.selector, policyEngine, address(this));
    ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
    return TrustedIssuerRegistry(address(proxy));
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
  function _deployCredentialRegistryCredentialRegistryIdentityValidatorPolicy(
    address policyEngine,
    address owner,
    bytes memory parameters
  )
    internal
    returns (CredentialRegistryIdentityValidatorPolicy)
  {
    CredentialRegistryIdentityValidatorPolicy identityValidatorPolicyImpl =
      new CredentialRegistryIdentityValidatorPolicy();
    bytes memory identityValidatorPolicyData =
      abi.encodeWithSelector(Policy.initialize.selector, policyEngine, owner, parameters);
    ERC1967Proxy identityValidatorPolicyProxy =
      new ERC1967Proxy(address(identityValidatorPolicyImpl), identityValidatorPolicyData);
    return CredentialRegistryIdentityValidatorPolicy(address(identityValidatorPolicyProxy));
  }
}
