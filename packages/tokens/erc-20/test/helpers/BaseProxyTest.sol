// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {ComplianceTokenERC20} from "../../src/ComplianceTokenERC20.sol";

/**
 * @title BaseProxyTest
 * @notice Base contract for ERC-20 token tests that need to deploy upgradeable contracts through proxies
 * @dev Provides helper functions to deploy common ERC-20 token contracts with proper proxy pattern
 */
abstract contract BaseProxyTest is Test {
  /**
   * @notice Deploy PolicyEngine through proxy
   * @param defaultPolicyResult The default policy result for the engine
   * @return The deployed PolicyEngine proxy instance
   */
  function _deployPolicyEngine(
    IPolicyEngine.PolicyResult defaultPolicyResult,
    address initialOwner
  )
    internal
    returns (PolicyEngine)
  {
    PolicyEngine policyEngineImpl = new PolicyEngine();
    bytes memory policyEngineData =
      abi.encodeWithSelector(PolicyEngine.initialize.selector, defaultPolicyResult, initialOwner);
    ERC1967Proxy policyEngineProxy = new ERC1967Proxy(address(policyEngineImpl), policyEngineData);
    return PolicyEngine(address(policyEngineProxy));
  }

  /**
   * @notice Deploy any Policy-based contract through proxy
   * @param policyImpl The implementation contract (must inherit from Policy)
   * @param policyEngine The address of the policy engine contract
   * @param owner The address of the policy owner
   * @param parameters ABI-encoded parameters for policy initialization
   * @return The deployed policy proxy address
   */
  function _deployPolicy(
    address policyImpl,
    address policyEngine,
    address owner,
    bytes memory parameters
  )
    internal
    returns (address)
  {
    bytes memory policyData = abi.encodeWithSelector(Policy.initialize.selector, policyEngine, owner, parameters);
    ERC1967Proxy policyProxy = new ERC1967Proxy(policyImpl, policyData);
    return address(policyProxy);
  }

  /**
   * @notice Deploy ComplianceTokenERC20 through proxy
   * @param tokenName The name of the token
   * @param tokenSymbol The symbol of the token
   * @param tokenDecimals The number of decimals for the token
   * @param policyEngine The address of the policy engine contract
   * @return The deployed ComplianceTokenERC20 proxy instance
   */
  function _deployComplianceTokenERC20(
    string memory tokenName,
    string memory tokenSymbol,
    uint8 tokenDecimals,
    address policyEngine
  )
    internal
    returns (ComplianceTokenERC20)
  {
    ComplianceTokenERC20 tokenImpl = new ComplianceTokenERC20();
    bytes memory tokenData = abi.encodeWithSelector(
      ComplianceTokenERC20.initialize.selector, tokenName, tokenSymbol, tokenDecimals, policyEngine
    );
    ERC1967Proxy tokenProxy = new ERC1967Proxy(address(tokenImpl), tokenData);
    return ComplianceTokenERC20(address(tokenProxy));
  }
}
