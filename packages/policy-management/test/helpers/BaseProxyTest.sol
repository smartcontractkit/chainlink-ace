// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {Policy} from "../../src/core/Policy.sol";
import {MockToken} from "./MockToken.sol";

/**
 * @title BaseProxyTest
 * @notice Base contract for policy-management tests that need to deploy upgradeable contracts through proxies
 * @dev Provides helper functions to deploy common policy-management contracts with proper proxy pattern
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
   * @notice Deploy MockToken through proxy
   * @param policyEngine The address of the policy engine contract
   * @return The deployed MockToken proxy address
   */
  function _deployMockToken(address policyEngine) internal returns (address) {
    // Import and create MockToken implementation
    MockToken mockTokenImpl = new MockToken();
    bytes memory mockTokenData = abi.encodeWithSelector(MockToken.initialize.selector, policyEngine);
    ERC1967Proxy mockTokenProxy = new ERC1967Proxy(address(mockTokenImpl), mockTokenData);
    return address(mockTokenProxy);
  }
}
