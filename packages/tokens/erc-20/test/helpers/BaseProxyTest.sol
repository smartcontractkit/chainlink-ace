// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

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
   * @param defaultAllow Whether the default policy engine rule will allow or reject the transaction
   * @return The deployed PolicyEngine proxy instance
   */
  function _deployPolicyEngine(bool defaultAllow, address initialOwner) internal returns (PolicyEngine) {
    PolicyEngine policyEngineImpl = new PolicyEngine();
    bytes memory policyEngineData = abi.encodeWithSelector(PolicyEngine.initialize.selector, defaultAllow, initialOwner);
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

  /**
   * @notice Encode PolicyRunRejected error for use with vm.expectRevert
   * @param policy The address of the policy that rejected the action
   * @param reason The reason for rejection
   * @param payload The payload that was rejected
   * @return The encoded error data
   */
  function _encodeRejectedRevert(
    address policy,
    string memory reason,
    IPolicyEngine.Payload memory payload
  )
    internal
    pure
    returns (bytes memory)
  {
    return abi.encodeWithSelector(IPolicyEngine.PolicyRunRejected.selector, policy, reason, payload);
  }

  /**
   * @notice Expect a PolicyRunRejected revert with a payload created from parameters
   * @param policy The address of the policy that rejected the action
   * @param reason The reason for rejection
   * @param selector The function selector
   * @param sender The sender address
   * @param data The encoded function parameters
   * @param context The context bytes (defaults to empty if not provided)
   */
  function _expectRejectedRevert(
    address policy,
    string memory reason,
    bytes4 selector,
    address sender,
    bytes memory data,
    bytes memory context
  )
    internal
  {
    IPolicyEngine.Payload memory payload =
      IPolicyEngine.Payload({selector: selector, sender: sender, data: data, context: context});
    vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyRunRejected.selector, policy, reason, payload));
  }

  /**
   * @notice Expect a PolicyRunRejected revert with a payload created from parameters (empty context)
   * @param policy The address of the policy that rejected the action
   * @param reason The reason for rejection
   * @param selector The function selector
   * @param sender The sender address
   * @param data The encoded function parameters
   */
  function _expectRejectedRevert(
    address policy,
    string memory reason,
    bytes4 selector,
    address sender,
    bytes memory data
  )
    internal
  {
    _expectRejectedRevert(policy, reason, selector, sender, data, "");
  }

  /**
   * @notice Expect a PolicyRunRejected revert with a payload
   * @param policy The address of the policy that rejected the action
   * @param reason The reason for rejection
   * @param payload The payload that was rejected
   */
  function _expectRejectedRevert(address policy, string memory reason, IPolicyEngine.Payload memory payload) internal {
    vm.expectRevert(_encodeRejectedRevert(policy, reason, payload));
  }
}
