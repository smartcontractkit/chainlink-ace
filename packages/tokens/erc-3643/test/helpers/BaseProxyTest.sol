// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IPolicyEngine} from "../../../../policy-management/src/interfaces/IPolicyEngine.sol";
import {PolicyEngineFactory} from "../../../../policy-management/src/core/PolicyEngineFactory.sol";
import {PolicyEngine} from "../../../../policy-management/src/core/PolicyEngine.sol";
import {PolicyFactory} from "../../../../policy-management/src/core/PolicyFactory.sol";
import {Policy} from "../../../../policy-management/src/core/Policy.sol";
import {ComplianceTokenERC3643} from "../../src/ComplianceTokenERC3643.sol";

/**
 * @title BaseProxyTest
 * @notice Base contract for ERC-3643 token tests that need to deploy upgradeable contracts through proxies
 * @dev Provides helper functions to deploy common ERC-3643 token contracts with proper proxy pattern
 */
abstract contract BaseProxyTest is Test {
  PolicyEngineFactory internal s_policyEngineFactory = new PolicyEngineFactory();
  PolicyFactory internal s_policyFactory = new PolicyFactory();

  PolicyEngine internal s_policyEngineImpl = new PolicyEngine();

  uint256 internal s_policyEngineNonce = 0;
  uint256 internal s_policyNonce = 0;

  /**
   * @notice Deploy PolicyEngine through proxy
   * @param defaultAllow Whether the default policy engine rule will allow or reject the transaction
   * @param initialOwner The address of the initial owner of the policy engine
   * @return The deployed PolicyEngine proxy instance
   */
  function _deployPolicyEngine(bool defaultAllow, address initialOwner) internal returns (PolicyEngine) {
    address policyEngine = s_policyEngineFactory.createPolicyEngine(
      address(s_policyEngineImpl), bytes32(s_policyEngineNonce++), defaultAllow, initialOwner
    );
    return PolicyEngine(policyEngine);
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
    return s_policyFactory.createPolicy(address(policyImpl), bytes32(s_policyNonce++), policyEngine, owner, parameters);
  }

  /**
   * @notice Deploy ComplianceTokenERC3643 through proxy
   * @param tokenName The name of the token
   * @param tokenSymbol The symbol of the token
   * @param tokenDecimals The number of decimals for the token
   * @param policyEngine The address of the policy engine contract
   * @return The deployed ComplianceTokenERC3643 proxy instance
   */
  function _deployComplianceTokenERC3643(
    string memory tokenName,
    string memory tokenSymbol,
    uint8 tokenDecimals,
    address policyEngine
  )
    internal
    returns (ComplianceTokenERC3643)
  {
    ComplianceTokenERC3643 tokenImpl = new ComplianceTokenERC3643();
    bytes memory tokenData = abi.encodeWithSelector(
      ComplianceTokenERC3643.initialize.selector, tokenName, tokenSymbol, tokenDecimals, policyEngine
    );
    ERC1967Proxy tokenProxy = new ERC1967Proxy(address(tokenImpl), tokenData);
    return ComplianceTokenERC3643(address(tokenProxy));
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
   * @notice Expect a PolicyRunRejected revert with a payload
   * @param policy The address of the policy that rejected the action
   * @param reason The reason for rejection
   * @param payload The payload that was rejected
   */
  function _expectRejectedRevert(address policy, string memory reason, IPolicyEngine.Payload memory payload) internal {
    vm.expectRevert(_encodeRejectedRevert(policy, reason, payload));
  }
}
