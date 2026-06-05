// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {PolicyEngineFactory} from "../../src/core/PolicyEngineFactory.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {PolicyFactory} from "../../src/core/PolicyFactory.sol";
import {MockTokenUpgradeable} from "./MockTokenUpgradeable.sol";
import {MockTokenFlexibleUpgradeable} from "./MockTokenFlexibleUpgradeable.sol";

/**
 * @title BaseProxyTest
 * @notice Base contract for policy-management tests that need to deploy upgradeable contracts through proxies
 * @dev Provides helper functions to deploy common policy-management contracts with proper proxy pattern
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
    address policyEngine = s_policyEngineFactory.createUpgradeablePolicyEngine(
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
    return s_policyFactory.createUpgradeablePolicy(
      address(policyImpl), bytes32(s_policyNonce++), policyEngine, owner, parameters
    );
  }

  /**
   * @notice Deploy MockTokenUpgradeable through proxy
   * @param policyEngine The address of the policy engine contract
   * @return The deployed MockTokenUpgradeable proxy address
   */
  function _deployMockToken(address policyEngine) internal returns (address) {
    // Import and create MockToken implementation
    MockTokenUpgradeable mockTokenImpl = new MockTokenUpgradeable();
    bytes memory mockTokenData = abi.encodeWithSelector(MockTokenUpgradeable.initialize.selector, policyEngine);
    ERC1967Proxy mockTokenProxy = new ERC1967Proxy(address(mockTokenImpl), mockTokenData);
    return address(mockTokenProxy);
  }

  /**
   * @notice Deploy MockTokenFlexibleUpgradeable through proxy
   * @param policyEngine The address of the policy engine contract
   * @return The deployed MockTokenFlexibleUpgradeable proxy address
   */
  function _deployMockFlexibleToken(address policyEngine) internal returns (address) {
    // Import and create MockToken implementation
    MockTokenFlexibleUpgradeable mockTokenImpl = new MockTokenFlexibleUpgradeable();
    bytes memory mockTokenData = abi.encodeWithSelector(MockTokenFlexibleUpgradeable.initialize.selector, policyEngine);
    ERC1967Proxy mockTokenProxy = new ERC1967Proxy(address(mockTokenImpl), mockTokenData);
    return address(mockTokenProxy);
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
    _expectRejectedRevert(policy, reason, payload);
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
   * @notice Expect a PolicyRunError revert with a payload
   * @param policy The address of the policy that caused the error
   * @param error The encoded error data
   * @param payload The payload that caused the error
   */
  function _expectRunError(address policy, bytes memory error, IPolicyEngine.Payload memory payload) internal {
    vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyRunError.selector, policy, error, payload));
  }

  /**
   * @notice Expect a PolicyPostRunError revert with a payload
   * @param policy The address of the policy that caused the error
   * @param error The encoded error data
   * @param payload The payload that caused the error
   */
  function _expectPostRunError(address policy, bytes memory error, IPolicyEngine.Payload memory payload) internal {
    vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyPostRunError.selector, policy, error, payload));
  }
}
