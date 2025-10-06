// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Policy} from "./Policy.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

/**
 * @title PolicyFactory
 * @notice Factory contract for creating deterministic minimal proxy clones of policy implementations.
 * @dev Uses OpenZeppelin's Clones library to create deterministic minimal proxies (EIP-1167) of policy contracts.
 *      Each policy is deployed with a unique salt derived from the creator's address and a unique policy ID,
 *      ensuring deterministic addresses and preventing duplicate deployments.
 */
contract PolicyFactory {
  /// @notice Emitted when a new policy is created
  event PolicyCreated(address policy);

  /// @notice Emitted when policy initialization fails
  error PolicyInitializationFailed(bytes reason);

  /**
   * @notice Creates a new policy contract using deterministic minimal proxy cloning.
   * @dev If a policy with the same salt already exists, returns the existing address instead of reverting.
   *      Uses CREATE2 for deterministic deployment addresses. The policy is automatically initialized
   *      with the provided parameters after deployment.
   * @param implementation The address of the policy implementation contract to clone
   * @param uniquePolicyId A unique identifier for this policy (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this policy
   * @param initialOwner The address that will own the newly created policy contract
   * @param configData ABI-encoded configuration data specific to the policy implementation
   * @return policyAddress The address of the created (or existing) policy contract
   */
  function createPolicy(
    address implementation,
    bytes32 uniquePolicyId,
    address policyEngine,
    address initialOwner,
    bytes calldata configData
  )
    public
    returns (address policyAddress)
  {
    bytes32 salt = getSalt(msg.sender, uniquePolicyId);
    policyAddress = Clones.predictDeterministicAddress(implementation, salt);
    if (policyAddress.code.length > 0) {
      return policyAddress;
    }

    policyAddress = Clones.cloneDeterministic(implementation, salt);

    try Policy(policyAddress).initialize(policyEngine, initialOwner, configData) {
      emit PolicyCreated(policyAddress);
    } catch (bytes memory reason) {
      revert PolicyInitializationFailed(reason);
    }
  }

  /**
   * @notice Predicts the deterministic address where a policy would be deployed.
   * @dev Useful for calculating policy addresses before deployment or checking if a policy already exists.
   *      Uses the same salt generation as createPolicy to ensure address consistency.
   * @param creator The address of the account that would create the policy
   * @param implementation The address of the policy implementation contract
   * @param uniquePolicyId The unique identifier for the policy
   * @return The predicted address where the policy would be deployed
   */
  function predictPolicyAddress(
    address creator,
    address implementation,
    bytes32 uniquePolicyId
  )
    public
    view
    returns (address)
  {
    bytes32 salt = getSalt(creator, uniquePolicyId);
    return Clones.predictDeterministicAddress(implementation, salt);
  }

  /**
   * @notice Generates a deterministic salt for policy deployment.
   * @dev Combines the sender address and unique policy ID to create a unique salt.
   *      This ensures that the same creator cannot deploy multiple policies with the same ID,
   *      while allowing different creators to use the same policy ID.
   * @param sender The address of the policy creator
   * @param uniquePolicyId The unique identifier for the policy
   * @return The generated salt for deterministic deployment
   */
  function getSalt(address sender, bytes32 uniquePolicyId) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(sender, uniquePolicyId));
  }
}
