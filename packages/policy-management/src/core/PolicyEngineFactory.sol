// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {PolicyEngine} from "./PolicyEngine.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

/**
 * @title PolicyEngineFactory
 * @notice Factory contract for creating deterministic minimal proxy clones of policy engine implementations.
 * @dev Uses OpenZeppelin's Clones library to create deterministic minimal proxies (EIP-1167) of policy
 *      engine contracts.
 *      Each engine is deployed with a unique salt derived from the creator's address and a unique engine ID,
 *      ensuring deterministic addresses and preventing duplicate deployments.
 */
contract PolicyEngineFactory {
  /// @notice Emitted when a new policy engine is created
  event PolicyEngineCreated(address engine);

  /// @notice Raised when engine initialization fails
  error EngineInitializationFailed(bytes reason);

  /// @notice Raised when the implementation address is the zero address
  error ImplementationIsZeroAddress();

  /// @notice Raised when the owner address is the zero address
  error InitialOwnerIsZeroAddress();

  /**
   * @notice Creates a new policy engine contract using deterministic minimal proxy cloning.
   * @dev If an engine with the same salt already exists, returns the existing address instead of reverting.
   *      Uses CREATE2 for deterministic deployment addresses. The engine is automatically initialized
   *      with the provided parameters after deployment.
   * @param implementation The address of the policy engine implementation contract to clone
   * @param uniqueEngineId A unique identifier for this engine (combined with msg.sender to create salt)
   * @param policyEngineDefaultAllow Default policy result for the policy engine: true allows by default, false rejects
   * by default
   * @param initialOwner The address that will own the newly created engine contract
   * @return engineAddress The address of the created (or existing) engine contract
   */
  function createPolicyEngine(
    address implementation,
    bytes32 uniqueEngineId,
    bool policyEngineDefaultAllow,
    address initialOwner
  )
    public
    returns (address engineAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();
    if (initialOwner == address(0)) revert InitialOwnerIsZeroAddress();

    bytes32 salt = getSalt(msg.sender, uniqueEngineId);
    engineAddress = Clones.predictDeterministicAddress(implementation, salt);
    if (engineAddress.code.length > 0) {
      return engineAddress;
    }

    engineAddress = Clones.cloneDeterministic(implementation, salt);

    try PolicyEngine(engineAddress).initialize(policyEngineDefaultAllow, initialOwner) {
      emit PolicyEngineCreated(engineAddress);
    } catch (bytes memory reason) {
      revert EngineInitializationFailed(reason);
    }
  }

  /**
   * @notice Predicts the deterministic address where a policy engine would be deployed.
   * @dev Useful for calculating engine addresses before deployment or checking if an engine already exists.
   *      Uses the same salt generation as createPolicyEngine to ensure address consistency.
   * @param creator The address of the account that would create the engine
   * @param implementation The address of the policy engine implementation contract
   * @param uniqueEngineId The unique identifier for the engine
   * @return The predicted address where the engine would be deployed
   */
  function predictEngineAddress(
    address creator,
    address implementation,
    bytes32 uniqueEngineId
  )
    public
    view
    returns (address)
  {
    bytes32 salt = getSalt(creator, uniqueEngineId);
    return Clones.predictDeterministicAddress(implementation, salt);
  }

  /**
   * @notice Generates a deterministic salt for engine deployment.
   * @dev Combines the sender address and unique engine ID to create a unique salt.
   *      This ensures that the same creator cannot deploy multiple engines with the same ID,
   *      while allowing different creators to use the same engine ID.
   * @param sender The address of the engine creator
   * @param uniqueEngineId The unique identifier for the engine
   * @return The generated salt for deterministic deployment
   */
  function getSalt(address sender, bytes32 uniqueEngineId) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(sender, uniqueEngineId));
  }
}
