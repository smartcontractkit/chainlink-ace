// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {CredentialRegistry} from "./CredentialRegistry.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

/**
 * @title CredentialRegistryFactory
 * @notice Factory contract for creating deterministic minimal proxy clones of credential registry implementations.
 * @dev Uses OpenZeppelin's Clones library to create deterministic minimal proxies (EIP-1167) of credential
 *      registry contracts.
 *      Each registry is deployed with a unique salt derived from the creator's address and a unique registry ID,
 *      ensuring deterministic addresses and preventing duplicate deployments.
 */
contract CredentialRegistryFactory {
  /// @notice Emitted when a new credential registry is created
  event CredentialRegistryCreated(address registry);

  /// @notice Emitted when registry initialization fails
  error RegistryInitializationFailed(bytes reason);

  /// @notice Emitted when implementation address is zero
  error ImplementationIsZeroAddress();

  /**
   * @notice Creates a new credential registry contract using deterministic minimal proxy cloning.
   * @dev If a registry with the same salt already exists, returns the existing address instead of reverting.
   *      Uses CREATE2 for deterministic deployment addresses. The registry is automatically initialized
   *      with the provided parameters after deployment.
   * @param implementation The address of the credential registry implementation contract to clone
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created (or existing) registry contract
   */
  function createCredentialRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    returns (address registryAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();

    bytes32 salt = getSalt(msg.sender, uniqueRegistryId);
    registryAddress = Clones.predictDeterministicAddress(implementation, salt);
    if (registryAddress.code.length > 0) {
      return registryAddress;
    }

    registryAddress = Clones.cloneDeterministic(implementation, salt);

    try CredentialRegistry(registryAddress).initialize(policyEngine, initialOwner) {
      emit CredentialRegistryCreated(registryAddress);
    } catch (bytes memory reason) {
      revert RegistryInitializationFailed(reason);
    }
  }

  /**
   * @notice Predicts the deterministic address where a credential registry would be deployed.
   * @dev Useful for calculating registry addresses before deployment or checking if a registry already exists.
   *      Uses the same salt generation as createCredentialRegistry to ensure address consistency.
   * @param creator The address of the account that would create the registry
   * @param implementation The address of the credential registry implementation contract
   * @param uniqueRegistryId The unique identifier for the registry
   * @return The predicted address where the registry would be deployed
   */
  function predictRegistryAddress(
    address creator,
    address implementation,
    bytes32 uniqueRegistryId
  )
    public
    view
    returns (address)
  {
    bytes32 salt = getSalt(creator, uniqueRegistryId);
    return Clones.predictDeterministicAddress(implementation, salt);
  }

  /**
   * @notice Generates a deterministic salt for registry deployment.
   * @dev Combines the sender address and unique registry ID to create a unique salt.
   *      This ensures that the same creator cannot deploy multiple registries with the same ID,
   *      while allowing different creators to use the same registry ID.
   * @param sender The address of the registry creator
   * @param uniqueRegistryId The unique identifier for the registry
   * @return The generated salt for deterministic deployment
   */
  function getSalt(address sender, bytes32 uniqueRegistryId) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(sender, uniqueRegistryId));
  }
}
