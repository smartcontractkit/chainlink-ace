// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IdentityRegistry} from "./IdentityRegistry.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title IdentityRegistryFactory
 * @notice Factory contract for creating deterministic minimal proxy clones of identity registry implementations.
 * @dev Uses OpenZeppelin's Clones library to create deterministic minimal proxies (EIP-1167) of identity
 *      registry contracts.
 *      Each registry is deployed with a unique salt derived from the creator's address and a unique registry ID,
 *      ensuring deterministic addresses and preventing duplicate deployments.
 */
contract IdentityRegistryFactory {
  /// @notice Emitted when a new identity registry is created
  event IdentityRegistryCreated(address registry);

  /// @notice Raised when the identity registry unexpectedly already exists
  error IdentityRegistryAlreadyExists();

  /// @notice Emitted when registry initialization fails
  error RegistryInitializationFailed(bytes reason);

  /// @notice Emitted when implementation address is zero
  error ImplementationIsZeroAddress();

  /**
   * @notice Creates a new identity registry contract using deterministic minimal proxy cloning, reverting if the
   *        existing address if the registry already exists.
   * @param implementation The address of the identity registry implementation contract to clone
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created registry contract
   */
  function createIdentityRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    returns (address registryAddress)
  {
    return _createIdentityRegistry(implementation, uniqueRegistryId, policyEngine, initialOwner, false);
  }

  /**
   * @notice Creates a new identity registry contract using deterministic minimal proxy cloning, returning the existing
   *         address if the registry already exists.
   * @param implementation The address of the identity registry implementation contract to clone
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created (or existing) registry contract
   */
  function getOrCreateIdentityRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    returns (address registryAddress)
  {
    return _createIdentityRegistry(implementation, uniqueRegistryId, policyEngine, initialOwner, true);
  }

  /**
   * @dev Creates a new identity registry contract using deterministic minimal proxy cloning.
   *      Uses CREATE2 (via OpenZeppelin Clones) for deterministic deployment addresses. The registry is automatically
   *      initialized with the provided parameters after deployment.
   *      If an engine with the same salt already exists:
   *         idempotent is false - revert the creation.
   *         idempotent is true - return the existing address.
   */
  function _createIdentityRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner,
    bool idempotent
  )
    internal
    returns (address registryAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();

    bytes32 salt = getSalt(msg.sender, uniqueRegistryId);
    registryAddress = Clones.predictDeterministicAddress(implementation, salt);
    if (registryAddress.code.length > 0) {
      if (idempotent) {
        return registryAddress;
      } else {
        revert IdentityRegistryAlreadyExists();
      }
    }

    registryAddress = Clones.cloneDeterministic(implementation, salt);
    try IdentityRegistry(registryAddress).initialize(policyEngine, initialOwner) {
      emit IdentityRegistryCreated(registryAddress);
    } catch Error(string memory reason) {
      revert RegistryInitializationFailed(bytes(reason));
    } catch (bytes memory reason) {
      revert RegistryInitializationFailed(reason);
    }
  }

  /**
   * @notice Predicts the deterministic address where an identity registry would be deployed.
   * @dev Useful for calculating registry addresses before deployment or checking if a registry already exists.
   *      Uses the same salt generation as _createIdentityRegistry to ensure address consistency.
   * @param creator The address of the account that would create the registry
   * @param implementation The address of the identity registry implementation contract
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
   * @notice  Creates a new identity registry contract using an upgradeable deterministic proxy, reverting if the
   *          existing address if the registry already exists.
   * @param implementation The address of the identity registry implementation contract to clone
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created registry contract
   */
  function createUpgradeableIdentityRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    returns (address registryAddress)
  {
    return _createUpgradeableIdentityRegistry(implementation, uniqueRegistryId, policyEngine, initialOwner, false);
  }

  /**
   * @notice  Creates a new identity registry contract using an upgradeable deterministic proxy, returning the existing
   *         address if the registry already exists.
   * @param implementation The address of the identity registry implementation contract to clone
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created (or existing) registry contract
   */
  function getOrCreateUpgradeableIdentityRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    returns (address registryAddress)
  {
    return _createUpgradeableIdentityRegistry(implementation, uniqueRegistryId, policyEngine, initialOwner, true);
  }

  /**
   * @dev Creates a new identity registry contract using an upgradeable deterministic proxy.
   *      Uses CREATE2 for deterministic deployment addresses. The registry is automatically initialized with the
   *      provided parameters during deployment.
   *      If a registry with the same salt already exists:
   *         idempotent is false - revert the creation.
   *         idempotent is true - return the existing address.
   */
  function _createUpgradeableIdentityRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner,
    bool idempotent
  )
    internal
    returns (address registryAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();

    bytes memory initData = abi.encodeWithSelector(IdentityRegistry.initialize.selector, policyEngine, initialOwner);
    bytes memory creationCode = _ERC1967ProxyCreationCode(implementation, initData);
    bytes32 salt = getSalt(msg.sender, uniqueRegistryId);
    registryAddress = Create2.computeAddress(salt, keccak256(creationCode));

    if (registryAddress.code.length > 0) {
      if (idempotent) {
        return registryAddress;
      } else {
        revert IdentityRegistryAlreadyExists();
      }
    }

    registryAddress = Create2.deploy(0, salt, creationCode);
    emit IdentityRegistryCreated(registryAddress);
  }

  /**
   * @notice Predicts the deterministic address where an upgradeable identity registry would be deployed.
   * @dev Useful for calculating registry addresses before deployment or checking if a registry already exists.
   *      Uses the same salt generation as createUpgradeableIdentityRegistry to ensure address consistency.
   * @param creator The address of the account that would create the registry
   * @param implementation The address of the identity registry implementation contract
   * @param uniqueRegistryId The unique identifier for the registry
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return The predicted address where the registry would be deployed
   */
  function predictUpgradeableRegistryAddress(
    address creator,
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    view
    returns (address)
  {
    bytes32 salt = getSalt(creator, uniqueRegistryId);
    bytes memory initData = abi.encodeWithSelector(IdentityRegistry.initialize.selector, policyEngine, initialOwner);
    return Create2.computeAddress(salt, keccak256(_ERC1967ProxyCreationCode(implementation, initData)));
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

  /**
   * @dev Encodes the full initcode for `new ERC1967Proxy(implementation, initData)`.
   *      This is identical to what the Solidity compiler emits for that expression,
   *      ensuring the CREATE2 address matches a direct `new` deployment.
   */
  function _ERC1967ProxyCreationCode(
    address implementation,
    bytes memory initData
  )
    internal
    pure
    returns (bytes memory)
  {
    return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, initData));
  }
}
