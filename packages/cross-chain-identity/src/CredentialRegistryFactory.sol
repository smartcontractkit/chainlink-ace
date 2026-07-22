// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {CredentialRegistry} from "./CredentialRegistry.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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

  /// @notice Raised when the credential registry unexpectedly already exists
  error CredentialRegistryAlreadyExists();

  /// @notice Emitted when registry initialization fails
  error RegistryInitializationFailed(bytes reason);

  /// @notice Emitted when implementation address is zero
  error ImplementationIsZeroAddress();

  /**
   * @notice Creates a new credential registry contract using deterministic minimal proxy cloning, reverting if the
   *         existing address if the registry already exists.
   * @param implementation The address of the credential registry implementation contract to clone
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created registry contract
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
    return _createCredentialRegistry(implementation, uniqueRegistryId, policyEngine, initialOwner, false);
  }

  /**
   * @notice Creates a new credential registry contract using deterministic minimal proxy cloning, returning the
   *         existing address if the registry already exists.
   * @param implementation The address of the credential registry implementation contract to clone
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created (or existing) registry contract
   */
  function getOrCreateCredentialRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    returns (address registryAddress)
  {
    return _createCredentialRegistry(implementation, uniqueRegistryId, policyEngine, initialOwner, true);
  }

  /**
   * @dev Creates a new credential registry contract using deterministic minimal proxy cloning.
   *      Uses CREATE2 (via OpenZeppelin Clones) for deterministic deployment addresses. The registry is automatically
   *      initialized with the provided parameters after deployment.
   *      If an engine with the same salt already exists:
   *         idempotent is false - revert the creation.
   *         idempotent is true - return the existing address.
   */
  function _createCredentialRegistry(
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
        revert CredentialRegistryAlreadyExists();
      }
    }

    registryAddress = Clones.cloneDeterministic(implementation, salt);
    try CredentialRegistry(registryAddress).initialize(policyEngine, initialOwner) {
      emit CredentialRegistryCreated(registryAddress);
    } catch Error(string memory reason) {
      revert RegistryInitializationFailed(bytes(reason));
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
   * @notice  Creates a new credential registry contract using an upgradeable deterministic proxy, reverting if the
   *          existing address if the registry already exists.
   * @param implementation The address of the credential registry implementation
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created registry contract
   */
  function createUpgradeableCredentialRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    returns (address registryAddress)
  {
    return _createUpgradeableCredentialRegistry(implementation, uniqueRegistryId, policyEngine, initialOwner, false);
  }

  /**
   * @notice  Creates a new credential registry contract using an upgradeable deterministic proxy, returning the
   *          existing address if the registry already exists.
   * @param implementation The address of the credential registry implementation
   * @param uniqueRegistryId A unique identifier for this registry (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this registry
   * @param initialOwner The address that will own the newly created registry contract
   * @return registryAddress The address of the created (or existing) registry contract
   */
  function getOrCreateUpgradeableCredentialRegistry(
    address implementation,
    bytes32 uniqueRegistryId,
    address policyEngine,
    address initialOwner
  )
    public
    returns (address registryAddress)
  {
    return _createUpgradeableCredentialRegistry(implementation, uniqueRegistryId, policyEngine, initialOwner, true);
  }

  /**
   * @dev Creates a new credential registry contract using an upgradeable deterministic proxy.
   *      Uses CREATE2 for deterministic deployment addresses. The registry is automatically initialized with the
   *      provided parameters during deployment.
   *      If a registry with the same salt already exists:
   *         idempotent is false - revert the creation.
   *         idempotent is true - return the existing address.
   *
   *      Note: unlike the minimal-clone path, `uniqueRegistryId` alone does NOT identify a registry here. The CREATE2
   *      address is computed from the proxy creation code, which embeds the init data (`policyEngine` and
   *      `initialOwner`). The same (creator, uniqueRegistryId) with a different `policyEngine` or `initialOwner`
   *      therefore deploys to a different address. This is not a hijack risk - the salt still binds `msg.sender`, so no
   *      one can deploy at another creator's address, and CREATE2 reverts on a pre-occupied address. Off-chain systems
   *      indexing registries by (creator, uniqueRegistryId) must not assume a single address for the upgradeable path.
   */
  function _createUpgradeableCredentialRegistry(
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

    bytes memory initData = abi.encodeWithSelector(CredentialRegistry.initialize.selector, policyEngine, initialOwner);
    bytes memory creationCode = _ERC1967ProxyCreationCode(implementation, initData);
    bytes32 salt = getSalt(msg.sender, uniqueRegistryId);
    registryAddress = Create2.computeAddress(salt, keccak256(creationCode));

    if (registryAddress.code.length > 0) {
      if (idempotent) {
        return registryAddress;
      } else {
        revert CredentialRegistryAlreadyExists();
      }
    }

    registryAddress = Create2.deploy(0, salt, creationCode);
    emit CredentialRegistryCreated(registryAddress);
  }

  /**
   * @notice Predicts the deterministic address where an upgradeable credential registry would be deployed.
   * @dev Useful for calculating registry addresses before deployment or checking if a registry already exists.
   *      Uses the same salt generation as createCredentialRegistry to ensure address consistency.
   * @param creator The address of the account that would create the registry
   * @param implementation The address of the credential registry implementation contract
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
    external
    view
    returns (address)
  {
    bytes32 salt = getSalt(creator, uniqueRegistryId);
    bytes memory initData = abi.encodeWithSelector(CredentialRegistry.initialize.selector, policyEngine, initialOwner);
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
