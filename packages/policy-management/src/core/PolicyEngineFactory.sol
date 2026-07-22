// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {PolicyEngine} from "./PolicyEngine.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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

  /// @notice Raised when the policy engine unexpectedly already exists
  error PolicyEngineAlreadyExists();

  /// @notice Raised when engine initialization fails
  error EngineInitializationFailed(bytes reason);

  /// @notice Raised when the implementation address is the zero address
  error ImplementationIsZeroAddress();

  /// @notice Raised when the owner address is the zero address
  error InitialOwnerIsZeroAddress();

  /**
   * @notice Creates a new policy engine contract using deterministic minimal proxy cloning, reverting if the existing
   *         address if the engine already exists.
   * @param implementation The address of the policy engine implementation contract to clone
   * @param uniqueEngineId A unique identifier for this engine (combined with msg.sender to create salt)
   * @param policyEngineDefaultAllow Default policy result for the policy engine: true allows by default, false rejects
   * by default
   * @param initialOwner The address that will own the newly created engine contract
   * @return engineAddress The address of the created engine contract
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
    return _createPolicyEngine(implementation, uniqueEngineId, policyEngineDefaultAllow, initialOwner, false);
  }

  /**
   * @notice Creates a new policy engine contract using deterministic minimal proxy cloning, returning the existing
   *         address if the engine already exists.
   * @param implementation The address of the policy engine implementation contract to clone
   * @param uniqueEngineId A unique identifier for this engine (combined with msg.sender to create salt)
   * @param policyEngineDefaultAllow Default policy result for the policy engine: true allows by default, false rejects
   * by default
   * @param initialOwner The address that will own the newly created engine contract
   * @return engineAddress The address of the created (or existing) engine contract
   */
  function getOrCreatePolicyEngine(
    address implementation,
    bytes32 uniqueEngineId,
    bool policyEngineDefaultAllow,
    address initialOwner
  )
    public
    returns (address engineAddress)
  {
    return _createPolicyEngine(implementation, uniqueEngineId, policyEngineDefaultAllow, initialOwner, true);
  }

  /**
   * @dev Creates a new policy engine contract using deterministic minimal proxy cloning.
   *      Uses CREATE2 (via OpenZeppelin Clones) for deterministic deployment addresses. The engine is automatically
   *      initialized with the provided parameters after deployment.
   *      If an engine with the same unique ID by the same sender already exists:
   *         idempotent is false - revert the creation.
   *         idempotent is true - return the existing address.
   */
  function _createPolicyEngine(
    address implementation,
    bytes32 uniqueEngineId,
    bool policyEngineDefaultAllow,
    address initialOwner,
    bool idempotent
  )
    internal
    returns (address engineAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();
    if (initialOwner == address(0)) revert InitialOwnerIsZeroAddress();

    bytes32 salt = getSalt(msg.sender, uniqueEngineId);
    engineAddress = Clones.predictDeterministicAddress(implementation, salt);
    if (engineAddress.code.length > 0) {
      if (idempotent) {
        return engineAddress;
      } else {
        revert PolicyEngineAlreadyExists();
      }
    }
    engineAddress = Clones.cloneDeterministic(implementation, salt);
    try PolicyEngine(engineAddress).initialize(policyEngineDefaultAllow, initialOwner) {
      emit PolicyEngineCreated(engineAddress);
    } catch Error(string memory reason) {
      revert EngineInitializationFailed(bytes(reason));
    } catch (bytes memory reason) {
      revert EngineInitializationFailed(reason);
    }
  }

  /**
   * @notice Predicts the deterministic address where a policy engine would be deployed.
   * @dev Useful for calculating engine addresses before deployment or checking if an engine already exists.
   *      Uses the same salt generation as _createPolicyEngine to ensure address consistency.
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
   * @notice Creates a new policy engine contract using an upgradeable deterministic proxy, reverting if the existing
   *         address if the engine already exists.
   * @param implementation The address of the policy engine implementation contract to clone
   * @param uniqueEngineId A unique identifier for this engine (combined with msg.sender to create salt)
   * @param policyEngineDefaultAllow Default policy result for the policy engine: true allows by default, false rejects
   * by default
   * @param initialOwner The address that will own the newly created engine contract
   * @return engineAddress The address of the created engine contract
   */
  function createUpgradeablePolicyEngine(
    address implementation,
    bytes32 uniqueEngineId,
    bool policyEngineDefaultAllow,
    address initialOwner
  )
    public
    returns (address engineAddress)
  {
    return _createUpgradeablePolicyEngine(implementation, uniqueEngineId, policyEngineDefaultAllow, initialOwner, false);
  }

  /**
   * @notice Creates a new policy engine contract using an upgradeable deterministic proxy, returning the existing
   *         address if the engine already exists.
   * @param implementation The address of the policy engine implementation contract to clone
   * @param uniqueEngineId A unique identifier for this engine (combined with msg.sender to create salt)
   * @param policyEngineDefaultAllow Default policy result for the policy engine: true allows by default, false rejects
   * by default
   * @param initialOwner The address that will own the newly created engine contract
   * @return engineAddress The address of the created (or existing) engine contract
   */
  function getOrCreateUpgradeablePolicyEngine(
    address implementation,
    bytes32 uniqueEngineId,
    bool policyEngineDefaultAllow,
    address initialOwner
  )
    public
    returns (address engineAddress)
  {
    return _createUpgradeablePolicyEngine(implementation, uniqueEngineId, policyEngineDefaultAllow, initialOwner, true);
  }

  /**
   * @dev Creates a new policy engine contract using an upgradeable deterministic proxy.
   *      Uses CREATE2 for deterministic deployment addresses. The engine is automatically initialized with the
   *      provided parameters during deployment.
   *      If an engine with the same salt already exists:
   *         idempotent is false - revert the creation.
   *         idempotent is true - return the existing address.
   */
  function _createUpgradeablePolicyEngine(
    address implementation,
    bytes32 uniqueEngineId,
    bool policyEngineDefaultAllow,
    address initialOwner,
    bool idempotent
  )
    internal
    returns (address engineAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();
    if (initialOwner == address(0)) revert InitialOwnerIsZeroAddress();

    bytes memory initData =
      abi.encodeWithSelector(PolicyEngine.initialize.selector, policyEngineDefaultAllow, initialOwner);
    bytes memory creationCode = _ERC1967ProxyCreationCode(implementation, initData);
    bytes32 salt = getSalt(msg.sender, uniqueEngineId);

    engineAddress = Create2.computeAddress(salt, keccak256(creationCode));

    if (engineAddress.code.length > 0) {
      if (idempotent) {
        return engineAddress;
      } else {
        revert PolicyEngineAlreadyExists();
      }
    }

    engineAddress = Create2.deploy(0, salt, creationCode);
    emit PolicyEngineCreated(engineAddress);
  }

  /**
   * @notice Predicts the deterministic address where an upgradeable policy engine would be deployed.
   * @dev Useful for calculating engine addresses before deployment or checking if an engine already exists.
   *      Uses the same salt generation as _createUpgradeablePolicyEngine to ensure address consistency.
   * @param creator The address of the account that would create the engine
   * @param implementation The address of the policy engine implementation contract
   * @param uniqueEngineId The unique identifier for the engine
   * @param policyEngineDefaultAllow Default policy result for the policy engine: true allows by default, false rejects
   * by default
   * @param initialOwner The address that will own the newly created engine contract
   * @return The predicted address where the engine would be deployed
   */
  function predictUpgradeableEngineAddress(
    address creator,
    address implementation,
    bytes32 uniqueEngineId,
    bool policyEngineDefaultAllow,
    address initialOwner
  )
    external
    view
    returns (address)
  {
    bytes32 salt = getSalt(creator, uniqueEngineId);
    bytes memory initData =
      abi.encodeWithSelector(PolicyEngine.initialize.selector, policyEngineDefaultAllow, initialOwner);
    return Create2.computeAddress(salt, keccak256(_ERC1967ProxyCreationCode(implementation, initData)));
  }

  /**
   * @notice Generates a deterministic salt for engine deployment.
   * @dev Combines the sender address and unique engine ID to create a unique salt.
   *      This ensures that the same creator cannot deploy multiple engines with the same ID,
   *      while allowing different creators to use the same engine ID.
   *
   *      Note that `block.chainid` is intentionally omitted from the salt. The same (sender, uniqueEngineId) therefore
   *      resolves to the same CREATE2 address on every chain. This is not a cross-chain hijack risk because the salt
   *      binds `msg.sender`, so an attacker on any chain derives a different address and cannot occupy another's
   *      predicted address; chain-consistent addresses are the intended property of deterministic deployment. If
   *      per-chain address divergence for the same `uniqueEngineId` is ever required, include `block.chainid` in the
   *      salt here.
   * @param sender The address of the engine creator
   * @param uniqueEngineId The unique identifier for the engine
   * @return The generated salt for deterministic deployment
   */
  function getSalt(address sender, bytes32 uniqueEngineId) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(sender, uniqueEngineId));
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
