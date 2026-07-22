// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Policy} from "./Policy.sol";
import {IPolicy} from "../interfaces/IPolicy.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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

  /// @notice Raised when the policy unexpectedly already exists
  error PolicyAlreadyExists();

  /// @notice Emitted when policy initialization fails
  error PolicyInitializationFailed(bytes reason);

  /// @notice Emitted when implementation address is zero
  error ImplementationIsZeroAddress();

  /// @notice The implementation does not support {IPolicy}
  error ImplementationDoesNotSupportIPolicy();

  /**
   * @notice Creates a new policy contract using deterministic minimal proxy cloning, reverting if the existing
   *         address if the policy already exists.
   * @param implementation The address of the policy implementation contract to clone
   * @param uniquePolicyId A unique identifier for this policy (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this policy
   * @param initialOwner The address that will own the newly created policy contract
   * @param configData ABI-encoded configuration data specific to the policy implementation
   * @return policyAddress The address of the created policy contract
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
    return _createPolicy(implementation, uniquePolicyId, policyEngine, initialOwner, configData, false);
  }

  /**
   * @notice Creates a new policy contract using deterministic minimal proxy cloning, returning the existing
   *         address if the policy already exists.
   * @param implementation The address of the policy implementation contract to clone
   * @param uniquePolicyId A unique identifier for this policy (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this policy
   * @param initialOwner The address that will own the newly created policy contract
   * @param configData ABI-encoded configuration data specific to the policy implementation
   * @return policyAddress The address of the created (or existing) policy contract
   */
  function getOrCreatePolicy(
    address implementation,
    bytes32 uniquePolicyId,
    address policyEngine,
    address initialOwner,
    bytes calldata configData
  )
    public
    returns (address policyAddress)
  {
    return _createPolicy(implementation, uniquePolicyId, policyEngine, initialOwner, configData, true);
  }

  /**
   * @dev Creates a new policy contract using deterministic minimal proxy cloning.
   *      Uses CREATE2 (via OpenZeppelin Clones) for deterministic deployment addresses. The policy is automatically
   *      initialized with the provided parameters after deployment.
   *      If a policy with the same unique ID by the same sender already exists:
   *         idempotent is false - revert the creation.
   *         idempotent is true - return the existing address.
   */
  function _createPolicy(
    address implementation,
    bytes32 uniquePolicyId,
    address policyEngine,
    address initialOwner,
    bytes calldata configData,
    bool idempotent
  )
    internal
    returns (address policyAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();
    _requireImplementationSupportsIPolicy(implementation);

    bytes32 salt = getSalt(msg.sender, uniquePolicyId);
    policyAddress = Clones.predictDeterministicAddress(implementation, salt);
    if (policyAddress.code.length > 0) {
      if (idempotent) {
        return policyAddress;
      } else {
        revert PolicyAlreadyExists();
      }
    }

    policyAddress = Clones.cloneDeterministic(implementation, salt);
    try Policy(policyAddress).initialize(policyEngine, initialOwner, configData) {
      emit PolicyCreated(policyAddress);
    } catch Error(string memory reason) {
      revert PolicyInitializationFailed(bytes(reason));
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
   * @notice Creates a new policy contract using an upgradeable deterministic proxy, reverting if the existing
   *         address if the policy already exists.
   * @param implementation The address of the policy implementation contract to use for the proxy
   * @param uniquePolicyId A unique identifier for this policy (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this policy
   * @param initialOwner The address that will own the newly created policy contract
   * @param configData ABI-encoded configuration data specific to the policy implementation
   * @return policyAddress The address of the created upgradeable policy contract
   */
  function createUpgradeablePolicy(
    address implementation,
    bytes32 uniquePolicyId,
    address policyEngine,
    address initialOwner,
    bytes calldata configData
  )
    public
    returns (address policyAddress)
  {
    return _createUpgradeablePolicy(implementation, uniquePolicyId, policyEngine, initialOwner, configData, false);
  }

  /**
   * @notice Creates a new policy contract using an upgradeable deterministic proxy, returning the existing
   *         address if the policy already exists.
   * @param implementation The address of the policy implementation contract to use for the proxy
   * @param uniquePolicyId A unique identifier for this policy (combined with msg.sender to create salt)
   * @param policyEngine The address of the policy engine that will manage this policy
   * @param initialOwner The address that will own the newly created policy contract
   * @param configData ABI-encoded configuration data specific to the policy implementation
   * @return policyAddress The address of the created upgradeable policy contract
   */
  function getOrCreateUpgradeablePolicy(
    address implementation,
    bytes32 uniquePolicyId,
    address policyEngine,
    address initialOwner,
    bytes calldata configData
  )
    public
    returns (address policyAddress)
  {
    return _createUpgradeablePolicy(implementation, uniquePolicyId, policyEngine, initialOwner, configData, true);
  }

  /**
   * @dev Creates a new policy contract using an upgradeable deterministic proxy.
   *      Uses CREATE2 for deterministic deployment addresses. The policy is automatically initialized with the
   *      provided parameters during deployment.
   *      If a policy with the same unique ID by the same sender already exists:
   *         idempotent is false - revert the creation.
   *         idempotent is true - return the existing address.
   */
  function _createUpgradeablePolicy(
    address implementation,
    bytes32 uniquePolicyId,
    address policyEngine,
    address initialOwner,
    bytes calldata configData,
    bool idempotent
  )
    internal
    returns (address policyAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();
    _requireImplementationSupportsIPolicy(implementation);

    bytes memory initData = abi.encodeWithSelector(Policy.initialize.selector, policyEngine, initialOwner, configData);
    bytes memory creationCode = _ERC1967ProxyCreationCode(implementation, initData);
    bytes32 salt = getSalt(msg.sender, uniquePolicyId);

    policyAddress = Create2.computeAddress(salt, keccak256(creationCode));

    if (policyAddress.code.length > 0) {
      if (idempotent) {
        return policyAddress;
      } else {
        revert PolicyAlreadyExists();
      }
    }

    policyAddress = Create2.deploy(0, salt, creationCode);
    emit PolicyCreated(policyAddress);
  }

  /**
   * @notice Predicts the deterministic address where an upgradeable policy would be deployed.
   * @dev Useful for calculating policy addresses before deployment or checking if a policy already exists.
   *      Uses the same salt generation as createUpgradeablePolicy to ensure address consistency.
   * @param creator The address of the account that would create the policy
   * @param implementation The address of the policy implementation contract
   * @param uniquePolicyId The unique identifier for the policy
   * @param policyEngine The address of the policy engine that will manage this policy
   * @param initialOwner The address that will own the newly created policy contract
   * @param configData ABI-encoded configuration data specific to the policy implementation
   * @return The predicted address where the policy would be deployed
   */
  function predictUpgradeablePolicyAddress(
    address creator,
    address implementation,
    bytes32 uniquePolicyId,
    address policyEngine,
    address initialOwner,
    bytes calldata configData
  )
    public
    view
    returns (address)
  {
    bytes32 salt = getSalt(creator, uniquePolicyId);
    bytes memory initData = abi.encodeWithSelector(Policy.initialize.selector, policyEngine, initialOwner, configData);
    return Create2.computeAddress(salt, keccak256(_ERC1967ProxyCreationCode(implementation, initData)));
  }

  /**
   * @notice Generates a deterministic salt for policy deployment.
   * @dev Combines the sender address and unique policy ID to create a unique salt.
   *      This ensures that the same creator cannot deploy multiple policies with the same ID,
   *      while allowing different creators to use the same policy ID.
   *
   *      Note that `block.chainid` is intentionally omitted from the salt. The same (sender, uniquePolicyId) therefore
   *      resolves to the same CREATE2 address on every chain. This is not a cross-chain hijack risk because the salt
   *      binds `msg.sender`, so an attacker on any chain derives a different address and cannot occupy another's
   *      predicted address; chain-consistent addresses are the intended property of deterministic deployment. If
   *      per-chain address divergence for the same `uniquePolicyId` is ever required, include `block.chainid` in the
   *      salt here.
   * @param sender The address of the policy creator
   * @param uniquePolicyId The unique identifier for the policy
   * @return The generated salt for deterministic deployment
   */
  function getSalt(address sender, bytes32 uniquePolicyId) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(sender, uniquePolicyId));
  }

  /**
   * @dev Reverts unless `implementation` responds to ERC-165 with support for {IPolicy}.
   */
  function _requireImplementationSupportsIPolicy(address implementation) internal view {
    try IERC165(implementation).supportsInterface(type(IPolicy).interfaceId) returns (bool supported) {
      if (!supported) revert ImplementationDoesNotSupportIPolicy();
    } catch {
      revert ImplementationDoesNotSupportIPolicy();
    }
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
