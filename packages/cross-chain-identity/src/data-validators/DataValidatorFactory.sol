// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IInitializableDataValidator} from "../interfaces/IInitializableDataValidator.sol";
import {ICredentialDataValidator} from "../interfaces/ICredentialDataValidator.sol";
import {IConfigVersionController} from "../interfaces/IConfigVersionController.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DataValidatorFactory
 * @notice Factory for deterministic minimal-proxy clones and ERC-1967 proxies of data validator implementations
 *         that expose {IInitializableDataValidator} and support ERC-165 for {ICredentialDataValidator} and
 *         {IConfigVersionController}.
 * @dev Mirrors the deployment pattern used by {PolicyFactory} and registry factories in this package.
 *      Upgradeable validators use `ERC1967Proxy` with non-empty initializer calldata so construction matches
 *      OpenZeppelin proxies that delegate during deployment (see `AccountFactory` in chainlink-smart-accounts).
 */
contract DataValidatorFactory {
  /// @notice Emitted when a new data validator instance is created.
  event DataValidatorCreated(address validator);

  /// @notice Emitted when validator initialization fails.
  error ValidatorInitializationFailed(bytes reason);

  /// @notice Emitted when implementation address is zero.
  error ImplementationIsZeroAddress();

  /// @notice Raised when a validator already exists at the deterministic address for the given (sender, id).
  error DataValidatorAlreadyExists();

  /// @notice The implementation does not declare ERC-165 support for {ICredentialDataValidator}.
  error DataValidatorUnsupported();

  /// @notice The implementation does not declare ERC-165 support for {IConfigVersionController}.
  error ConfigVersionControllerUnsupported();

  /**
   * @notice Creates a new validator using a deterministic minimal proxy (EIP-1167), reverting if a validator
   *         already exists at the deterministic address for the given (sender, id).
   * @param implementation The implementation contract to clone; must pass ERC-165 checks.
   * @param uniqueValidatorId Salt component (combined with `msg.sender`) for CREATE2 address.
   * @param initialOwner The owner assigned on the new validator.
   * @param configData ABI-encoded configuration for `IInitializableDataValidator.initialize`.
   * @return validatorAddress The created proxy instance.
   */
  function createDataValidator(
    address implementation,
    bytes32 uniqueValidatorId,
    address initialOwner,
    bytes calldata configData
  )
    public
    returns (address validatorAddress)
  {
    return _createDataValidator(implementation, uniqueValidatorId, initialOwner, configData, false);
  }

  /**
   * @notice Creates a new validator using a deterministic minimal proxy (EIP-1167), returning the existing instance
   *         if a validator already exists at the deterministic address for the given (sender, id).
   * @dev Use this when idempotent get-or-create semantics are desired. The existing instance is returned as-is and is
   *      NOT re-initialised, so its owner/config remain those set on first creation; only the (sender, id) determine
   *      the address, not `initialOwner`/`configData`.
   * @param implementation The implementation contract to clone; must pass ERC-165 checks.
   * @param uniqueValidatorId Salt component (combined with `msg.sender`) for CREATE2 address.
   * @param initialOwner The owner assigned on the new validator (only used when one is created).
   * @param configData ABI-encoded configuration for `IInitializableDataValidator.initialize` (only used on create).
   * @return validatorAddress The created or existing proxy instance.
   */
  function getOrCreateDataValidator(
    address implementation,
    bytes32 uniqueValidatorId,
    address initialOwner,
    bytes calldata configData
  )
    public
    returns (address validatorAddress)
  {
    return _createDataValidator(implementation, uniqueValidatorId, initialOwner, configData, true);
  }

  /**
   * @dev Creates a minimal-proxy validator. If one already exists at the deterministic address:
   *      idempotent is false - revert with {DataValidatorAlreadyExists}.
   *      idempotent is true  - return the existing address (not re-initialised).
   */
  function _createDataValidator(
    address implementation,
    bytes32 uniqueValidatorId,
    address initialOwner,
    bytes calldata configData,
    bool idempotent
  )
    internal
    returns (address validatorAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();
    _requireImplementationSupportsRequiredInterfaces(implementation);

    bytes32 salt = getSalt(msg.sender, uniqueValidatorId);
    validatorAddress = Clones.predictDeterministicAddress(implementation, salt);
    if (validatorAddress.code.length > 0) {
      if (idempotent) {
        return validatorAddress;
      }
      revert DataValidatorAlreadyExists();
    }

    validatorAddress = Clones.cloneDeterministic(implementation, salt);
    _initializeValidator(validatorAddress, initialOwner, configData);
  }

  /**
   * @notice Creates a new validator behind an ERC-1967 proxy with deterministic CREATE2 deployment, reverting if a
   *         validator already exists at the deterministic address.
   * @param implementation The implementation contract for the proxy; must pass ERC-165 checks.
   * @param uniqueValidatorId Salt component (combined with `msg.sender`) for CREATE2 address.
   * @param initialOwner The owner assigned on the new validator.
   * @param configData ABI-encoded configuration for `IInitializableDataValidator.initialize`.
   * @return validatorAddress The created proxy instance.
   * @dev Initialization is executed in the proxy constructor via `initData` (no separate post-deploy call). Unlike
   *      {createDataValidator}, which normalises initialize() failures into {ValidatorInitializationFailed}, a failing
   *      initializer here reverts during construction and propagates from `Create2.deploy` (e.g.
   *      `Create2FailedDeployment`) rather than as {ValidatorInitializationFailed}. This is safe: a constructor revert
   *      leaves no code at the address, so the deployment fails atomically with no partially-initialised validator.
   */
  function createUpgradeableDataValidator(
    address implementation,
    bytes32 uniqueValidatorId,
    address initialOwner,
    bytes calldata configData
  )
    public
    returns (address validatorAddress)
  {
    return _createUpgradeableDataValidator(implementation, uniqueValidatorId, initialOwner, configData, false);
  }

  /**
   * @notice Creates a new validator behind an ERC-1967 proxy, returning the existing instance if a validator already
   *         exists at the deterministic address.
   * @dev Get-or-create counterpart of {createUpgradeableDataValidator}. The existing instance is returned as-is.
   * @param implementation The implementation contract for the proxy; must pass ERC-165 checks.
   * @param uniqueValidatorId Salt component (combined with `msg.sender`) for CREATE2 address.
   * @param initialOwner The owner assigned on the new validator (only used when one is created).
   * @param configData ABI-encoded configuration for `IInitializableDataValidator.initialize` (only used on create).
   * @return validatorAddress The created or existing proxy instance.
   */
  function getOrCreateUpgradeableDataValidator(
    address implementation,
    bytes32 uniqueValidatorId,
    address initialOwner,
    bytes calldata configData
  )
    public
    returns (address validatorAddress)
  {
    return _createUpgradeableDataValidator(implementation, uniqueValidatorId, initialOwner, configData, true);
  }

  /**
   * @dev Creates an ERC-1967 proxy validator. If one already exists at the deterministic address:
   *      idempotent is false - revert with {DataValidatorAlreadyExists}.
   *      idempotent is true  - return the existing address.
   */
  function _createUpgradeableDataValidator(
    address implementation,
    bytes32 uniqueValidatorId,
    address initialOwner,
    bytes calldata configData,
    bool idempotent
  )
    internal
    returns (address validatorAddress)
  {
    if (implementation == address(0)) revert ImplementationIsZeroAddress();
    _requireImplementationSupportsRequiredInterfaces(implementation);

    bytes memory initData =
      abi.encodeWithSelector(IInitializableDataValidator.initialize.selector, initialOwner, configData);
    bytes32 salt = getSalt(msg.sender, uniqueValidatorId);
    bytes memory creationCode = _ERC1967ProxyCreationCode(implementation, initData);
    validatorAddress = Create2.computeAddress(salt, keccak256(creationCode));

    if (validatorAddress.code.length > 0) {
      if (idempotent) {
        return validatorAddress;
      }
      revert DataValidatorAlreadyExists();
    }

    validatorAddress = Create2.deploy(0, salt, creationCode);
    emit DataValidatorCreated(validatorAddress);
  }

  /**
   * @notice Predicts the clone address for a given creator, implementation, and id.
   */
  function predictDataValidatorAddress(
    address creator,
    address implementation,
    bytes32 uniqueValidatorId
  )
    public
    view
    returns (address)
  {
    bytes32 salt = getSalt(creator, uniqueValidatorId);
    return Clones.predictDeterministicAddress(implementation, salt);
  }

  /**
   * @notice Predicts the ERC-1967 proxy address for a given creator, implementation, id, and initializer args.
   * @dev The address depends on `initialOwner` and `configData` because they are embedded in proxy creation code.
   */
  function predictUpgradeableDataValidatorAddress(
    address creator,
    address implementation,
    bytes32 uniqueValidatorId,
    address initialOwner,
    bytes calldata configData
  )
    public
    view
    returns (address)
  {
    bytes memory initData =
      abi.encodeWithSelector(IInitializableDataValidator.initialize.selector, initialOwner, configData);
    bytes32 salt = getSalt(creator, uniqueValidatorId);
    return Create2.computeAddress(salt, keccak256(_ERC1967ProxyCreationCode(implementation, initData)));
  }

  /**
   * @notice Deterministic salt from creator and validator id.
   */
  function getSalt(address sender, bytes32 uniqueValidatorId) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(sender, uniqueValidatorId));
  }

  function _requireImplementationSupportsRequiredInterfaces(address implementation) internal view {
    try IERC165(implementation).supportsInterface(type(ICredentialDataValidator).interfaceId) returns (bool supported) {
      if (!supported) revert DataValidatorUnsupported();
    } catch {
      revert DataValidatorUnsupported();
    }

    try IERC165(implementation).supportsInterface(type(IConfigVersionController).interfaceId) returns (bool supported) {
      if (!supported) revert ConfigVersionControllerUnsupported();
    } catch {
      revert ConfigVersionControllerUnsupported();
    }
  }

  function _initializeValidator(address validatorAddress, address initialOwner, bytes calldata configData) internal {
    try IInitializableDataValidator(validatorAddress).initialize(initialOwner, configData) {
      emit DataValidatorCreated(validatorAddress);
    } catch Error(string memory reason) {
      revert ValidatorInitializationFailed(bytes(reason));
    } catch (bytes memory reason) {
      revert ValidatorInitializationFailed(reason);
    }
  }

  /**
   * @dev Encodes the full initcode for `new ERC1967Proxy(implementation, initData)`.
   *      Matches what the compiler emits so CREATE2 addressing aligns with direct deployment.
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
