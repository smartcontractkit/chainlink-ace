// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ICredentialRegistry} from "./interfaces/ICredentialRegistry.sol";
import {ICredentialValidator} from "./interfaces/ICredentialValidator.sol";
import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";

contract CredentialRegistry is PolicyProtected, ICredentialRegistry {
  /// @custom:storage-location erc7201:cross-chain-identity.CredentialRegistry
  struct CredentialRegistryStorage {
    mapping(bytes32 ccid => bytes32[] credentialTypeIds) credentialTypeIdsByCCID;
    mapping(bytes32 ccid => mapping(bytes32 credentialTypeId => Credential credentials)) credentials;
  }

  // keccak256(abi.encode(uint256(keccak256("cross-chain-identity.CredentialRegistry")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant credentialRegistryStorageLocation =
    0xda878a21d431ff897bdb535b211ae68088a4b0265066b239bc4db2e51d9a8200;

  function _credentialRegistryStorage() private pure returns (CredentialRegistryStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := credentialRegistryStorageLocation
    }
  }

  /**
   * @dev Initializes the credential registry and sets the policy engine.
   * @param policyEngine The address of the policy engine contract.
   * @param initialOwner The address that will own the newly created registry contract.
   */
  function initialize(address policyEngine, address initialOwner) public virtual initializer {
    __CredentialRegistry_init(policyEngine, initialOwner);
  }

  function __CredentialRegistry_init(address policyEngine, address initialOwner) internal onlyInitializing {
    __CredentialRegistry_init_unchained();
    __PolicyProtected_init(initialOwner, policyEngine);
  }

  // solhint-disable-next-line no-empty-blocks
  function __CredentialRegistry_init_unchained() internal onlyInitializing {}

  /// @inheritdoc ICredentialRegistry
  function registerCredential(
    bytes32 ccid,
    bytes32 credentialTypeId,
    uint40 expiresAt,
    bytes calldata credentialData,
    bytes calldata context
  )
    public
    virtual
    override
    runPolicyWithContext(context)
  {
    if (expiresAt > 0 && expiresAt <= block.timestamp) {
      revert InvalidCredentialConfiguration("Invalid expiration time");
    }
    _registerCredential(ccid, credentialTypeId, expiresAt, credentialData);
  }

  /// @inheritdoc ICredentialRegistry
  function registerCredentials(
    bytes32 ccid,
    bytes32[] calldata credentialTypeIds,
    uint40 expiresAt,
    bytes[] calldata credentialDatas,
    bytes calldata context
  )
    public
    virtual
    override
    runPolicyWithContext(context)
  {
    if (credentialTypeIds.length == 0 || credentialTypeIds.length != credentialDatas.length) {
      revert InvalidCredentialConfiguration("Invalid input length");
    }
    if (expiresAt > 0 && expiresAt <= block.timestamp) {
      revert InvalidCredentialConfiguration("Invalid expiration time");
    }
    for (uint256 i = 0; i < credentialTypeIds.length; i++) {
      _registerCredential(ccid, credentialTypeIds[i], expiresAt, credentialDatas[i]);
    }
  }

  /// @inheritdoc ICredentialRegistry
  function removeCredential(
    bytes32 ccid,
    bytes32 credentialTypeId,
    bytes calldata context
  )
    public
    virtual
    override
    runPolicyWithContext(context)
  {
    uint256 length = _credentialRegistryStorage().credentialTypeIdsByCCID[ccid].length;
    for (uint256 i = 0; i < length; i++) {
      if (_credentialRegistryStorage().credentialTypeIdsByCCID[ccid][i] == credentialTypeId) {
        _credentialRegistryStorage().credentialTypeIdsByCCID[ccid][i] =
          _credentialRegistryStorage().credentialTypeIdsByCCID[ccid][length - 1];
        _credentialRegistryStorage().credentialTypeIdsByCCID[ccid].pop();
        delete _credentialRegistryStorage().credentials[ccid][credentialTypeId];

        emit CredentialRemoved(ccid, credentialTypeId);
        return;
      }
    }
    revert CredentialNotFound(ccid, credentialTypeId);
  }

  /// @inheritdoc ICredentialRegistry
  function renewCredential(
    bytes32 ccid,
    bytes32 credentialTypeId,
    uint40 expiresAt,
    bytes calldata context
  )
    public
    virtual
    override
    runPolicyWithContext(context)
  {
    if (expiresAt > 0 && expiresAt <= block.timestamp) {
      revert InvalidCredentialConfiguration("Invalid expiration time");
    }
    uint256 length = _credentialRegistryStorage().credentialTypeIdsByCCID[ccid].length;
    for (uint256 i = 0; i < length; i++) {
      if (_credentialRegistryStorage().credentialTypeIdsByCCID[ccid][i] == credentialTypeId) {
        uint40 currentExpiresAt = _credentialRegistryStorage().credentials[ccid][credentialTypeId].expiresAt;

        _credentialRegistryStorage().credentials[ccid][credentialTypeId].expiresAt = expiresAt;
        emit CredentialRenewed(ccid, credentialTypeId, currentExpiresAt, expiresAt);
        return;
      }
    }
    revert CredentialNotFound(ccid, credentialTypeId);
  }

  function isCredentialExpired(bytes32 ccid, bytes32 credentialTypeId) public view returns (bool) {
    return _credentialRegistryStorage().credentials[ccid][credentialTypeId].expiresAt > 0
      && _credentialRegistryStorage().credentials[ccid][credentialTypeId].expiresAt <= block.timestamp;
  }

  /// @inheritdoc ICredentialRegistry
  function getCredentialTypes(bytes32 ccid) public view virtual override returns (bytes32[] memory) {
    return _credentialRegistryStorage().credentialTypeIdsByCCID[ccid];
  }

  /// @inheritdoc ICredentialRegistry
  function getCredential(bytes32 ccid, bytes32 credentialTypeId) public view returns (Credential memory) {
    for (uint256 i = 0; i < _credentialRegistryStorage().credentialTypeIdsByCCID[ccid].length; i++) {
      if (_credentialRegistryStorage().credentialTypeIdsByCCID[ccid][i] == credentialTypeId) {
        return _credentialRegistryStorage().credentials[ccid][credentialTypeId];
      }
    }
    revert CredentialNotFound(ccid, credentialTypeId);
  }

  /// @inheritdoc ICredentialRegistry
  function getCredentials(
    bytes32 ccid,
    bytes32[] calldata credentialTypeIds
  )
    external
    view
    returns (Credential[] memory)
  {
    uint8 length = uint8(credentialTypeIds.length);
    Credential[] memory credentials = new Credential[](length);
    for (uint256 i = 0; i < length; i++) {
      credentials[i] = getCredential(ccid, credentialTypeIds[i]);
    }
    return credentials;
  }

  /// @inheritdoc ICredentialValidator
  function validate(
    bytes32 ccid,
    bytes32 credentialTypeId,
    bytes calldata context
  )
    public
    view
    virtual
    override
    returns (bool)
  {
    return _validate(ccid, credentialTypeId, context);
  }

  /// @inheritdoc ICredentialValidator
  function validateAll(
    bytes32 ccid,
    bytes32[] calldata credentialTypeIds,
    bytes calldata context
  )
    public
    view
    virtual
    override
    returns (bool)
  {
    for (uint256 i = 0; i < credentialTypeIds.length; i++) {
      if (!_validate(ccid, credentialTypeIds[i], context)) {
        return false;
      }
    }
    return true;
  }

  function _validate(bytes32 ccid, bytes32 credentialTypeId, bytes calldata /*context*/ ) internal view returns (bool) {
    uint256 length = _credentialRegistryStorage().credentialTypeIdsByCCID[ccid].length;
    for (uint256 i = 0; i < length; i++) {
      if (_credentialRegistryStorage().credentialTypeIdsByCCID[ccid][i] == credentialTypeId) {
        return (
          _credentialRegistryStorage().credentials[ccid][credentialTypeId].expiresAt == 0
            || _credentialRegistryStorage().credentials[ccid][credentialTypeId].expiresAt > block.timestamp
        );
      }
    }
    return false;
  }

  function _registerCredential(
    bytes32 ccid,
    bytes32 credentialTypeId,
    uint40 expiresAt,
    bytes calldata credentialData
  )
    internal
  {
    uint256 length = _credentialRegistryStorage().credentialTypeIdsByCCID[ccid].length;
    for (uint256 i = 0; i < length; i++) {
      if (_credentialRegistryStorage().credentialTypeIdsByCCID[ccid][i] == credentialTypeId) {
        revert CredentialAlreadyRegistered(ccid, credentialTypeId);
      }
    }
    _credentialRegistryStorage().credentialTypeIdsByCCID[ccid].push(credentialTypeId);
    _credentialRegistryStorage().credentials[ccid][credentialTypeId] = Credential(expiresAt, credentialData);
    emit CredentialRegistered(ccid, credentialTypeId, expiresAt, credentialData);
  }
}
