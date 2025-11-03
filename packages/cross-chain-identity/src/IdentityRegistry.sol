// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";

contract IdentityRegistry is PolicyProtected, IIdentityRegistry {
  /// @custom:storage-location erc7201:cross-chain-identity.IdentityRegistry
  struct IdentityRegistryStorage {
    mapping(address account => bytes32 ccid) accountToCcid;
    mapping(bytes32 ccid => address[] accounts) ccidToAccounts;
  }

  // keccak256(abi.encode(uint256(keccak256("cross-chain-identity.IdentityRegistry")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant identityRegistryStorageLocation =
    0x95c7dd14054992de17881168e75df13bb7ed90a1eacfff26d4643d48ec30de00;

  function _identityRegistryStorage() private pure returns (IdentityRegistryStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := identityRegistryStorageLocation
    }
  }

  /**
   * @dev Initializes the identity registry and sets the policy engine.
   * @param policyEngine The address of the policy engine contract.
   * @param initialOwner The address that will own the newly created registry contract.
   */
  function initialize(address policyEngine, address initialOwner) public virtual initializer {
    __IdentityRegistry_init(policyEngine, initialOwner);
  }

  function __IdentityRegistry_init(address policyEngine, address initialOwner) internal onlyInitializing {
    __IdentityRegistry_init_unchained();
    __PolicyProtected_init(initialOwner, policyEngine);
  }

  // solhint-disable-next-line no-empty-blocks
  function __IdentityRegistry_init_unchained() internal onlyInitializing {}

  /// @inheritdoc IIdentityRegistry
  function registerIdentity(
    bytes32 ccid,
    address account,
    bytes calldata context
  )
    public
    virtual
    override
    runPolicyWithContext(context)
  {
    _registerIdentity(ccid, account, context);
  }

  /// @inheritdoc IIdentityRegistry
  function registerIdentities(
    bytes32[] calldata ccids,
    address[] calldata accounts,
    bytes calldata context
  )
    public
    virtual
    override
    runPolicyWithContext(context)
  {
    if (ccids.length == 0 || ccids.length != accounts.length) {
      revert InvalidIdentityConfiguration("Invalid input length");
    }
    for (uint256 i = 0; i < ccids.length; i++) {
      _registerIdentity(ccids[i], accounts[i], context);
    }
  }

  function _registerIdentity(bytes32 ccid, address account, bytes calldata /*context*/ ) internal {
    if (ccid == bytes32(0)) {
      revert InvalidIdentityConfiguration("CCID cannot be empty");
    }
    if (_identityRegistryStorage().accountToCcid[account] != bytes32(0)) {
      revert IdentityAlreadyRegistered(ccid, account);
    }
    _identityRegistryStorage().accountToCcid[account] = ccid;
    _identityRegistryStorage().ccidToAccounts[ccid].push(account);
    emit IdentityRegistered(ccid, account);
  }

  /// @inheritdoc IIdentityRegistry
  function removeIdentity(
    bytes32 ccid,
    address account,
    bytes calldata context
  )
    public
    virtual
    override
    runPolicyWithContext(context)
  {
    uint256 length = _identityRegistryStorage().ccidToAccounts[ccid].length;
    for (uint256 i = 0; i < length; i++) {
      if (_identityRegistryStorage().ccidToAccounts[ccid][i] == account) {
        _identityRegistryStorage().ccidToAccounts[ccid][i] = _identityRegistryStorage().ccidToAccounts[ccid][length - 1];
        _identityRegistryStorage().ccidToAccounts[ccid].pop();
        delete _identityRegistryStorage().accountToCcid[account];

        emit IdentityRemoved(ccid, account);
        return;
      }
    }
    revert IdentityNotFound(ccid, account);
  }

  /// @inheritdoc IIdentityRegistry
  function getIdentity(address account) public view virtual override returns (bytes32) {
    return _identityRegistryStorage().accountToCcid[account];
  }

  /// @inheritdoc IIdentityRegistry
  function getAccounts(bytes32 ccid) public view virtual override returns (address[] memory) {
    return _identityRegistryStorage().ccidToAccounts[ccid];
  }
}
