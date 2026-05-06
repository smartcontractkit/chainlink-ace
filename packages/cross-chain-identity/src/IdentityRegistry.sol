// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {PolicyProtectedUpgradeable} from "@chainlink/policy-management/core/PolicyProtectedUpgradeable.sol";

contract IdentityRegistry is PolicyProtectedUpgradeable, IIdentityRegistry {
  string public constant override typeAndVersion = "IdentityRegistry 1.0.0";

  /// @custom:storage-location erc7201:chainlink.ace.IdentityRegistry
  struct IdentityRegistryStorage {
    mapping(address account => bytes32 ccid) accountToCcid;
    mapping(bytes32 ccid => address[] accounts) ccidToAccounts;
    // Maps ccid => account => index in ccidToAccounts array (index + 1, 0 means not found)
    mapping(bytes32 ccid => mapping(address account => uint256 index)) accountIndex;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.IdentityRegistry")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant identityRegistryStorageLocation =
    0x31dacf4de1329b533dc7ad419a7ae424eacaaf799ae802e5d062dea412180200;

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
    // Store index + 1 (so 0 means not found)
    _identityRegistryStorage().accountIndex[ccid][account] = _identityRegistryStorage().ccidToAccounts[ccid].length;
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
    uint256 indexPlusOne = _identityRegistryStorage().accountIndex[ccid][account];
    if (indexPlusOne == 0) {
      revert IdentityNotFound(ccid, account);
    }

    uint256 index = indexPlusOne - 1;
    uint256 lastIndex = _identityRegistryStorage().ccidToAccounts[ccid].length - 1;

    if (index != lastIndex) {
      // Move the last element to the position being removed
      address lastAccount = _identityRegistryStorage().ccidToAccounts[ccid][lastIndex];
      _identityRegistryStorage().ccidToAccounts[ccid][index] = lastAccount;
      // Update the moved account's index
      _identityRegistryStorage().accountIndex[ccid][lastAccount] = indexPlusOne;
    }

    // Remove the last element
    _identityRegistryStorage().ccidToAccounts[ccid].pop();
    delete _identityRegistryStorage().accountToCcid[account];
    delete _identityRegistryStorage().accountIndex[ccid][account];

    emit IdentityRemoved(ccid, account);
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
