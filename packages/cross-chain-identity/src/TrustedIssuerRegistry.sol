// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ITrustedIssuerRegistry} from "./interfaces/ITrustedIssuerRegistry.sol";
import {PolicyProtectedUpgradeable} from "@chainlink/policy-management/core/PolicyProtectedUpgradeable.sol";

/**
 * @title TrustedIssuerRegistry
 * @dev Implementation of the ITrustedIssuerRegistry interface using ERC-7201 storage pattern.
 */
contract TrustedIssuerRegistry is PolicyProtectedUpgradeable, ITrustedIssuerRegistry {
  string public constant override typeAndVersion = "TrustedIssuerRegistry 1.0.0";

  /// @custom:storage-location erc7201:chainlink.ace.TrustedIssuerRegistry
  struct TrustedIssuerRegistryStorage {
    mapping(bytes32 issuerIdHash => bool isTrusted) trustedIssuers;
    bytes32[] issuerList;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.TrustedIssuerRegistry")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant trustedIssuerRegistryStorageLocation =
    0x24368af76f28f75e0d3c893af5175655a9b97a18e82e58c43f9152ef16421900;

  function _trustedIssuerRegistryStorage() private pure returns (TrustedIssuerRegistryStorage storage $) {
    assembly {
      $.slot := trustedIssuerRegistryStorageLocation
    }
  }

  constructor() {
    _disableInitializers();
  }

  /**
   * @dev Initializes the trusted issuer registry and sets the policy engine.
   * @param policyEngine The address of the policy engine contract.
   * @param initialOwner The address that will own the newly created registry contract.
   */
  function initialize(address policyEngine, address initialOwner) public virtual initializer {
    __TrustedIssuerRegistry_init(policyEngine, initialOwner);
  }

  function __TrustedIssuerRegistry_init(address policyEngine, address initialOwner) internal onlyInitializing {
    __TrustedIssuerRegistry_init_unchained();
    __PolicyProtected_init(initialOwner, policyEngine);
  }

  function __TrustedIssuerRegistry_init_unchained() internal onlyInitializing {}

  // ------------------------------------------------------------------------
  // Externals
  // ------------------------------------------------------------------------

  function addTrustedIssuer(
    string memory issuerId,
    bytes calldata context
  )
    external
    override
    runPolicyWithContext(context)
  {
    _addTrustedIssuer(issuerId, context);
  }

  function removeTrustedIssuer(
    string memory issuerId,
    bytes calldata context
  )
    external
    override
    runPolicyWithContext(context)
  {
    _removeTrustedIssuer(issuerId, context);
  }

  // ------------------------------------------------------------------------
  // internals
  // ------------------------------------------------------------------------

  function _addTrustedIssuer(string memory issuerId, bytes calldata context) internal {
    if (bytes(issuerId).length == 0) {
      revert("issuerId cannot be empty");
    }

    bytes32 issuerIdHash = keccak256(abi.encodePacked(issuerId));

    TrustedIssuerRegistryStorage storage $ = _trustedIssuerRegistryStorage();
    if ($.trustedIssuers[issuerIdHash]) {
      revert("Issuer already trusted");
    }

    $.trustedIssuers[issuerIdHash] = true;
    $.issuerList.push(issuerIdHash);

    emit TrustedIssuerAdded(issuerIdHash, issuerId);
  }

  function _removeTrustedIssuer(string memory issuerId, bytes calldata context) internal {
    if (bytes(issuerId).length == 0) {
      revert("issuerId cannot be empty");
    }

    bytes32 issuerIdHash = keccak256(abi.encodePacked(issuerId));

    TrustedIssuerRegistryStorage storage $ = _trustedIssuerRegistryStorage();
    if (!$.trustedIssuers[issuerIdHash]) {
      revert("Issuer not trusted");
    }

    $.trustedIssuers[issuerIdHash] = false;

    uint256 length = $.issuerList.length;
    for (uint256 i = 0; i < length; i++) {
      if ($.issuerList[i] == issuerIdHash) {
        $.issuerList[i] = $.issuerList[length - 1];
        $.issuerList.pop();
        break;
      }
    }

    emit TrustedIssuerRemoved(issuerIdHash, issuerId);
  }

  function _isTrustedIssuer(bytes32 issuerIdHash) internal view returns (bool) {
    return _trustedIssuerRegistryStorage().trustedIssuers[issuerIdHash];
  }

  // ------------------------------------------------------------------------
  // View
  // ------------------------------------------------------------------------

  function getTrustedIssuers() public view virtual override returns (bytes32[] memory) {
    return _trustedIssuerRegistryStorage().issuerList;
  }

  function isTrustedIssuer(string memory issuerId) external view override returns (bool) {
    bytes32 issuerIdHash = keccak256(abi.encodePacked(issuerId));
    return _isTrustedIssuer(issuerIdHash);
  }
}
