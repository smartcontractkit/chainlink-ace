// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ICredentialDataValidator} from "../interfaces/ICredentialDataValidator.sol";
import {IConfigVersionController} from "../interfaces/IConfigVersionController.sol";
import {IInitializableDataValidator} from "../interfaces/IInitializableDataValidator.sol";
import {ConfigVersionController} from "./ConfigVersionController.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title AllowDenyListDataValidator
 * @notice Validates input data against generic allow and deny lists of bytes32 items.
 * @dev Configuration changes are tracked with a monotonic version for optimistic concurrency.
 * @author Chainlink
 */
contract AllowDenyListDataValidator is
  UUPSUpgradeable,
  ConfigVersionController,
  ERC165Upgradeable,
  ICredentialDataValidator,
  IInitializableDataValidator
{
  /// @notice Human-readable contract identifier and version.
  // solhint-disable-next-line const-name-snakecase
  string public constant typeAndVersion = "AllowDenyListDataValidator 1.2.0";

  error ItemAlreadyAllowlisted(bytes32 item);
  error ItemNotAllowlisted(bytes32 item);
  error ItemAlreadyDenylisted(bytes32 item);
  error ItemNotDenylisted(bytes32 item);
  error ItemInOppositeList(bytes32 item);
  error DataTypeAlreadySupported(bytes32 dataTypeId);
  error DataTypeNotSupported(bytes32 dataTypeId);

  /// @custom:storage-location erc7201:chainlink.ace.AllowDenyListDataValidator
  struct AllowDenyListDataValidatorStorage {
    mapping(bytes32 item => bool isAllowlisted) allowlist;
    mapping(bytes32 item => bool isDenylisted) denylist;
    mapping(bytes32 dataTypeId => bool isSupported) supportedDataTypes;
    uint256 allowlistCount;
    uint256 denylistCount;
    uint256 supportedDataTypeCount;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.AllowDenyListDataValidator")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant allowDenyListDataValidatorStorageLocation =
    0x4d4f6473d41938d04db6097c0b17537253b811851219e08da23f54b91dc00800;

  /**
   * @notice Returns the storage pointer for validator state.
   * @return $ The validator storage struct.
   */
  function _allowDenyListDataValidatorStorage() private pure returns (AllowDenyListDataValidatorStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := allowDenyListDataValidatorStorageLocation
    }
  }

  // disabling initializers on the implementation contract itself
  /// @custom:oz-upgrades-unsafe-allow constructor
  /// @notice Locks the implementation contract against direct initialization.
  constructor() {
    _disableInitializers();
  }

  /**
   * @notice Initializes the validator with optional initial config.
   * @param initialOwner The owner assigned during initialization.
   * @param configData ABI-encoded `(bytes32[] initialAllowlist, bytes32[] initialDenylist, bytes32[]
   *        initialSupportedDataTypes)`.
   */
  function initialize(address initialOwner, bytes calldata configData) public initializer {
    (bytes32[] memory initialAllowlist, bytes32[] memory initialDenylist, bytes32[] memory initialSupportedDataTypes) =
      abi.decode(configData, (bytes32[], bytes32[], bytes32[]));

    __UUPSUpgradeable_init();
    __Ownable_init(initialOwner);
    __ERC165_init();

    _addAllowlistItems(initialAllowlist);
    _addDenylistItems(initialDenylist);
    _addSupportedDataTypes(initialSupportedDataTypes);

    bytes memory initialConfig = abi.encode(initialAllowlist, initialDenylist, initialSupportedDataTypes);
    _bootstrapConfigVersion();
    emit ConfigurationUpdated(0, 1, bytes4(0), initialConfig);
  }

  /// @inheritdoc ERC165Upgradeable
  function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165Upgradeable) returns (bool) {
    return interfaceId == type(ICredentialDataValidator).interfaceId
      || interfaceId == type(IConfigVersionController).interfaceId
      || interfaceId == type(IInitializableDataValidator).interfaceId || super.supportsInterface(interfaceId);
  }

  /// @inheritdoc UUPSUpgradeable
  // solhint-disable-next-line no-empty-blocks
  function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

  /**
   * @notice Adds an item to the allowlist.
   * @param item The item to add.
   */
  function addAllowlistItem(bytes32 item) external onlyConfigEntry {
    _addAllowlistItem(item);
  }

  /**
   * @notice Removes an item from the allowlist.
   * @param item The item to remove.
   */
  function removeAllowlistItem(bytes32 item) external onlyConfigEntry {
    _removeAllowlistItem(item);
  }

  /**
   * @notice Adds an item to the denylist.
   * @param item The item to add.
   */
  function addDenylistItem(bytes32 item) external onlyConfigEntry {
    _addDenylistItem(item);
  }

  /**
   * @notice Removes an item from the denylist.
   * @param item The item to remove.
   */
  function removeDenylistItem(bytes32 item) external onlyConfigEntry {
    _removeDenylistItem(item);
  }

  /**
   * @notice Adds a supported data type.
   * @param dataTypeId The data type to add.
   */
  function addSupportedDataType(bytes32 dataTypeId) external onlyConfigEntry {
    _addSupportedDataType(dataTypeId);
  }

  /**
   * @notice Removes a supported data type.
   * @param dataTypeId The data type to remove.
   */
  function removeSupportedDataType(bytes32 dataTypeId) external onlyConfigEntry {
    _removeSupportedDataType(dataTypeId);
  }

  /**
   * @notice Returns whether an item is currently allowlisted.
   * @param item The item to check.
   * @return True if the item is allowlisted.
   */
  function isAllowlisted(bytes32 item) external view returns (bool) {
    return _allowDenyListDataValidatorStorage().allowlist[item];
  }

  /**
   * @notice Returns whether an item is currently denylisted.
   * @param item The item to check.
   * @return True if the item is denylisted.
   */
  function isDenylisted(bytes32 item) external view returns (bool) {
    return _allowDenyListDataValidatorStorage().denylist[item];
  }

  /**
   * @notice Returns whether a data type is explicitly supported.
   * @param dataTypeId The data type to check.
   * @return True if the data type is supported.
   */
  function isSupportedDataType(bytes32 dataTypeId) external view returns (bool) {
    return _allowDenyListDataValidatorStorage().supportedDataTypes[dataTypeId];
  }

  /**
   * @notice Returns whether a single item is allowed by the current lists.
   * @param item The bytes32 item to validate.
   * @return True if the item passes deny and allow checks.
   */
  function isItemAllowed(bytes32 item) public view returns (bool) {
    bytes32[] memory items = new bytes32[](1);
    items[0] = item;
    return _areItemsAllowed(items);
  }

  /// @inheritdoc ICredentialDataValidator
  function validateCredentialData(
    bytes32, /*ccid*/
    address, /*account*/
    bytes32 dataTypeId,
    bytes calldata credentialData,
    bytes calldata /*context*/
  )
    external
    view
    returns (bool)
  {
    AllowDenyListDataValidatorStorage storage $ = _allowDenyListDataValidatorStorage();

    if ($.supportedDataTypeCount > 0 && !$.supportedDataTypes[dataTypeId]) {
      return false;
    }

    if (credentialData.length < 64 || credentialData.length % 32 != 0) {
      return false;
    }

    bytes32[] memory items;
    try this.decodeItems(credentialData) returns (bytes32[] memory decodedItems) {
      items = decodedItems;
    } catch {
      return false;
    }

    return _areItemsAllowed(items);
  }

  /**
   * @notice Decodes the ABI-encoded item list used by the data payload.
   * @param credentialData The ABI-encoded bytes32 array payload.
   * @return items The decoded items.
   */
  function decodeItems(bytes calldata credentialData) external view onlyConfigEntry returns (bytes32[] memory items) {
    return abi.decode(credentialData, (bytes32[]));
  }

  /**
   * @notice Returns true when no item is denylisted and either the allowlist is empty or one item is allowlisted.
   * @param items The bytes32 items to evaluate.
   * @return True if the item set passes current deny and allow rules.
   */
  function _areItemsAllowed(bytes32[] memory items) internal view returns (bool) {
    AllowDenyListDataValidatorStorage storage $ = _allowDenyListDataValidatorStorage();
    bool anyAllowedFound = false;

    if (items.length == 0) {
      return false;
    }

    for (uint256 i = 0; i < items.length; ++i) {
      bytes32 item = items[i];
      if ($.denylist[item]) {
        return false;
      }
      if ($.allowlist[item]) {
        anyAllowedFound = true;
      }
    }

    if ($.allowlistCount == 0) {
      return true;
    }

    return anyAllowedFound;
  }

  /**
   * @notice Returns whether a selector is a supported configuration action.
   * @param selector The selector to check.
   * @return True if the selector is supported by configure.
   */
  function _isSupportedConfigSelector(bytes4 selector) internal pure override returns (bool) {
    if (selector == this.addAllowlistItem.selector || selector == this.removeAllowlistItem.selector) {
      return true;
    }
    if (selector == this.addDenylistItem.selector || selector == this.removeDenylistItem.selector) {
      return true;
    }
    bool supportsDataTypeSelectors =
      selector == this.addSupportedDataType.selector || selector == this.removeSupportedDataType.selector;
    return supportsDataTypeSelectors;
  }

  /**
   * @notice Adds a single item to the allowlist.
   * @param item The item to add.
   */
  function _addAllowlistItem(bytes32 item) internal {
    AllowDenyListDataValidatorStorage storage $ = _allowDenyListDataValidatorStorage();
    if ($.denylist[item]) {
      revert ItemInOppositeList(item);
    }
    if ($.allowlist[item]) {
      revert ItemAlreadyAllowlisted(item);
    }
    $.allowlist[item] = true;
    ++$.allowlistCount;
  }

  /**
   * @notice Removes a single item from the allowlist.
   * @param item The item to remove.
   */
  function _removeAllowlistItem(bytes32 item) internal {
    AllowDenyListDataValidatorStorage storage $ = _allowDenyListDataValidatorStorage();
    if (!$.allowlist[item]) {
      revert ItemNotAllowlisted(item);
    }
    delete $.allowlist[item];
    --$.allowlistCount;
  }

  /**
   * @notice Adds a single item to the denylist.
   * @param item The item to add.
   */
  function _addDenylistItem(bytes32 item) internal {
    AllowDenyListDataValidatorStorage storage $ = _allowDenyListDataValidatorStorage();
    if ($.allowlist[item]) {
      revert ItemInOppositeList(item);
    }
    if ($.denylist[item]) {
      revert ItemAlreadyDenylisted(item);
    }
    $.denylist[item] = true;
    ++$.denylistCount;
  }

  /**
   * @notice Removes a single item from the denylist.
   * @param item The item to remove.
   */
  function _removeDenylistItem(bytes32 item) internal {
    AllowDenyListDataValidatorStorage storage $ = _allowDenyListDataValidatorStorage();
    if (!$.denylist[item]) {
      revert ItemNotDenylisted(item);
    }
    delete $.denylist[item];
    --$.denylistCount;
  }

  /**
   * @notice Adds a single supported data type.
   * @param dataTypeId The data type to add.
   */
  function _addSupportedDataType(bytes32 dataTypeId) internal {
    AllowDenyListDataValidatorStorage storage $ = _allowDenyListDataValidatorStorage();
    if ($.supportedDataTypes[dataTypeId]) {
      revert DataTypeAlreadySupported(dataTypeId);
    }
    $.supportedDataTypes[dataTypeId] = true;
    ++$.supportedDataTypeCount;
  }

  /**
   * @notice Removes a single supported data type.
   * @param dataTypeId The data type to remove.
   */
  function _removeSupportedDataType(bytes32 dataTypeId) internal {
    AllowDenyListDataValidatorStorage storage $ = _allowDenyListDataValidatorStorage();
    if (!$.supportedDataTypes[dataTypeId]) {
      revert DataTypeNotSupported(dataTypeId);
    }
    delete $.supportedDataTypes[dataTypeId];
    --$.supportedDataTypeCount;
  }

  /**
   * @notice Adds a batch of items to the allowlist during initialization.
   * @param items The items to add.
   */
  function _addAllowlistItems(bytes32[] memory items) internal {
    uint256 itemsLength = items.length;
    for (uint256 i = 0; i < itemsLength; ++i) {
      _addAllowlistItem(items[i]);
    }
  }

  /**
   * @notice Adds a batch of items to the denylist during initialization.
   * @param items The items to add.
   */
  function _addDenylistItems(bytes32[] memory items) internal {
    uint256 itemsLength = items.length;
    for (uint256 i = 0; i < itemsLength; ++i) {
      _addDenylistItem(items[i]);
    }
  }

  /**
   * @notice Adds a batch of supported data types during initialization.
   * @param dataTypeIds The data types to add.
   */
  function _addSupportedDataTypes(bytes32[] memory dataTypeIds) internal {
    uint256 dataTypeIdsLength = dataTypeIds.length;
    for (uint256 i = 0; i < dataTypeIdsLength; ++i) {
      _addSupportedDataType(dataTypeIds[i]);
    }
  }
}
