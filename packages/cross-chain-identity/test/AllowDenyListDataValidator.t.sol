// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {AllowDenyListDataValidator} from "../src/data-validators/AllowDenyListDataValidator.sol";
import {ConfigVersionController} from "../src/data-validators/ConfigVersionController.sol";
import {IConfigVersionController} from "../src/interfaces/IConfigVersionController.sol";

/**
 * @title AllowDenyListDataValidatorTest
 * @notice Covers allow/deny evaluation and version-controlled config updates.
 * @author Chainlink
 */
contract AllowDenyListDataValidatorTest is Test {
  bytes32 private constant ITEM_US = bytes32("US");
  bytes32 private constant ITEM_TR = bytes32("TR");
  bytes32 private constant ITEM_UK = bytes32("UK");
  bytes32 private constant ITEM_FR = bytes32("FR");
  bytes32 private constant DATA_TYPE_REGION = keccak256("common.region");
  bytes32 private constant DATA_TYPE_COUNTRY = keccak256("common.country");
  bytes32 private constant DATA_TYPE_OTHER = keccak256("common.other");

  address private s_owner;
  address private s_notOwner;
  AllowDenyListDataValidator private s_validator;

  /// @notice Deploys a validator proxy with initial lists and supported data types.
  function setUp() public {
    s_owner = makeAddr("owner");
    s_notOwner = makeAddr("notOwner");

    bytes32[] memory allowlist = new bytes32[](2);
    allowlist[0] = ITEM_US;
    allowlist[1] = ITEM_TR;

    bytes32[] memory denylist = new bytes32[](1);
    denylist[0] = ITEM_UK;

    bytes32[] memory supportedDataTypes = new bytes32[](1);
    supportedDataTypes[0] = DATA_TYPE_COUNTRY;

    s_validator = _deployValidator(s_owner, allowlist, denylist, supportedDataTypes);
  }

  /// @notice After initialize, configuration version is 1.
  function test_initialize_setsConfigVersionOne() public view {
    assertEq(s_validator.getConfigVersion(), 1);
  }

  /// @notice Supported data types pass when any decoded item is allowlisted and none is denylisted.
  function test_validateCredentialData_success() public view {
    assertTrue(
      s_validator.validateCredentialData(
        bytes32(0), address(0), DATA_TYPE_COUNTRY, abi.encode(_asArray(ITEM_FR, ITEM_US)), ""
      )
    );
    assertTrue(s_validator.isItemAllowed(ITEM_TR));
  }

  /// @notice Denylist entries always fail even if another decoded item is allowlisted.
  function test_validateCredentialData_denylistPrecedence() public view {
    assertFalse(
      s_validator.validateCredentialData(
        bytes32(0), address(0), DATA_TYPE_COUNTRY, abi.encode(_asArray(ITEM_US, ITEM_UK)), ""
      )
    );
    assertFalse(s_validator.isItemAllowed(ITEM_UK));
  }

  /// @notice Validation fails when none of the decoded items are allowlisted.
  function test_validateCredentialData_allowlistGate() public view {
    assertFalse(
      s_validator.validateCredentialData(bytes32(0), address(0), DATA_TYPE_COUNTRY, abi.encode(_asArray(ITEM_FR)), "")
    );
  }

  /// @notice Unsupported data types are rejected while a support list is configured.
  function test_validateCredentialData_rejectsUnsupportedDataType() public view {
    assertFalse(
      s_validator.validateCredentialData(bytes32(0), address(0), DATA_TYPE_OTHER, abi.encode(_asArray(ITEM_US)), "")
    );
  }

  /// @notice Malformed data payloads fail closed instead of reverting.
  function test_validateCredentialData_rejectsMalformedEncoding() public view {
    assertFalse(s_validator.validateCredentialData(bytes32(0), address(0), DATA_TYPE_COUNTRY, bytes("US"), ""));
    assertFalse(s_validator.validateCredentialData(bytes32(0), address(0), DATA_TYPE_COUNTRY, hex"1234", ""));
  }

  /// @notice Single-item config changes require the expected version and emit the transition.
  function test_addDenylistItem_incrementsVersion() public {
    uint256 currentVersion = s_validator.getConfigVersion();
    bytes memory configCall = abi.encodeCall(AllowDenyListDataValidator.addDenylistItem, (ITEM_FR));
    uint256 expectedNextVersion = currentVersion + 1;

    vm.expectEmit();
    emit IConfigVersionController.ConfigurationUpdated(
      currentVersion, expectedNextVersion, AllowDenyListDataValidator.addDenylistItem.selector, configCall
    );

    vm.prank(s_owner);
    uint256 returnedVersion = s_validator.configure(currentVersion, configCall);

    assertEq(returnedVersion, expectedNextVersion);
    assertEq(s_validator.getConfigVersion(), expectedNextVersion);
    assertTrue(s_validator.isDenylisted(ITEM_FR));
    assertFalse(s_validator.isItemAllowed(ITEM_FR));
  }

  /// @notice Removing all allowlist entries one by one leaves the validator in deny-only mode.
  function test_removeAllowlistItem_allowsUnknownItemsWhenAllowlistEmpty() public {
    uint256 currentVersion = s_validator.getConfigVersion();
    bytes memory removeUsCall = abi.encodeCall(AllowDenyListDataValidator.removeAllowlistItem, (ITEM_US));

    vm.prank(s_owner);
    currentVersion = s_validator.configure(currentVersion, removeUsCall);

    bytes memory removeTrCall = abi.encodeCall(AllowDenyListDataValidator.removeAllowlistItem, (ITEM_TR));

    vm.prank(s_owner);
    currentVersion = s_validator.configure(currentVersion, removeTrCall);

    assertFalse(s_validator.isAllowlisted(ITEM_US));
    assertFalse(s_validator.isAllowlisted(ITEM_TR));
    assertTrue(
      s_validator.validateCredentialData(bytes32(0), address(0), DATA_TYPE_COUNTRY, abi.encode(_asArray(ITEM_FR)), "")
    );
  }

  /// @notice When both lists are empty, validation passes because no rule is configured.
  function test_validateCredentialData_passesWhenBothListsEmpty() public {
    uint256 currentVersion = s_validator.getConfigVersion();
    bytes memory removeUsCall = abi.encodeCall(AllowDenyListDataValidator.removeAllowlistItem, (ITEM_US));

    vm.prank(s_owner);
    currentVersion = s_validator.configure(currentVersion, removeUsCall);

    bytes memory removeTrCall = abi.encodeCall(AllowDenyListDataValidator.removeAllowlistItem, (ITEM_TR));

    vm.prank(s_owner);
    currentVersion = s_validator.configure(currentVersion, removeTrCall);

    bytes memory removeUkCall = abi.encodeCall(AllowDenyListDataValidator.removeDenylistItem, (ITEM_UK));

    vm.prank(s_owner);
    currentVersion = s_validator.configure(currentVersion, removeUkCall);

    assertEq(currentVersion, s_validator.getConfigVersion());
    assertTrue(
      s_validator.validateCredentialData(bytes32(0), address(0), DATA_TYPE_COUNTRY, abi.encode(_asArray(ITEM_FR)), "")
    );
  }

  /// @notice Calls revert when the caller uses a stale version.
  function test_addAllowlistItem_revertsOnStaleVersion() public {
    vm.startPrank(s_owner);
    uint256 currentVersion = s_validator.getConfigVersion();
    bytes memory configCall = abi.encodeCall(AllowDenyListDataValidator.addAllowlistItem, (bytes32("DE")));
    vm.expectRevert(
      abi.encodeWithSelector(ConfigVersionController.UnexpectedConfigVersion.selector, uint256(123), currentVersion)
    );
    s_validator.configure(123, configCall);
    vm.stopPrank();
  }

  /// @notice configure wraps action reverts with selector-aware configuration errors.
  function test_configure_wrapsActionErrors() public {
    uint256 currentVersion = s_validator.getConfigVersion();
    bytes memory configCall = abi.encodeCall(AllowDenyListDataValidator.addDenylistItem, (ITEM_UK));

    vm.expectRevert(
      abi.encodeWithSelector(
        ConfigVersionController.ConfigurationError.selector,
        AllowDenyListDataValidator.addDenylistItem.selector,
        abi.encodeWithSelector(AllowDenyListDataValidator.ItemAlreadyDenylisted.selector, ITEM_UK)
      )
    );

    vm.prank(s_owner);
    s_validator.configure(currentVersion, configCall);
  }

  /// @notice Adding an item to the opposite list is rejected to preserve disjoint membership.
  function test_addDenylistItem_revertsWhenItemAlreadyAllowlisted() public {
    uint256 currentVersion = s_validator.getConfigVersion();
    bytes memory configCall = abi.encodeCall(AllowDenyListDataValidator.addDenylistItem, (ITEM_US));

    vm.expectRevert(
      abi.encodeWithSelector(
        ConfigVersionController.ConfigurationError.selector,
        AllowDenyListDataValidator.addDenylistItem.selector,
        abi.encodeWithSelector(AllowDenyListDataValidator.ItemInOppositeList.selector, ITEM_US)
      )
    );

    vm.prank(s_owner);
    s_validator.configure(currentVersion, configCall);
  }

  /// @notice Direct calls to action methods are rejected unless they come from configure.
  function test_actionMethod_revertsOutsideConfigure() public {
    vm.expectRevert(ConfigVersionController.OnlyConfigEntry.selector);
    s_validator.addAllowlistItem(bytes32("DE"));
  }

  /// @notice Only the owner can update the config through configure.
  function test_onlyOwner_reverts() public {
    uint256 currentVersion = s_validator.getConfigVersion();
    bytes memory configCall = abi.encodeCall(AllowDenyListDataValidator.addSupportedDataType, (DATA_TYPE_REGION));
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, s_notOwner));
    vm.prank(s_notOwner);
    s_validator.configure(currentVersion, configCall);
  }

  /**
   * @notice Deploys a validator behind an ERC1967 proxy.
   * @param initialOwner The owner assigned during initialization.
   * @param initialAllowlist The initial allowlist items.
   * @param initialDenylist The initial denylist items.
   * @param initialSupportedDataTypes The initial supported data types.
   * @return The deployed proxy-backed validator.
   */
  function _deployValidator(
    address initialOwner,
    bytes32[] memory initialAllowlist,
    bytes32[] memory initialDenylist,
    bytes32[] memory initialSupportedDataTypes
  )
    internal
    returns (AllowDenyListDataValidator)
  {
    AllowDenyListDataValidator implementation = new AllowDenyListDataValidator();
    bytes memory initData = abi.encodeWithSelector(
      AllowDenyListDataValidator.initialize.selector,
      initialOwner,
      abi.encode(initialAllowlist, initialDenylist, initialSupportedDataTypes)
    );
    ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
    return AllowDenyListDataValidator(address(proxy));
  }

  /**
   * @notice Creates a one-item array.
   * @param item0 The item to include.
   * @return items The resulting array.
   */
  function _asArray(bytes32 item0) internal pure returns (bytes32[] memory items) {
    items = new bytes32[](1);
    items[0] = item0;
  }

  /**
   * @notice Creates a two-item array.
   * @param item0 The first item to include.
   * @param item1 The second item to include.
   * @return items The resulting array.
   */
  function _asArray(bytes32 item0, bytes32 item1) internal pure returns (bytes32[] memory items) {
    items = new bytes32[](2);
    items[0] = item0;
    items[1] = item1;
  }
}
