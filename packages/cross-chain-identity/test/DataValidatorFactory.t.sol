// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DataValidatorFactory} from "../src/data-validators/DataValidatorFactory.sol";
import {AllowDenyListDataValidator} from "../src/data-validators/AllowDenyListDataValidator.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/// @notice ERC-165 contract that does not advertise validator interfaces (for factory negative tests).
contract MockUnsupportedValidatorImplementation is ERC165 {
  function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
    return super.supportsInterface(interfaceId);
  }
}

contract DataValidatorFactoryTest is Test {
  DataValidatorFactory private s_factory;
  AllowDenyListDataValidator private s_implementation;

  bytes32 private constant ITEM_US = bytes32("US");
  bytes32 private constant DATA_TYPE_COUNTRY = keccak256("common.country");

  function setUp() public {
    s_factory = new DataValidatorFactory();
    s_implementation = new AllowDenyListDataValidator();
  }

  function _sampleConfigData() internal pure returns (bytes memory) {
    bytes32[] memory allowlist = new bytes32[](1);
    allowlist[0] = ITEM_US;
    bytes32[] memory denylist = new bytes32[](0);
    bytes32[] memory dataTypes = new bytes32[](1);
    dataTypes[0] = DATA_TYPE_COUNTRY;
    return abi.encode(allowlist, denylist, dataTypes);
  }

  function test_createDataValidator_success() public {
    bytes32 validatorId = keccak256(abi.encodePacked("validator-1"));
    bytes memory configData = _sampleConfigData();

    address expected = s_factory.predictDataValidatorAddress(address(this), address(s_implementation), validatorId);

    vm.expectEmit();
    emit DataValidatorFactory.DataValidatorCreated(expected);

    address created = s_factory.createDataValidator(address(s_implementation), validatorId, address(this), configData);
    assertEq(created, expected);

    AllowDenyListDataValidator v = AllowDenyListDataValidator(created);
    assertEq(v.owner(), address(this));
    assertTrue(v.validateCredentialData(bytes32(0), address(0), DATA_TYPE_COUNTRY, abi.encode(allowlistOne()), ""));
  }

  function test_createUpgradeableDataValidator_success() public {
    bytes32 validatorId = keccak256(abi.encodePacked("validator-uups-1"));
    bytes memory configData = _sampleConfigData();

    address expected = s_factory.predictUpgradeableDataValidatorAddress(
      address(this), address(s_implementation), validatorId, address(this), configData
    );

    vm.expectEmit();
    emit DataValidatorFactory.DataValidatorCreated(expected);

    address created =
      s_factory.createUpgradeableDataValidator(address(s_implementation), validatorId, address(this), configData);
    assertEq(created, expected);

    AllowDenyListDataValidator v = AllowDenyListDataValidator(created);
    assertEq(v.owner(), address(this));

    AllowDenyListDataValidator newImpl = new AllowDenyListDataValidator();
    vm.prank(address(this));
    v.upgradeToAndCall(address(newImpl), "");
    assertTrue(v.validateCredentialData(bytes32(0), address(0), DATA_TYPE_COUNTRY, abi.encode(allowlistOne()), ""));
  }

  function test_createDataValidator_duplicateCreate_reverts() public {
    bytes32 validatorId = keccak256(abi.encodePacked("validator-dup"));
    bytes memory configData = _sampleConfigData();

    s_factory.createDataValidator(address(s_implementation), validatorId, address(this), configData);
    vm.expectRevert(DataValidatorFactory.DataValidatorAlreadyExists.selector);
    s_factory.createDataValidator(address(s_implementation), validatorId, address(this), configData);
  }

  function test_getOrCreateDataValidator_duplicate_returnsExisting() public {
    bytes32 validatorId = keccak256(abi.encodePacked("validator-dup"));
    bytes memory configData = _sampleConfigData();

    address a = s_factory.getOrCreateDataValidator(address(s_implementation), validatorId, address(this), configData);
    address b = s_factory.getOrCreateDataValidator(address(s_implementation), validatorId, address(this), configData);
    assertEq(a, b);
  }

  function test_createUpgradeableDataValidator_duplicateCreate_reverts() public {
    bytes32 validatorId = keccak256(abi.encodePacked("validator-uups-dup"));
    bytes memory configData = _sampleConfigData();

    s_factory.createUpgradeableDataValidator(address(s_implementation), validatorId, address(this), configData);
    vm.expectRevert(DataValidatorFactory.DataValidatorAlreadyExists.selector);
    s_factory.createUpgradeableDataValidator(address(s_implementation), validatorId, address(this), configData);
  }

  function test_getOrCreateUpgradeableDataValidator_duplicate_returnsExisting() public {
    bytes32 validatorId = keccak256(abi.encodePacked("validator-uups-dup"));
    bytes memory configData = _sampleConfigData();

    address a =
      s_factory.getOrCreateUpgradeableDataValidator(address(s_implementation), validatorId, address(this), configData);
    address b =
      s_factory.getOrCreateUpgradeableDataValidator(address(s_implementation), validatorId, address(this), configData);
    assertEq(a, b);
  }

  function test_createDataValidator_zeroImplementation_reverts() public {
    vm.expectRevert(DataValidatorFactory.ImplementationIsZeroAddress.selector);
    s_factory.createDataValidator(address(0), bytes32(uint256(1)), address(this), _sampleConfigData());
  }

  function test_createDataValidator_badImplementation_reverts() public {
    MockUnsupportedValidatorImplementation bad = new MockUnsupportedValidatorImplementation();
    vm.expectRevert(DataValidatorFactory.DataValidatorUnsupported.selector);
    s_factory.createDataValidator(address(bad), bytes32(uint256(1)), address(this), _sampleConfigData());
  }

  function test_createUpgradeableDataValidator_upgradeNotOwner_reverts() public {
    bytes32 validatorId = keccak256(abi.encodePacked("validator-uups-2"));
    address owner = makeAddr("owner");
    address notOwner = makeAddr("notOwner");

    address created =
      s_factory.createUpgradeableDataValidator(address(s_implementation), validatorId, owner, _sampleConfigData());
    AllowDenyListDataValidator v = AllowDenyListDataValidator(created);
    AllowDenyListDataValidator newImpl = new AllowDenyListDataValidator();

    vm.prank(notOwner);
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, notOwner));
    v.upgradeToAndCall(address(newImpl), "");
  }

  function allowlistOne() private pure returns (bytes32[] memory a) {
    a = new bytes32[](1);
    a[0] = ITEM_US;
  }
}
