// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IdentityRegistryFactory} from "../src/IdentityRegistryFactory.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";

contract IdentityRegistryFactoryTest is Test {
  PolicyEngine private s_policyEngine;
  IdentityRegistryFactory private s_factory;
  IdentityRegistry private s_registryImplementation;

  function setUp() public {
    s_policyEngine = new PolicyEngine();
    s_factory = new IdentityRegistryFactory();
    s_registryImplementation = new IdentityRegistry();
  }

  function test_createIdentityRegistry_success() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    address expectedRegistryAddress =
      s_factory.predictRegistryAddress(address(this), address(s_registryImplementation), registryId);

    vm.expectEmit();
    emit IdentityRegistryFactory.IdentityRegistryCreated(expectedRegistryAddress);

    address newRegistryAddress = s_factory.createIdentityRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), address(this)
    );
    assertEq(newRegistryAddress, expectedRegistryAddress);
  }

  function test_createIdentityRegistry_duplicateCreate_success() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    address expectedRegistryAddress =
      s_factory.predictRegistryAddress(address(this), address(s_registryImplementation), registryId);

    vm.expectEmit();
    emit IdentityRegistryFactory.IdentityRegistryCreated(expectedRegistryAddress);

    address newRegistryAddress = s_factory.createIdentityRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), address(this)
    );
    address newRegistryAddress2 = s_factory.createIdentityRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), address(this)
    );
    assertEq(newRegistryAddress, newRegistryAddress2);
  }

  function test_createIdentityRegistry_badImplementation_revert() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    vm.expectRevert();
    s_factory.createIdentityRegistry(address(0), registryId, address(s_policyEngine), address(this));
  }

  function test_createIdentityRegistry_zeroPolicyEngine_revert() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    vm.expectRevert();
    s_factory.createIdentityRegistry(address(s_registryImplementation), registryId, address(0), address(this));
  }

  function test_createIdentityRegistry_zeroInitialOwner_revert() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    vm.expectRevert();
    s_factory.createIdentityRegistry(address(s_registryImplementation), registryId, address(s_policyEngine), address(0));
  }

  function test_createIdentityRegistry_verifyInitialization() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));
    address initialOwner = address(0x123);

    address registryAddress = s_factory.createIdentityRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), initialOwner
    );

    IdentityRegistry registry = IdentityRegistry(registryAddress);
    assertEq(registry.owner(), initialOwner, "Registry owner should be set correctly");
    assertEq(registry.getPolicyEngine(), address(s_policyEngine), "Policy engine should be attached");
  }

  function test_createIdentityRegistry_differentUsers() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));
    address user1 = address(0x111);
    address user2 = address(0x222);

    address registry1 =
      s_factory.createIdentityRegistry(address(s_registryImplementation), registryId, address(s_policyEngine), user1);

    vm.prank(user2);
    address registry2 =
      s_factory.createIdentityRegistry(address(s_registryImplementation), registryId, address(s_policyEngine), user2);

    assertTrue(registry1 != registry2, "Different users should get different registry addresses");
    assertEq(IdentityRegistry(registry1).owner(), user1, "Registry 1 owner should be user1");
    assertEq(IdentityRegistry(registry2).owner(), user2, "Registry 2 owner should be user2");
  }
}
