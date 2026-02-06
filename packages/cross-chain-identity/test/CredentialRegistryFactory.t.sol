// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CredentialRegistryFactory} from "../src/CredentialRegistryFactory.sol";
import {CredentialRegistry} from "../src/CredentialRegistry.sol";
import {PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";

contract CredentialRegistryFactoryTest is Test {
  PolicyEngine private s_policyEngine;
  CredentialRegistryFactory private s_factory;
  CredentialRegistry private s_registryImplementation;

  function setUp() public {
    s_policyEngine = new PolicyEngine();
    s_factory = new CredentialRegistryFactory();
    s_registryImplementation = new CredentialRegistry();
  }

  function test_createCredentialRegistry_success() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    address expectedRegistryAddress =
      s_factory.predictRegistryAddress(address(this), address(s_registryImplementation), registryId);

    vm.expectEmit();
    emit CredentialRegistryFactory.CredentialRegistryCreated(expectedRegistryAddress);

    address newRegistryAddress = s_factory.createCredentialRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), address(this)
    );
    assertEq(newRegistryAddress, expectedRegistryAddress);
  }

  function test_createCredentialRegistry_duplicateCreate_success() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    address expectedRegistryAddress =
      s_factory.predictRegistryAddress(address(this), address(s_registryImplementation), registryId);

    vm.expectEmit();
    emit CredentialRegistryFactory.CredentialRegistryCreated(expectedRegistryAddress);

    address newRegistryAddress = s_factory.createCredentialRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), address(this)
    );
    address newRegistryAddress2 = s_factory.createCredentialRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), address(this)
    );
    assertEq(newRegistryAddress, newRegistryAddress2);
  }

  function test_createCredentialRegistry_badImplementation_revert() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    vm.expectRevert();
    s_factory.createCredentialRegistry(address(0), registryId, address(s_policyEngine), address(this));
  }

  function test_createCredentialRegistry_zeroPolicyEngine_revert() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    vm.expectRevert();
    s_factory.createCredentialRegistry(address(s_registryImplementation), registryId, address(0), address(this));
  }

  function test_createCredentialRegistry_zeroInitialOwner_revert() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));

    vm.expectRevert();
    s_factory.createCredentialRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), address(0)
    );
  }

  function test_createCredentialRegistry_verifyInitialization() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));
    address initialOwner = address(0x123);

    address registryAddress = s_factory.createCredentialRegistry(
      address(s_registryImplementation), registryId, address(s_policyEngine), initialOwner
    );

    CredentialRegistry registry = CredentialRegistry(registryAddress);
    assertEq(registry.owner(), initialOwner, "Registry owner should be set correctly");
    assertEq(registry.getPolicyEngine(), address(s_policyEngine), "Policy engine should be attached");
  }

  function test_createCredentialRegistry_differentUsers() public {
    bytes32 registryId = keccak256(abi.encodePacked("registry-1"));
    address user1 = address(0x111);
    address user2 = address(0x222);

    address registry1 =
      s_factory.createCredentialRegistry(address(s_registryImplementation), registryId, address(s_policyEngine), user1);

    vm.prank(user2);
    address registry2 =
      s_factory.createCredentialRegistry(address(s_registryImplementation), registryId, address(s_policyEngine), user2);

    assertTrue(registry1 != registry2, "Different users should get different registry addresses");
    assertEq(CredentialRegistry(registry1).owner(), user1, "Registry 1 owner should be user1");
    assertEq(CredentialRegistry(registry2).owner(), user2, "Registry 2 owner should be user2");
  }
}
