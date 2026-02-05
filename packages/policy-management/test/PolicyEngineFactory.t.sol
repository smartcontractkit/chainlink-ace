// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {PolicyEngineFactory} from "../src/core/PolicyEngineFactory.sol";
import {PolicyEngine} from "../src/core/PolicyEngine.sol";
import {IPolicyEngine} from "../src/interfaces/IPolicyEngine.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract PolicyEngineFactoryTest is BaseProxyTest {
  PolicyEngineFactory private s_factory;
  PolicyEngine private s_engineImplementation;

  function setUp() public {
    s_factory = new PolicyEngineFactory();
    s_engineImplementation = new PolicyEngine();
  }

  function test_createPolicyEngine_success() public {
    bytes32 engineId = keccak256(abi.encodePacked("engine-1"));

    address expectedEngineAddress =
      s_factory.predictEngineAddress(address(this), address(s_engineImplementation), engineId);

    vm.expectEmit();
    emit PolicyEngineFactory.PolicyEngineCreated(expectedEngineAddress);

    address newEngineAddress =
      s_factory.createPolicyEngine(address(s_engineImplementation), engineId, false, address(this));
    assertEq(newEngineAddress, expectedEngineAddress);
  }

  function test_createPolicyEngine_duplicateCreate_success() public {
    bytes32 engineId = keccak256(abi.encodePacked("engine-1"));

    address expectedEngineAddress =
      s_factory.predictEngineAddress(address(this), address(s_engineImplementation), engineId);

    vm.expectEmit();
    emit PolicyEngineFactory.PolicyEngineCreated(expectedEngineAddress);

    address newEngineAddress =
      s_factory.createPolicyEngine(address(s_engineImplementation), engineId, false, address(this));
    address newEngineAddress2 =
      s_factory.createPolicyEngine(address(s_engineImplementation), engineId, false, address(this));
    assertEq(newEngineAddress, newEngineAddress2);
  }

  function test_createPolicyEngine_zeroAddress_revert() public {
    bytes32 engineId = keccak256(abi.encodePacked("engine-1"));

    vm.expectRevert();
    s_factory.createPolicyEngine(address(0), engineId, false, address(this));
  }

  function test_createPolicyEngine_verifyInitialization() public {
    bytes32 engineId = keccak256(abi.encodePacked("engine-1"));
    address initialOwner = address(0x123);

    address engineAddress = s_factory.createPolicyEngine(address(s_engineImplementation), engineId, false, initialOwner);

    PolicyEngine engine = PolicyEngine(engineAddress);
    assertTrue(
      engine.hasRole(engine.DEFAULT_ADMIN_ROLE(), initialOwner),
      "Engine should have DEFAULT_ADMIN_ROLE assigned to initialOwner"
    );
    assertTrue(
      engine.hasRole(engine.ADMIN_ROLE(), initialOwner), "Engine should have ADMIN_ROLE assigned to initialOwner"
    );
    assertTrue(
      engine.hasRole(engine.POLICY_CONFIG_ADMIN_ROLE(), initialOwner),
      "Engine should have POLICY_CONFIG_ADMIN_ROLE assigned to initialOwner"
    );
  }

  function test_createPolicyEngine_differentUsers() public {
    bytes32 engineId = keccak256(abi.encodePacked("engine-1"));
    address user1 = address(0x111);
    address user2 = address(0x222);

    address engine1 = s_factory.createPolicyEngine(address(s_engineImplementation), engineId, false, user1);

    vm.prank(user2);
    address engine2 = s_factory.createPolicyEngine(address(s_engineImplementation), engineId, false, user2);

    assertTrue(engine1 != engine2, "Different users should get different engine addresses");
    assertTrue(
      PolicyEngine(engine1).hasRole(PolicyEngine(engine1).DEFAULT_ADMIN_ROLE(), user1),
      "Engine 1 should have DEFAULT_ADMIN_ROLE assigned to user1"
    );
    assertTrue(
      PolicyEngine(engine2).hasRole(PolicyEngine(engine2).DEFAULT_ADMIN_ROLE(), user2),
      "Engine 2 should have DEFAULT_ADMIN_ROLE assigned to user2"
    );
  }
}
