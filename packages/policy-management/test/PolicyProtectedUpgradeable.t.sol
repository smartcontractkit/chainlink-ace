// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyProtected} from "../src/interfaces/IPolicyProtected.sol";
import {IPolicyEngine, PolicyEngine} from "../src/core/PolicyEngine.sol";
import {MaxPolicy} from "../src/policies/MaxPolicy.sol";
import {MockTokenExtractor} from "./helpers/MockTokenExtractor.sol";
import {MockTokenUpgradeable} from "./helpers/MockTokenUpgradeable.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";
import {FaultyPolicyEngine} from "./helpers/FaultyPolicyEngine.sol";

contract PolicyProtectedUpgradeableTest is BaseProxyTest {
  MockTokenUpgradeable public token;
  PolicyEngine public policyEngine;
  MaxPolicy public policy;

  function setUp() public {
    policyEngine = _deployPolicyEngine(true, address(this));

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    MaxPolicy policyImpl = new MaxPolicy();
    policy = MaxPolicy(_deployPolicy(address(policyImpl), address(policyEngine), address(this), abi.encode(100)));
    MockTokenExtractor extractor = new MockTokenExtractor();

    bytes4[] memory selectors = new bytes4[](3);
    selectors[0] = MockTokenUpgradeable.transfer.selector;
    selectors[1] = MockTokenUpgradeable.transferWithContext.selector;
    selectors[2] = MockTokenUpgradeable.transferFrom.selector;

    policyEngine.setExtractors(selectors, address(extractor));

    bytes32[] memory parameterOutputFormat = new bytes32[](1);
    parameterOutputFormat[0] = extractor.PARAM_AMOUNT();

    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transfer.selector, address(policy), parameterOutputFormat
    );
    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transferWithContext.selector, address(policy), parameterOutputFormat
    );
    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transferFrom.selector, address(policy), parameterOutputFormat
    );
  }

  function test_policyEngine_targetAttached() public {
    PolicyEngine newEngine = _deployPolicyEngine(true, address(this));

    vm.expectEmit();
    emit IPolicyEngine.TargetAttached(address(token));
    vm.expectEmit();
    emit IPolicyProtected.PolicyEngineAttached(address(newEngine));
    vm.expectEmit();
    emit IPolicyEngine.TargetDetached(address(token));

    token.attachPolicyEngine(address(newEngine));
  }

  function test_transfer_success() public {
    address recipient = makeAddr("recipient");
    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);
  }

  function test_transferWithContext_success() public {
    address recipient = makeAddr("recipient");
    token.transferWithContext(recipient, 100, "");
    assert(token.balanceOf(recipient) == 100);
  }

  function test_transfer_defaultPolicyRejected_reverts() public {
    policyEngine.setTargetDefaultPolicyAllow(address(token), false);

    address recipient = makeAddr("recipient");
    _expectRejectedRevert(
      address(0),
      "no policy allowed the action and default is reject",
      MockTokenUpgradeable.transfer.selector,
      address(this),
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_transfer_overQuota_reverts() public {
    address recipient = makeAddr("recipient");
    _expectRejectedRevert(
      address(policy),
      "amount exceeds maximum limit",
      MockTokenUpgradeable.transfer.selector,
      address(this),
      abi.encode(recipient, 200)
    );
    token.transfer(recipient, 200);
  }

  function test_transferWithContext_overQuota_reverts() public {
    address recipient = makeAddr("recipient");
    _expectRejectedRevert(
      address(policy),
      "amount exceeds maximum limit",
      MockTokenUpgradeable.transferWithContext.selector,
      address(this),
      abi.encode(recipient, 200, "")
    );
    token.transferWithContext(recipient, 200, "");
  }

  function test_policyEngine_detach_ignoreRevert() public {
    FaultyPolicyEngine faultyPolicyEngine = new FaultyPolicyEngine();
    token.attachPolicyEngine(address(faultyPolicyEngine));

    vm.expectEmit();
    emit IPolicyProtected.PolicyEngineAttached(address(policyEngine));
    // change policy engine i.e. detach from engine - FaultyPolicyEngine will always revert, but we should ignore it and
    // continue
    vm.expectEmit();
    emit IPolicyProtected.PolicyEngineDetachFailed(
      address(faultyPolicyEngine), abi.encodeWithSignature("Error(string)", "FaultyPolicyEngine: detach not allowed")
    );
    token.attachPolicyEngine(address(policyEngine));
    assert(token.getPolicyEngine() == address(policyEngine));
  }

  function test_getContext_defaultsEmpty() public view {
    assertEq(token.getContext().length, 0);
  }

  function test_setContext_getContext() public {
    bytes memory context = abi.encode("some-context", uint256(42));
    token.setContext(context);
    assertEq(token.getContext(), context);
  }

  function test_getContext_isPerSender() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    bytes memory aliceContext = abi.encode("alice");
    bytes memory bobContext = abi.encode("bob");

    vm.prank(alice);
    token.setContext(aliceContext);
    vm.prank(bob);
    token.setContext(bobContext);

    vm.prank(alice);
    assertEq(token.getContext(), aliceContext);
    vm.prank(bob);
    assertEq(token.getContext(), bobContext);
  }

  function test_clearContext() public {
    bytes memory context = abi.encode("some-context");
    token.setContext(context);
    assertEq(token.getContext(), context);

    token.clearContext();
    assertEq(token.getContext().length, 0);
  }

  function test_clearContext_onlyClearsCallerContext() public {
    address alice = makeAddr("alice");
    bytes memory aliceContext = abi.encode("alice");
    bytes memory selfContext = abi.encode("self");

    vm.prank(alice);
    token.setContext(aliceContext);
    token.setContext(selfContext);

    token.clearContext();

    assertEq(token.getContext().length, 0);
    assertEq(token.getSenderContext(alice), aliceContext);
  }

  function test_getSenderContext_defaultsEmpty() public {
    assertEq(token.getSenderContext(makeAddr("nobody")).length, 0);
  }

  function test_getSenderContext_returnsSenderContext() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    bytes memory aliceContext = abi.encode("alice", uint256(1));
    bytes memory bobContext = abi.encode("bob", uint256(2));

    vm.prank(alice);
    token.setContext(aliceContext);
    vm.prank(bob);
    token.setContext(bobContext);

    assertEq(token.getSenderContext(alice), aliceContext);
    assertEq(token.getSenderContext(bob), bobContext);
  }

  function test_getSenderContext_matchesGetContext() public {
    address alice = makeAddr("alice");
    bytes memory context = abi.encode("alice-context");

    vm.prank(alice);
    token.setContext(context);

    vm.prank(alice);
    assertEq(token.getContext(), token.getSenderContext(alice));
  }
}
