// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyProtected} from "../src/interfaces/IPolicyProtected.sol";
import {IPolicyEngine, PolicyEngine} from "../src/core/PolicyEngine.sol";
import {MaxPolicy} from "../src/policies/MaxPolicy.sol";
import {MockTokenExtractor} from "./helpers/MockTokenExtractor.sol";
import {MockTokenUpgradeable} from "./helpers/MockTokenUpgradeable.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
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
    emit IPolicyEngine.TargetDetached(address(token));
    vm.expectEmit();
    emit IPolicyEngine.TargetAttached(address(token));
    vm.expectEmit();
    emit IPolicyProtected.PolicyEngineAttached(address(newEngine));

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

    // change policy engine i.e. detach from engine - FaultyPolicyEngine will always revert, but we should ignore it and
    // continue
    vm.expectEmit();
    emit IPolicyProtected.PolicyEngineDetachFailed(
      address(faultyPolicyEngine), abi.encodeWithSignature("Error(string)", "FaultyPolicyEngine: detach not allowed")
    );
    vm.expectEmit();
    emit IPolicyProtected.PolicyEngineAttached(address(policyEngine));
    token.attachPolicyEngine(address(policyEngine));
    assert(token.getPolicyEngine() == address(policyEngine));
  }
}
