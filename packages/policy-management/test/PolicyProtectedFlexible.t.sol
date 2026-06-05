// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyProtected} from "../src/interfaces/IPolicyProtected.sol";
import {IPolicyEngine, PolicyEngine} from "../src/core/PolicyEngine.sol";
import {MockTokenFlexible} from "./helpers/MockTokenFlexible.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract PolicyProtectedFlexibleTest is BaseProxyTest {
  function test_attachPolicyEngineAfterDeploy_success() public {
    MockTokenFlexible token = new MockTokenFlexible(address(0));
    PolicyEngine policyEngine = _deployPolicyEngine(true, address(this));

    vm.expectEmit();
    emit IPolicyEngine.TargetAttached(address(token));
    vm.expectEmit();
    emit IPolicyProtected.PolicyEngineAttached(address(policyEngine));

    token.attachPolicyEngine(address(policyEngine));
  }

  function test_reattachPolicyEngine_success() public {
    PolicyEngine policyEngine = _deployPolicyEngine(true, address(this));
    MockTokenFlexible token = new MockTokenFlexible(address(policyEngine));
    PolicyEngine newPolicyEngine = _deployPolicyEngine(true, address(this));

    vm.expectEmit();
    emit IPolicyEngine.TargetAttached(address(token));
    vm.expectEmit();
    emit IPolicyProtected.PolicyEngineAttached(address(newPolicyEngine));
    vm.expectEmit();
    emit IPolicyEngine.TargetDetached(address(token));

    token.attachPolicyEngine(address(newPolicyEngine));
  }

  function test_deattachPolicyEngine_success() public {
    PolicyEngine policyEngine = _deployPolicyEngine(true, address(this));
    MockTokenFlexible token = new MockTokenFlexible(address(policyEngine));

    vm.expectEmit();
    emit IPolicyEngine.TargetDetached(address(token));

    token.attachPolicyEngine(address(0));
  }

  function test_transferWithoutPolicyEngine_success() public {
    MockTokenFlexible token = new MockTokenFlexible(address(0));

    address recipient = makeAddr("recipient");
    token.transfer(recipient, 100);
    assert(token.balanceOf(recipient) == 100);
  }
}
