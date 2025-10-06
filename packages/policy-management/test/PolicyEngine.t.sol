// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "../src/interfaces/IPolicyEngine.sol";
import {IExtractor} from "../src/interfaces/IExtractor.sol";
import {PolicyEngine} from "../src/core/PolicyEngine.sol";
import {PolicyAlwaysAllowed, PolicyAlwaysAllowedWithPostRunError} from "./helpers/PolicyAlwaysAllowed.sol";
import {PolicyAlwaysRejected} from "./helpers/PolicyAlwaysRejected.sol";
import {PolicyFailingRun} from "./helpers/PolicyFailingRun.sol";
import {DummyExtractor} from "./helpers/DummyExtractor.sol";
import {ExpectedParameterPolicy} from "./helpers/ExpectedParameterPolicy.sol";
import {CustomMapper} from "./helpers/CustomMapper.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";

contract PolicyEngineTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  IExtractor public extractor;
  bytes4 public constant selector = bytes4(keccak256("someSelector()"));
  IPolicyEngine.Payload public testPayload;
  address target;

  PolicyAlwaysAllowed public policyAlwaysAllowedImpl;
  PolicyAlwaysRejected public policyAlwaysRejectedImpl;
  PolicyFailingRun public policyFailingRunImpl;
  PolicyAlwaysAllowedWithPostRunError public policyAllowedWithPostRunErrorImpl;
  ExpectedParameterPolicy public expectedParameterPolicyImpl;

  function setUp() public {
    policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Rejected, address(this));

    target = makeAddr("target");

    extractor = new DummyExtractor();

    policyAlwaysAllowedImpl = new PolicyAlwaysAllowed();
    policyAlwaysRejectedImpl = new PolicyAlwaysRejected();
    policyFailingRunImpl = new PolicyFailingRun();
    policyAllowedWithPostRunErrorImpl = new PolicyAlwaysAllowedWithPostRunError();
    expectedParameterPolicyImpl = new ExpectedParameterPolicy();

    testPayload = IPolicyEngine.Payload({selector: selector, sender: target, data: new bytes(0), context: new bytes(0)});
  }

  function test_setExtractor_storesExtractorAndEmitsEvent() public {
    vm.expectEmit();
    emit IPolicyEngine.ExtractorSet(selector, address(extractor));

    policyEngine.setExtractor(selector, address(extractor));

    address storedExtractor = policyEngine.getExtractor(selector);

    assertEq(storedExtractor, address(extractor), "Extractor should be set");
  }

  function test_addPolicy_storesPolicyAndEmitsEvent() public {
    PolicyAlwaysAllowed policy = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    vm.expectEmit();
    emit IPolicyEngine.PolicyAdded(target, selector, address(policy));

    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));

    address[] memory policies = policyEngine.getPolicies(target, selector);

    assertEq(policies.length, 1, "Policy should be added");
    assertEq(policies[0], address(policy), "Policy address should match");
  }

  function test_addPolicy_thatIsDuplicate_thenReverts() public {
    PolicyAlwaysAllowed policy = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));

    vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.InvalidConfiguration.selector, "Policy already added"));
    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));
  }

  function test_run_whenNoPoliciesAddedThenDefaultPolicyIsUsed() public {
    bytes memory expectedRevert = abi.encodeWithSignature("PolicyRunRejected(bytes4,address)", selector, address(0));

    vm.expectRevert(expectedRevert);
    vm.startPrank(target);
    policyEngine.run(testPayload);
  }

  function test_setDefaultPolicy_doesNotAllowContinueValueAndReverts() public {
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.InvalidConfiguration.selector, "Default policy must be either Allowed or Rejected"
      )
    );

    policyEngine.setDefaultPolicyResult(IPolicyEngine.PolicyResult.Continue);
  }

  function test_run_whenSingleAllowedPolicyAddedThenPolicyIsUsed() public {
    PolicyAlwaysAllowed policy = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));

    bool success;

    vm.expectEmit();
    emit PolicyAlwaysAllowed.PolicyAllowedExecuted(1);

    vm.startPrank(target);
    try policyEngine.run(testPayload) {
      success = true;
    } catch {
      success = false;
    }

    assertTrue(success, "Policy should allow execution");
  }

  function test_run_whenRejectingPolicyPrecedesAllowingPolicyThenRevertsOccurs() public {
    PolicyAlwaysRejected policyRejected = PolicyAlwaysRejected(
      _deployPolicy(address(policyAlwaysRejectedImpl), address(policyEngine), address(this), new bytes(0))
    );
    PolicyAlwaysAllowed policyAllowed = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policyRejected), new bytes32[](0));
    policyEngine.addPolicy(target, selector, address(policyAllowed), new bytes32[](0));

    vm.startPrank(target);
    bytes memory expectedRevert = abi.encodeWithSignature("PolicyRunRejected(bytes4,address)", selector, policyRejected);

    vm.expectRevert(expectedRevert);

    policyEngine.run(testPayload);
  }

  function test_run_whenAllowingPolicyPrecedesRejectingPolicyThenTransactionGoesThrough() public {
    PolicyAlwaysRejected policyRejected = PolicyAlwaysRejected(
      _deployPolicy(address(policyAlwaysRejectedImpl), address(policyEngine), address(this), new bytes(0))
    );
    PolicyAlwaysAllowed policyAllowed = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policyAllowed), new bytes32[](0));
    policyEngine.addPolicy(target, selector, address(policyRejected), new bytes32[](0));

    bool success;

    vm.expectEmit();
    emit PolicyAlwaysAllowed.PolicyAllowedExecuted(1);
    vm.startPrank(target);

    try policyEngine.run(testPayload) {
      success = true;
    } catch {
      success = false;
    }

    assertTrue(success, "Policy should allow execution");
  }

  function test_run_whenPolicyRevertsTransactionReverts() public {
    PolicyFailingRun policyFailingRun =
      PolicyFailingRun(_deployPolicy(address(policyFailingRunImpl), address(policyEngine), address(this), new bytes(0)));
    PolicyAlwaysAllowed policyAllowed = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policyFailingRun), new bytes32[](0));
    policyEngine.addPolicy(target, selector, address(policyAllowed), new bytes32[](0));

    vm.startPrank(target);

    vm.expectPartialRevert(IPolicyEngine.PolicyRunError.selector);
    policyEngine.run(testPayload);
  }

  function test_run_whenAllowingPolicyRevertsOnPostRunAndActionIndicatesItShouldRevertThenTransactionReverts() public {
    PolicyAlwaysAllowedWithPostRunError policyAllowedWithPostRunError = PolicyAlwaysAllowedWithPostRunError(
      _deployPolicy(address(policyAllowedWithPostRunErrorImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policyAllowedWithPostRunError), new bytes32[](0));

    vm.startPrank(target);

    vm.expectPartialRevert(IPolicyEngine.PolicyPostRunError.selector);
    policyEngine.run(testPayload);
  }

  function test_run_whenAddingAllowingPolicyAtPrecedingIndexThenTransactionDoesNotRevert() public {
    PolicyAlwaysRejected policyRejected = PolicyAlwaysRejected(
      _deployPolicy(address(policyAlwaysRejectedImpl), address(policyEngine), address(this), new bytes(0))
    );
    PolicyAlwaysAllowed policyAllowed = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policyRejected), new bytes32[](0));
    policyEngine.addPolicyAt(target, selector, address(policyAllowed), new bytes32[](0), 0);

    bool success;

    vm.expectEmit();
    emit PolicyAlwaysAllowed.PolicyAllowedExecuted(1);
    vm.startPrank(target);
    try policyEngine.run(testPayload) {
      success = true;
    } catch {
      success = false;
    }

    assertTrue(success, "Policy should allow execution");
  }

  function test_removePolicy_whenRemovingPolicyAtIntermediateIndexOrderIsPreserved() public {
    PolicyAlwaysAllowed policyAllowed1 = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );
    PolicyAlwaysAllowed policyAllowed2 = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(2))
    );
    PolicyAlwaysAllowed policyAllowed3 = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(3))
    );
    PolicyAlwaysAllowed policyAllowed4 = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(4))
    );

    policyEngine.addPolicy(target, selector, address(policyAllowed1), new bytes32[](0));
    policyEngine.addPolicy(target, selector, address(policyAllowed2), new bytes32[](0));
    policyEngine.addPolicy(target, selector, address(policyAllowed3), new bytes32[](0));
    policyEngine.addPolicy(target, selector, address(policyAllowed4), new bytes32[](0));

    vm.expectEmit();
    emit IPolicyEngine.PolicyRemoved(target, selector, address(policyAllowed2));

    policyEngine.removePolicy(target, selector, address(policyAllowed2));

    address[] memory policies = policyEngine.getPolicies(target, selector);

    assertEq(policies.length, 3, "Policy should be removed");
    assertEq(policies[0], address(policyAllowed1), "Policy address should match");
    assertEq(policies[1], address(policyAllowed3), "Policy address should match");
    assertEq(policies[2], address(policyAllowed4), "Policy address should match");
  }

  function test_removePolicy_then_run_omitsRemovedPolicy() public {
    PolicyAlwaysRejected policyRejected = PolicyAlwaysRejected(
      _deployPolicy(address(policyAlwaysRejectedImpl), address(policyEngine), address(this), new bytes(0))
    );
    PolicyAlwaysAllowed policyAllowed = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policyAllowed), new bytes32[](0));
    policyEngine.addPolicy(target, selector, address(policyRejected), new bytes32[](0));

    bool success;

    vm.expectEmit();
    emit PolicyAlwaysAllowed.PolicyAllowedExecuted(1);

    vm.startPrank(target);
    try policyEngine.run(testPayload) {
      success = true;
    } catch {
      success = false;
    }

    assertTrue(success, "Policy should allow execution");
    vm.stopPrank();

    vm.startPrank(address(this));
    policyEngine.removePolicy(target, selector, address(policyAllowed));
    vm.stopPrank();

    vm.startPrank(target);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    policyEngine.run(testPayload);
  }

  function test_run_CustomMapper() public {
    bytes[] memory parameters = new bytes[](1);
    parameters[0] = abi.encode("test_run_CustomMapper");

    CustomMapper mapper = new CustomMapper();
    mapper.setMappedParameters(parameters);

    ExpectedParameterPolicy policy = ExpectedParameterPolicy(
      _deployPolicy(address(expectedParameterPolicyImpl), address(policyEngine), address(this), abi.encode(parameters))
    );

    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));
    policyEngine.setPolicyMapper(address(policy), address(mapper));

    vm.startPrank(target);
    policyEngine.run(testPayload);
  }

  function test_run_forDifferentTargets() public {
    address secondTarget = makeAddr("secondTarget");

    PolicyAlwaysAllowed policy = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));

    PolicyAlwaysRejected policyRejected = PolicyAlwaysRejected(
      _deployPolicy(address(policyAlwaysRejectedImpl), address(policyEngine), address(this), new bytes(0))
    );

    policyEngine.addPolicy(secondTarget, selector, address(policyRejected), new bytes32[](0));

    bool success;
    vm.startPrank(target);
    try policyEngine.run(testPayload) {
      success = true;
    } catch {
      success = false;
    }

    assertTrue(success, "Policy should allow execution");
    vm.stopPrank();

    vm.startPrank(secondTarget);
    vm.expectPartialRevert(IPolicyEngine.PolicyRunRejected.selector);
    policyEngine.run(
      IPolicyEngine.Payload({selector: selector, sender: secondTarget, data: new bytes(0), context: new bytes(0)})
    );
  }

  function test_run_targetDefaultPolicyTakesPrecedenceOverGlobalDefaultPolicy() public {
    policyEngine.setTargetDefaultPolicyResult(target, IPolicyEngine.PolicyResult.Allowed);

    bool success;

    vm.startPrank(target);
    try policyEngine.run(testPayload) {
      success = true;
    } catch {
      success = false;
    }

    assertTrue(success, "Policy should allow execution");
  }
}
