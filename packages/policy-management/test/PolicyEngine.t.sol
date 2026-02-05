// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IPolicyEngine} from "../src/interfaces/IPolicyEngine.sol";
import {IExtractor} from "../src/interfaces/IExtractor.sol";
import {PolicyEngine} from "../src/core/PolicyEngine.sol";
import {Policy} from "../src/core/Policy.sol";
import {PolicyAlwaysAllowed, PolicyAlwaysAllowedWithPostRunError} from "./helpers/PolicyAlwaysAllowed.sol";
import {PolicyAlwaysRejected} from "./helpers/PolicyAlwaysRejected.sol";
import {PolicyFailingRun} from "./helpers/PolicyFailingRun.sol";
import {DummyExtractor} from "./helpers/DummyExtractor.sol";
import {MockTokenExtractor} from "./helpers/MockTokenExtractor.sol";
import {MockToken} from "./helpers/MockToken.sol";
import {ExpectedParameterPolicy} from "./helpers/ExpectedParameterPolicy.sol";
import {CustomMapper} from "./helpers/CustomMapper.sol";
import {BaseProxyTest} from "./helpers/BaseProxyTest.sol";
import {PolicyAlwaysContinue} from "./helpers/PolicyAlwaysContinue.sol";

contract PolicyEngineTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  IExtractor public extractor;
  bytes4 public constant selector = bytes4(keccak256("someSelector()"));
  IPolicyEngine.Payload public testPayload;
  address target;

  PolicyAlwaysAllowed public policyAlwaysAllowedImpl;
  PolicyAlwaysRejected public policyAlwaysRejectedImpl;
  PolicyAlwaysContinue public policyAlwaysContinueImpl;
  PolicyFailingRun public policyFailingRunImpl;
  PolicyAlwaysAllowedWithPostRunError public policyAllowedWithPostRunErrorImpl;
  ExpectedParameterPolicy public expectedParameterPolicyImpl;

  function setUp() public {
    policyEngine = _deployPolicyEngine(false, address(this));

    target = makeAddr("target");

    extractor = new DummyExtractor();

    policyAlwaysAllowedImpl = new PolicyAlwaysAllowed();
    policyAlwaysRejectedImpl = new PolicyAlwaysRejected();
    policyAlwaysContinueImpl = new PolicyAlwaysContinue();
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

  function test_setPolicyMapper_storesMapperAndEmitsEvent() public {
    PolicyAlwaysAllowed policy = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );
    CustomMapper mapper = new CustomMapper();

    vm.expectEmit();
    emit IPolicyEngine.PolicyMapperSet(address(policy), address(mapper));

    policyEngine.setPolicyMapper(address(policy), address(mapper));

    address storedMapper = policyEngine.getPolicyMapper(address(policy));

    assertEq(storedMapper, address(mapper), "Mapper should be set");
  }

  function test_addPolicy_storesPolicyAndEmitsEvent() public {
    PolicyAlwaysAllowed policyAllowed = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );
    PolicyAlwaysRejected policyRejected = PolicyAlwaysRejected(
      _deployPolicy(address(policyAlwaysRejectedImpl), address(policyEngine), address(this), new bytes(0))
    );

    bytes32[] memory emptyParams = new bytes32[](0);
    vm.expectEmit();
    emit IPolicyEngine.PolicyAdded(target, selector, address(policyAllowed), 0, emptyParams);
    policyEngine.addPolicy(target, selector, address(policyAllowed), emptyParams);

    address[] memory expectedPolicies = new address[](2);
    expectedPolicies[0] = address(policyRejected);
    expectedPolicies[1] = address(policyAllowed);
    vm.expectEmit();
    emit IPolicyEngine.PolicyAddedAt(target, selector, address(policyRejected), 0, emptyParams, expectedPolicies);
    policyEngine.addPolicyAt(target, selector, address(policyRejected), emptyParams, 0);

    address[] memory policies = policyEngine.getPolicies(target, selector);

    assertEq(policies.length, 2, "Two policies should be added");
    assertEq(policies[0], address(policyRejected));
    assertEq(policies[1], address(policyAllowed));
  }

  function test_addPolicy_thatIsDuplicate_thenReverts() public {
    PolicyAlwaysAllowed policy = PolicyAlwaysAllowed(
      _deployPolicy(address(policyAlwaysAllowedImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));

    vm.expectRevert(abi.encodeWithSelector(Policy.InvalidParameters.selector, "Policy already added"));
    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));
  }

  function test_run_whenNoPoliciesAddedThenDefaultPolicyIsUsed() public {
    _expectRejectedRevert(address(0), "no policy allowed the action and default is reject", testPayload);
    vm.startPrank(target);
    policyEngine.run(testPayload);
  }

  function test_run_whenNoPoliciesDefaultAllowedEmitsCompleteEvent() public {
    policyEngine.setDefaultPolicyAllow(true);

    vm.startPrank(target);

    IPolicyEngine.Parameter[] memory emptyParameters = new IPolicyEngine.Parameter[](0);
    vm.expectEmit();
    emit IPolicyEngine.PolicyRunComplete(
      testPayload.sender, target, testPayload.selector, emptyParameters, testPayload.context
    );
    policyEngine.run(testPayload);
  }

  function test_run_whenExtractorSetDefaultAllowedEmitsCompleteEvent() public {
    MockTokenExtractor mockExtractor = new MockTokenExtractor();

    address recipient = makeAddr("recipient");
    uint256 amount = 100;
    bytes4 transferSelector = MockToken.transfer.selector;
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: transferSelector,
      sender: target,
      data: abi.encode(recipient, amount),
      context: new bytes(0)
    });
    policyEngine.setExtractor(transferSelector, address(mockExtractor));
    policyEngine.setDefaultPolicyAllow(true);

    vm.startPrank(target);

    IPolicyEngine.Parameter[] memory expectedParameters = new IPolicyEngine.Parameter[](3);
    expectedParameters[0] = IPolicyEngine.Parameter(mockExtractor.PARAM_FROM(), abi.encode(target));
    expectedParameters[1] = IPolicyEngine.Parameter(mockExtractor.PARAM_TO(), abi.encode(recipient));
    expectedParameters[2] = IPolicyEngine.Parameter(mockExtractor.PARAM_AMOUNT(), abi.encode(amount));

    vm.expectEmit();
    emit IPolicyEngine.PolicyRunComplete(payload.sender, target, payload.selector, expectedParameters, payload.context);
    policyEngine.run(payload);
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

    IPolicyEngine.Parameter[] memory emptyParameters = new IPolicyEngine.Parameter[](0);
    vm.expectEmit();
    emit IPolicyEngine.PolicyRunComplete(
      testPayload.sender, target, testPayload.selector, emptyParameters, testPayload.context
    );
    policyEngine.run(testPayload);
  }

  function test_run_whenSingleContinuedPolicyAddedThenPolicyIsUsed() public {
    policyEngine.setDefaultPolicyAllow(true);

    PolicyAlwaysContinue policy =
      PolicyAlwaysContinue(_deployPolicy(address(policyAlwaysContinueImpl), address(policyEngine), address(this), ""));

    policyEngine.addPolicy(target, selector, address(policy), new bytes32[](0));

    vm.startPrank(target);

    IPolicyEngine.Parameter[] memory emptyParameters = new IPolicyEngine.Parameter[](0);
    vm.expectEmit();
    emit IPolicyEngine.PolicyRunComplete(
      testPayload.sender, target, testPayload.selector, emptyParameters, testPayload.context
    );
    policyEngine.run(testPayload);
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
    _expectRejectedRevert(address(policyRejected), "test policy always rejects", testPayload);

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

    bytes memory error = abi.encodeWithSignature("Error(string)", "Run error");
    _expectRunError(address(policyFailingRun), error, testPayload);
    policyEngine.run(testPayload);
  }

  function test_run_whenAllowingPolicyRevertsOnPostRunAndActionIndicatesItShouldRevertThenTransactionReverts() public {
    PolicyAlwaysAllowedWithPostRunError policyAllowedWithPostRunError = PolicyAlwaysAllowedWithPostRunError(
      _deployPolicy(address(policyAllowedWithPostRunErrorImpl), address(policyEngine), address(this), abi.encode(1))
    );

    policyEngine.addPolicy(target, selector, address(policyAllowedWithPostRunError), new bytes32[](0));

    vm.startPrank(target);

    bytes memory error = abi.encodeWithSignature("Error(string)", "Post run error");
    _expectPostRunError(address(policyAllowedWithPostRunError), error, testPayload);
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
    _expectRejectedRevert(address(policyRejected), "test policy always rejects", testPayload);
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
    IPolicyEngine.Payload memory secondPayload =
      IPolicyEngine.Payload({selector: selector, sender: secondTarget, data: new bytes(0), context: new bytes(0)});
    _expectRejectedRevert(address(policyRejected), "test policy always rejects", secondPayload);
    policyEngine.run(secondPayload);
  }

  function test_run_targetDefaultPolicyTakesPrecedenceOverGlobalDefaultPolicy() public {
    policyEngine.setTargetDefaultPolicyAllow(target, true); // true = allow by default

    bool success;

    vm.startPrank(target);
    try policyEngine.run(testPayload) {
      success = true;
    } catch {
      success = false;
    }

    assertTrue(success, "Policy should allow execution");
  }

  function test_setPolicyConfiguration_byPolicyAdmin() public {
    address policyAdmin = makeAddr("policyAdmin");

    policyEngine.grantRole(policyEngine.POLICY_CONFIG_ADMIN_ROLE(), policyAdmin);

    PolicyAlwaysRejected policyRejected = PolicyAlwaysRejected(
      _deployPolicy(address(policyAlwaysRejectedImpl), address(policyEngine), address(policyEngine), new bytes(0))
    );

    vm.startPrank(policyAdmin);

    vm.expectEmit();
    emit PolicyAlwaysRejected.ConfigFuncExecuted();
    vm.expectEmit();
    emit IPolicyEngine.PolicyConfigured(address(policyRejected), 0, PolicyAlwaysRejected.configFunc.selector, "");
    policyEngine.setPolicyConfiguration(address(policyRejected), 0, PolicyAlwaysRejected.configFunc.selector, "");

    vm.expectEmit();
    emit PolicyAlwaysRejected.ConfigFuncExecuted();
    vm.expectEmit();
    emit IPolicyEngine.PolicyConfigured(address(policyRejected), 1, PolicyAlwaysRejected.configFunc.selector, "");
    policyEngine.setPolicyConfiguration(address(policyRejected), 1, PolicyAlwaysRejected.configFunc.selector, "");
  }

  function test_setPolicyConfiguration_byNonPolicyAdmin_reverts() public {
    address nonPolicyAdmin = makeAddr("nonPolicyAdmin");

    PolicyAlwaysRejected policyRejected = PolicyAlwaysRejected(
      _deployPolicy(address(policyAlwaysRejectedImpl), address(policyEngine), address(policyEngine), new bytes(0))
    );

    vm.startPrank(nonPolicyAdmin);

    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector,
        nonPolicyAdmin,
        policyEngine.POLICY_CONFIG_ADMIN_ROLE()
      )
    );
    policyEngine.setPolicyConfiguration(address(policyRejected), 0, PolicyAlwaysRejected.configFunc.selector, "");
  }
}
