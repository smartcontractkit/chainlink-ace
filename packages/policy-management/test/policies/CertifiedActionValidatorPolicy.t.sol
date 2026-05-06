// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {ICertifiedActionValidator} from "@chainlink/policy-management/interfaces/ICertifiedActionValidator.sol";
import {CertifiedActionValidatorPolicy} from "@chainlink/policy-management/policies/CertifiedActionValidatorPolicy.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {MockTokenExtractor} from "../helpers/MockTokenExtractor.sol";
import {BaseCertifiedActionTest} from "../helpers/BaseCertifiedActionTest.sol";
import {MockCertifiedActionValidatorPolicyExtension} from "../helpers/MockCertifiedActionValidatorPolicyExtension.sol";

contract CertifiedActionValidatorPolicyTest is BaseCertifiedActionTest {
  PolicyEngine public policyEngine;
  MockTokenUpgradeable public token;
  CertifiedActionValidatorPolicy public policy;
  address public deployer;
  address public recipient;
  address public signer;
  uint256 public signerKey;

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");
    (signer, signerKey) = makeAddrAndKey("signer");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    CertifiedActionValidatorPolicy policyImpl = new CertifiedActionValidatorPolicy();
    policy = CertifiedActionValidatorPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, ""));
    policy.allowIssuer(abi.encode(signer));
    MockTokenExtractor extractor = new MockTokenExtractor();
    bytes32[] memory parameterOutputFormat = new bytes32[](3);
    parameterOutputFormat[0] = extractor.PARAM_FROM();
    parameterOutputFormat[1] = extractor.PARAM_TO();
    parameterOutputFormat[2] = extractor.PARAM_AMOUNT();

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    policyEngine.setExtractor(MockTokenUpgradeable.transfer.selector, address(extractor));
    policyEngine.setExtractor(MockTokenUpgradeable.transferWithContext.selector, address(extractor));
    policyEngine.setExtractor(MockTokenUpgradeable.transferFrom.selector, address(extractor));

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

  function test_preActionPermit_validPermitNoParameters_succeeds() public {
    vm.startPrank(deployer);

    policyEngine.addPolicy(address(token), MockTokenUpgradeable.pause.selector, address(policy), new bytes32[](0));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.pause.selector, new bytes[](0));

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);
    token.pause();
  }

  function test_preActionPermit_validPermit_succeeds() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);
    uint256 usage = policy.getUsage(permit.permitId);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(permit.permitId), usage + 1);
  }

  function test_preActionPermit_validPermitExceedsUsage_reverts() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);
    permit.maxUses = 2;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);
    uint256 usage = policy.getUsage(permit.permitId);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 200);
    vm.assertEq(policy.getUsage(permit.permitId), usage + 2);

    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_preActionPermit_validPermitExpired_reverts() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);
    permit.expiry = 2;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);
    uint256 usage = policy.getUsage(permit.permitId);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(permit.permitId), usage + 1);

    vm.warp(block.timestamp + 1 days + 1);
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_preActionPermit_incorrectPermitParams_reverts() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);

    _expectRejectedRevert(
      address(policy),
      "no valid permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 99)
    );
    token.transfer(recipient, 99);
  }

  function test_preActionPermit_prePresentedPermitHookCalled_succeeds() public {
    vm.startPrank(deployer);

    MockCertifiedActionValidatorPolicyExtension policyImpl = new MockCertifiedActionValidatorPolicyExtension();
    policy = CertifiedActionValidatorPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, ""));
    policy.allowIssuer(abi.encode(signer));
    policyEngine.addPolicy(address(token), MockTokenUpgradeable.pause.selector, address(policy), new bytes32[](0));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.pause.selector, new bytes[](0));

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);
    vm.expectCall(
      address(policy),
      abi.encodeWithSelector(MockCertifiedActionValidatorPolicyExtension.validatePrePresentedPermitHook.selector)
    );
    token.pause();
  }

  function test_preActionPermit_prePresentedPermitHookCalledWithContext_succeeds() public {
    vm.startPrank(deployer);

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    MockCertifiedActionValidatorPolicyExtension policyImpl = new MockCertifiedActionValidatorPolicyExtension();

    policy = CertifiedActionValidatorPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, ""));
    policy.allowIssuer(abi.encode(signer));

    MockTokenExtractor extractor = new MockTokenExtractor();
    bytes32[] memory parameterOutputFormat = new bytes32[](3);
    parameterOutputFormat[0] = extractor.PARAM_FROM();
    parameterOutputFormat[1] = extractor.PARAM_TO();
    parameterOutputFormat[2] = extractor.PARAM_AMOUNT();

    policyEngine.setExtractor(MockTokenUpgradeable.transferWithContext.selector, address(extractor));
    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transferWithContext.selector, address(policy), parameterOutputFormat
    );

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));
    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // pre-present the permit, so the _validatePrePresentedPermitHook is called even it goes through contextual path
    policy.present(permit, signature);
    vm.expectCall(
      address(policy),
      abi.encodeWithSelector(MockCertifiedActionValidatorPolicyExtension.validatePrePresentedPermitHook.selector)
    );
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
  }

  function test_preActionPermit_overrideContextPermits() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory contextPermit1 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    contextPermit1.maxUses = 3;
    ICertifiedActionValidator.Permit memory contextPermit2 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    contextPermit2.maxUses = 3;
    ICertifiedActionValidator.Permit memory prePresentedPermit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    prePresentedPermit.maxUses = 1;

    bytes memory contextPermit1Signature = _signPermit(policy, contextPermit1, signerKey);
    bytes memory contextPermit2Signature = _signPermit(policy, contextPermit2, signerKey);
    bytes memory prePresentedPermitSignature = _signPermit(policy, prePresentedPermit, signerKey);

    // transfer with context permits - succeeds
    token.transferWithContext(
      recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(contextPermit1, contextPermit1Signature))
    );
    token.transferWithContext(
      recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(contextPermit2, contextPermit2Signature))
    );
    vm.assertEq(token.balanceOf(recipient), 200);
    vm.assertEq(policy.getUsage(contextPermit1.permitId), 1);
    vm.assertEq(policy.getUsage(contextPermit2.permitId), 1);

    // present and use pre-presented permit - succeeds
    policy.present(prePresentedPermit, prePresentedPermitSignature);
    token.transferWithContext(
      recipient,
      100,
      abi.encode(ICertifiedActionValidator.SignedPermit(prePresentedPermit, prePresentedPermitSignature))
    );
    vm.assertEq(token.balanceOf(recipient), 300);
    vm.assertEq(policy.getUsage(prePresentedPermit.permitId), 1);

    // transfer with context permits - fails
    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(contextPermit1, contextPermit1Signature));
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);
  }

  function test_preActionPermit_overrideOldPermits() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit1 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);
    permit1.maxUses = 3;
    ICertifiedActionValidator.Permit memory permit2 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);
    permit2.maxUses = 3;
    ICertifiedActionValidator.Permit memory permit3 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);
    permit3.maxUses = 1;

    bytes memory signature1 = _signPermit(policy, permit1, signerKey);
    bytes memory signature2 = _signPermit(policy, permit2, signerKey);
    bytes memory signature3 = _signPermit(policy, permit3, signerKey);

    // present and use pre-presented permit 1 - succeeds
    policy.present(permit1, signature1);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(permit1.permitId), 1);

    // present and use pre-presented permit 2 - succeeds
    policy.present(permit2, signature2);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 200);
    vm.assertEq(policy.getUsage(permit2.permitId), 1);

    // present and use pre-presented permit 3 - succeeds
    policy.present(permit3, signature3);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 300);
    vm.assertEq(policy.getUsage(permit3.permitId), 1);

    // transfer again - fails (permit 3 is exhausted and old permits are ignored)
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_actionWithPermit_validPermit_succeeds() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(permit.permitId), 1);
  }

  function test_actionWithPermit_validPermitExceedsUsage_reverts() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    permit.maxUses = 2;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(token.balanceOf(recipient), 100);
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(token.balanceOf(recipient), 200);
    vm.assertEq(policy.getUsage(permit.permitId), 2);

    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));
    _expectRejectedRevert(
      address(policy),
      "invalid signed permit in context",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);
  }

  function test_actionWithPermit_validPermitExpired_reverts() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    permit.maxUses = 2;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(permit.permitId), 1);

    vm.warp(block.timestamp + 1 days + 1);
    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));
    _expectRejectedRevert(
      address(policy),
      "invalid signed permit in context",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);
  }

  function test_actionWithPermit_incorrectPermitParams_reverts() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));
    _expectRejectedRevert(
      address(policy),
      "invalid signed permit in context",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 99, context),
      context
    );
    token.transferWithContext(recipient, 99, context);
  }

  function test_actionWithPermit_prePresentedPermitHookCalledWithContext_succeeds() public {
    vm.startPrank(deployer);

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    MockCertifiedActionValidatorPolicyExtension policyImpl = new MockCertifiedActionValidatorPolicyExtension();

    policy = CertifiedActionValidatorPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, ""));
    policy.allowIssuer(abi.encode(signer));

    MockTokenExtractor extractor = new MockTokenExtractor();
    bytes32[] memory parameterOutputFormat = new bytes32[](3);
    parameterOutputFormat[0] = extractor.PARAM_FROM();
    parameterOutputFormat[1] = extractor.PARAM_TO();
    parameterOutputFormat[2] = extractor.PARAM_AMOUNT();

    policyEngine.setExtractor(MockTokenUpgradeable.transferWithContext.selector, address(extractor));
    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transferWithContext.selector, address(policy), parameterOutputFormat
    );

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));
    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    vm.expectCall(
      address(policy), abi.encodeWithSelector(MockCertifiedActionValidatorPolicyExtension.validatePermitHook.selector)
    );
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
  }

  function test_no_permit_reverts() public {
    vm.startPrank(deployer);

    _expectRejectedRevert(
      address(policy),
      "no valid permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test__security_representSamePermit_rejects() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Present and use permit once
    policy.present(permit, signature);

    // Try to re-present the same permit again - should fail
    vm.expectRevert(abi.encodeWithSelector(ICertifiedActionValidator.PermitAlreadyPresented.selector, permit.permitId));
    policy.present(permit, signature);
  }

  function test__security_representDifferentPermitButSamePermitId_rejects() public {
    vm.startPrank(deployer);

    // create 1st permit
    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit1 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    bytes memory signature1 = _signPermit(policy, permit1, signerKey);

    // Present and use permit once
    policy.present(permit1, signature1);

    // create 2nd permit with the same permit id
    ICertifiedActionValidator.Permit memory permit2 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferFrom.selector, params);
    permit2.permitId = permit1.permitId;

    bytes memory signature2 = _signPermit(policy, permit2, signerKey);

    // Try to re-present the same permit again - should fail
    vm.expectRevert(abi.encodeWithSelector(ICertifiedActionValidator.PermitAlreadyPresented.selector, permit2.permitId));
    policy.present(permit2, signature2);
  }

  function test__security_presentUsedPermit_usageCountIsNotReset() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    permit.maxUses = 1;

    bytes memory signature = _signPermit(policy, permit, signerKey);
    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));

    // use permit once with context
    token.transferWithContext(recipient, 100, context);
    vm.assertEq(policy.getUsage(permit.permitId), 1);

    // Present the permit
    policy.present(permit, signature);
    vm.assertEq(policy.getUsage(permit.permitId), 1);

    // use the permit again - should fail
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);
  }

  function test__security_presentRevokedPermit_rejects() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));
    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    bytes memory signature = _signPermit(policy, permit, signerKey);

    // revoke the permit
    policy.revoke(permit.permitId);

    // try to present the revoked permit - should fail
    vm.expectRevert(abi.encodeWithSelector(ICertifiedActionValidator.PermitAlreadyRevoked.selector, permit.permitId));
    policy.present(permit, signature);
  }

  /**
   * @notice Test that revoked pre-presented permits cannot be used
   * @dev Verifies the revoked flag prevents usage even though intentToPermit mapping remains
   */
  function test_security_revokedPrePresentedPermit_cannotBeUsed() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);
    permit.maxUses = 5;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Present and use permit once
    policy.present(permit, signature);
    token.transfer(recipient, 100);
    vm.assertEq(policy.getUsage(permit.permitId), 1);

    // Revoke the permit
    policy.revoke(permit.permitId);

    // Try to use the revoked permit - should fail
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);

    // Verify usage counter didn't increment
    vm.assertEq(policy.getUsage(permit.permitId), 1);
  }

  /**
   * @notice Test that revoked contextual permits cannot be used
   * @dev Verifies the revoked flag prevents contextual permit usage
   */
  function test_security_revokedContextualPermit_cannotBeUsed() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    permit.maxUses = 5;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Use contextual permit once
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(policy.getUsage(permit.permitId), 1);

    // Revoke the permit
    policy.revoke(permit.permitId);

    // Try to use the revoked contextual permit - should fail
    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));
    _expectRejectedRevert(
      address(policy),
      "invalid signed permit in context",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);

    // Verify usage counter didn't increment
    vm.assertEq(policy.getUsage(permit.permitId), 1);
  }

  /**
   * @notice Test that revoking a permit that was never used prevents any usage
   * @dev Verifies revocation works even before first use
   */
  function test_security_revokedPermit_beforeAnyUsage_cannotBeUsed() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Present permit
    policy.present(permit, signature);
    vm.assertEq(policy.getUsage(permit.permitId), 0);

    // Revoke immediately without any usage
    policy.revoke(permit.permitId);

    // Try to use - should fail
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);

    // Verify it was never used
    vm.assertEq(policy.getUsage(permit.permitId), 0);
  }

  /**
   * @notice Test that revoking a contextual-only permit (never pre-presented) prevents usage
   * @dev Verifies revocation works for permits that only exist from contextual usage
   */
  function test_security_revokedContextualOnlyPermit_cannotBeUsed() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    permit.maxUses = 5;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Use contextual permit once (never pre-presented)
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(policy.getUsage(permit.permitId), 1);

    // Revoke it
    policy.revoke(permit.permitId);

    // Try to use again - should fail
    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));
    _expectRejectedRevert(
      address(policy),
      "invalid signed permit in context",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);

    // Usage should still be 1
    vm.assertEq(policy.getUsage(permit.permitId), 1);
  }

  /**
   * @notice Test that contextual permits track usage correctly and don't bypass maxUses
   * @dev Ensures the fix doesn't break contextual permit usage tracking
   */
  function test_security_contextualPermit_respectsMaxUses() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    permit.maxUses = 3;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Use contextual permit 3 times
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(policy.getUsage(permit.permitId), 1);

    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(policy.getUsage(permit.permitId), 2);

    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(policy.getUsage(permit.permitId), 3);

    // 4th use should fail
    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));
    _expectRejectedRevert(
      address(policy),
      "invalid signed permit in context",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);
  }

  /**
   * @notice Test that revoking an issuer invalidates all pre-presented permits from that issuer (lazy revocation)
   * @dev Verifies lazy revocation: when issuer is revoked, their permits fail validation even if not explicitly revoked
   */
  function test_security_revokedIssuer_invalidatesPrePresentedPermits() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);
    permit.maxUses = 5;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Present and use permit once
    policy.present(permit, signature);
    token.transfer(recipient, 100);
    vm.assertEq(policy.getUsage(permit.permitId), 1);
    vm.assertEq(token.balanceOf(recipient), 100);

    // Revoke the issuer (not the permit)
    policy.disAllowIssuer(abi.encode(signer));

    // Try to use the permit again - should fail because issuer is revoked (lazy revocation)
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);

    // Verify usage counter didn't increment
    vm.assertEq(policy.getUsage(permit.permitId), 1);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  /**
   * @notice Test that revoking an issuer invalidates all contextual permits from that issuer (lazy revocation)
   * @dev Verifies lazy revocation: when issuer is revoked, their contextual permits fail validation
   */
  function test_security_revokedIssuer_invalidatesContextualPermits() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    permit.maxUses = 5;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Use contextual permit once
    token.transferWithContext(recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature)));
    vm.assertEq(policy.getUsage(permit.permitId), 1);
    vm.assertEq(token.balanceOf(recipient), 100);

    // Revoke the issuer (not the permit)
    policy.disAllowIssuer(abi.encode(signer));

    // Try to use the contextual permit again - should fail because issuer is revoked (lazy revocation)
    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));
    _expectRejectedRevert(
      address(policy),
      "invalid signed permit in context",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);

    // Verify usage counter didn't increment
    vm.assertEq(policy.getUsage(permit.permitId), 1);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  /**
   * @notice Test that revoking an issuer invalidates permits that were never used (lazy revocation)
   * @dev Verifies lazy revocation works even for permits that haven't been used yet
   */
  function test_security_revokedIssuer_invalidatesUnusedPrePresentedPermits() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Present permit but don't use it yet
    policy.present(permit, signature);
    vm.assertEq(policy.getUsage(permit.permitId), 0);

    // Revoke the issuer (not the permit)
    policy.disAllowIssuer(abi.encode(signer));

    // Try to use the permit - should fail because issuer is revoked (lazy revocation)
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);

    // Verify it was never used
    vm.assertEq(policy.getUsage(permit.permitId), 0);
    vm.assertEq(token.balanceOf(recipient), 0);
  }

  /**
   * @notice Test that re-adding a revoked issuer restores permits (lazy revocation is dynamic)
   * @dev With lazy revocation, issuer status is checked dynamically, so re-adding the issuer
   *      should restore permit validity
   */
  function test_security_revokedIssuer_reAddingIssuer_restoresPermits() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);
    permit.maxUses = 5;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // Present and use permit once
    policy.present(permit, signature);
    token.transfer(recipient, 100);
    vm.assertEq(policy.getUsage(permit.permitId), 1);
    vm.assertEq(token.balanceOf(recipient), 100);

    // Revoke the issuer
    policy.disAllowIssuer(abi.encode(signer));

    // Try to use - should fail (lazy revocation)
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100); // Balance unchanged

    // Re-add the issuer
    policy.allowIssuer(abi.encode(signer));

    // Permit should work again because lazy revocation checks issuer status dynamically
    token.transfer(recipient, 100);
    vm.assertEq(policy.getUsage(permit.permitId), 2);
    vm.assertEq(token.balanceOf(recipient), 200);
  }

  function test_security_permitUsedAsBothPrePresentedAndContextual_respectsMaxUses() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    permit.maxUses = 2;

    bytes memory signature = _signPermit(policy, permit, signerKey);

    // transfer with context - 1st use
    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, signature));
    token.transferWithContext(recipient, 100, context);
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(permit.permitId), 1);

    // transfer with pre-presented permit - 2nd use
    policy.present(permit, signature);
    token.transferWithContext(recipient, 100, context);
    vm.assertEq(token.balanceOf(recipient), 200);
    vm.assertEq(policy.getUsage(permit.permitId), 2);

    // transfer with pre-presented permit - already exhausted
    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transferWithContext.selector,
      deployer,
      abi.encode(recipient, 100, context),
      context
    );
    token.transferWithContext(recipient, 100, context);
  }

  function test_security_prioritizePrePresentedPermit_incrementsUsageCorrectly() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory prePresentedPermit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    prePresentedPermit.maxUses = 2;

    ICertifiedActionValidator.Permit memory contextPermit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transferWithContext.selector, params);
    contextPermit.maxUses = 2;

    bytes memory prePresentedPermitSignature = _signPermit(policy, prePresentedPermit, signerKey);
    bytes memory contextPermitSignature = _signPermit(policy, contextPermit, signerKey);

    // present pre-presented permit
    policy.present(prePresentedPermit, prePresentedPermitSignature);

    // submit context permit - should ignore context permit and use pre-presented permit
    token.transferWithContext(
      recipient, 100, abi.encode(ICertifiedActionValidator.SignedPermit(contextPermit, contextPermitSignature))
    );
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(prePresentedPermit.permitId), 1);
  }

  function test_check_validSignature_returnsTrue() public {
    vm.startPrank(deployer);

    policyEngine.addPolicy(address(token), MockTokenUpgradeable.pause.selector, address(policy), new bytes32[](0));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.pause.selector, new bytes[](0));

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);
    vm.assertEq(policy.check(permit, signature), true);
  }

  function test_check_invalidSignature_returnsFalse() public {
    vm.startPrank(deployer);

    policyEngine.addPolicy(address(token), MockTokenUpgradeable.pause.selector, address(policy), new bytes32[](0));

    ICertifiedActionValidator.Permit memory permit1 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.pause.selector, new bytes[](0));

    ICertifiedActionValidator.Permit memory permit2 =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.unpause.selector, new bytes[](0));

    bytes memory signature2 = _signPermit(policy, permit2, signerKey);

    vm.assertEq(policy.check(permit1, signature2), false);
  }
}
