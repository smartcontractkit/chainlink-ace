// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {ICertifiedActionValidator} from "@chainlink/policy-management/interfaces/ICertifiedActionValidator.sol";
import {CertifiedActionValidatorPolicy} from "@chainlink/policy-management/policies/CertifiedActionValidatorPolicy.sol";
import {CertifiedActionDONValidatorPolicy} from
  "@chainlink/policy-management/policies/CertifiedActionDONValidatorPolicy.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {MockTokenExtractor} from "../helpers/MockTokenExtractor.sol";
import {BaseCertifiedActionTest} from "../helpers/BaseCertifiedActionTest.sol";

contract CertifiedActionDONValidatorPolicyTest is BaseCertifiedActionTest {
  PolicyEngine public policyEngine;
  MockTokenUpgradeable public token;
  CertifiedActionDONValidatorPolicy public policy;
  address public deployer;
  address public recipient;
  address public signer;
  uint256 public signerKey;
  address public mockKeystoneForwarder;

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");
    (signer, signerKey) = makeAddrAndKey("signer");
    mockKeystoneForwarder = makeAddr("mockKeystoneForwarder");

    vm.startPrank(deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    CertifiedActionDONValidatorPolicy policyImpl = new CertifiedActionDONValidatorPolicy();
    policy = CertifiedActionDONValidatorPolicy(
      _deployPolicy(address(policyImpl), address(policyEngine), deployer, abi.encode(mockKeystoneForwarder))
    );
    policy.allowIssuer(abi.encode(signer));
    MockTokenExtractor extractor = new MockTokenExtractor();
    bytes32[] memory parameterOutputFormat = new bytes32[](3);
    parameterOutputFormat[0] = extractor.PARAM_FROM();
    parameterOutputFormat[1] = extractor.PARAM_TO();
    parameterOutputFormat[2] = extractor.PARAM_AMOUNT();

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    policyEngine.setExtractor(MockTokenUpgradeable.transfer.selector, address(extractor));
    policyEngine.setExtractor(MockTokenUpgradeable.transferFrom.selector, address(extractor));

    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transfer.selector, address(policy), parameterOutputFormat
    );
    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transferFrom.selector, address(policy), parameterOutputFormat
    );
  }

  function test_DONPreActionPermit_validPermit_succeeds() public {
    vm.startPrank(mockKeystoneForwarder);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    policy.onReport(_ocrMetadata(), abi.encode(permit));
    uint256 usage = policy.getUsage(permit.permitId);

    vm.stopPrank();
    vm.startPrank(deployer);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(permit.permitId), usage + 1);
  }

  function test_InvalidDONPreActionPermit_validPermit_succeeds() public {
    address bogus = makeAddr("bogus");
    vm.startPrank(bogus);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    vm.expectRevert(
      abi.encodeWithSelector(CertifiedActionDONValidatorPolicy.UnauthorizedKeystoneForwarder.selector, bogus)
    );
    policy.onReport(_ocrMetadata(), abi.encode(permit));
  }

  function test_check_fromKeystoneForwarder_returnsTrue() public {
    vm.startPrank(mockKeystoneForwarder);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    policy.onReport(_ocrMetadata(), abi.encode(permit));

    vm.assertEq(policy.check(permit, abi.encode(signer)), true);
  }

  function test_check_invalidAddress_fromKeystoneForwarder_returnsFalse() public {
    vm.startPrank(mockKeystoneForwarder);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), MockTokenUpgradeable.transfer.selector, params);

    policy.onReport(_ocrMetadata(), abi.encode(permit));

    vm.assertEq(policy.check(permit, abi.encode(makeAddr("randomAddress"))), false);
  }

  function test_contextualPermit_reverts() public {
    vm.startPrank(deployer);

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

    bytes memory context = abi.encode(ICertifiedActionValidator.SignedPermit(permit, abi.encode(signer)));
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

  function _ocrMetadata() internal returns (bytes memory) {
    return abi.encodePacked(
      uint256(1234), // workflow_cid (32 bytes)
      "AAAAAAAAAA", // workflow_name (10 bytes)
      signer, // workflow_owner (20 bytes)
      "BB" // report_name (2 bytes)
    );
  }
}
