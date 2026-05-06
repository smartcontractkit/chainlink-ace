// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {ICertifiedActionValidator} from "@chainlink/policy-management/interfaces/ICertifiedActionValidator.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";
import {CertifiedActionValidatorPolicy} from "@chainlink/policy-management/policies/CertifiedActionValidatorPolicy.sol";
import {CertifiedActionERC20TransferValidatorPolicy} from
  "@chainlink/policy-management/policies/CertifiedActionERC20TransferValidatorPolicy.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {MockTokenExtractor} from "../helpers/MockTokenExtractor.sol";
import {BaseCertifiedActionTest} from "../helpers/BaseCertifiedActionTest.sol";

contract CertifiedActionERC20TransferValidatorPolicyTest is BaseCertifiedActionTest {
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

    CertifiedActionERC20TransferValidatorPolicy policyImpl = new CertifiedActionERC20TransferValidatorPolicy();
    policy = CertifiedActionERC20TransferValidatorPolicy(
      _deployPolicy(address(policyImpl), address(policyEngine), deployer, "")
    );
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

  function test_preActionPermit_validPermitExact_succeeds() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), IERC20.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);
    uint256 usage = policy.getUsage(permit.permitId);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
    vm.assertEq(policy.getUsage(permit.permitId), usage + 1);
  }

  function test_preActionPermit_validPermitUnderMax_succeeds() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), IERC20.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);
    uint256 usage = policy.getUsage(permit.permitId);

    vm.assertEq(token.balanceOf(recipient), 0);
    token.transfer(recipient, 99);
    vm.assertEq(token.balanceOf(recipient), 99);
    vm.assertEq(policy.getUsage(permit.permitId), usage + 1);
  }

  function test_preActionPermit_validPermitOverMaxAmount_reverts() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), IERC20.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    policy.present(permit, signature);

    _expectRejectedRevert(
      address(policy),
      "no valid pre-presented permit found",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 101)
    );
    token.transfer(recipient, 101);
  }

  function test_preActionPermit_invalidSelector_reverts() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), IERC20.approve.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    vm.expectRevert(abi.encodeWithSelector(Policy.InvalidParameters.selector, "unsupported selector"));
    policy.present(permit, signature);
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

  function test_check_validPermit_returnsTrue() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    // permit for transfer
    ICertifiedActionValidator.Permit memory permit1 =
      _generatePermit(deployer, address(token), IERC20.transfer.selector, params);

    bytes memory signature1 = _signPermit(policy, permit1, signerKey);

    policy.present(permit1, signature1);
    vm.assertEq(policy.check(permit1, signature1), true);

    // permit for transferFrom
    ICertifiedActionValidator.Permit memory permit2 =
      _generatePermit(deployer, address(token), IERC20.transferFrom.selector, params);

    bytes memory signature2 = _signPermit(policy, permit2, signerKey);

    policy.present(permit2, signature2);
    vm.assertEq(policy.check(permit2, signature2), true);
  }

  function test_check_invalidSelector_returnsFalse() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](3);
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);
    params[2] = abi.encode(uint256(100));

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), IERC20.approve.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    vm.assertEq(policy.check(permit, signature), false);
  }

  function test_check_invalidParameters_returnsFalse() public {
    vm.startPrank(deployer);

    bytes[] memory params = new bytes[](2); // missing amount parameter
    params[0] = abi.encode(deployer);
    params[1] = abi.encode(recipient);

    ICertifiedActionValidator.Permit memory permit =
      _generatePermit(deployer, address(token), IERC20.transfer.selector, params);

    bytes memory signature = _signPermit(policy, permit, signerKey);

    vm.assertEq(policy.check(permit, signature), false);
  }
}
