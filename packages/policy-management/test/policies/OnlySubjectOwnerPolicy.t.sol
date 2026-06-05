// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "../helpers/PolicyProtectedNonOwnable.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {OnlySubjectOwnerPolicy} from "../../src/policies/OnlySubjectOwnerPolicy.sol";

contract OnlySubjectOwnerPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockTokenUpgradeable public token;
  OnlySubjectOwnerPolicy public policy;
  address public deployer;
  address public tokenOwner;
  address public account;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    tokenOwner = makeAddr("tokenOwner");
    account = makeAddr("account");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    policyEngine = PolicyEngine(_deployPolicyEngine(true, deployer));

    OnlySubjectOwnerPolicy policyImpl = new OnlySubjectOwnerPolicy();
    policy = OnlySubjectOwnerPolicy(_deployPolicy(address(policyImpl), address(policyEngine), deployer, new bytes(0)));

    // Deploy token and transfer ownership to tokenOwner
    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));
    token.transferOwnership(tokenOwner);

    policyEngine.addPolicy(address(token), MockTokenUpgradeable.transfer.selector, address(policy), new bytes32[](0));
  }

  function test_transfer_subjectOwner_success() public {
    vm.startPrank(tokenOwner, tokenOwner);
    token.transfer(recipient, 100);
    assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_notSubjectOwner_reverts() public {
    vm.startPrank(account, account);

    _expectRejectedRevert(
      address(policy),
      "caller is not the subject owner",
      MockTokenUpgradeable.transfer.selector,
      account,
      abi.encode(recipient, 100)
    );

    token.transfer(recipient, 100);
  }

  function test_transfer_deployer_reverts() public {
    vm.startPrank(deployer, deployer);

    _expectRejectedRevert(
      address(policy),
      "caller is not the subject owner",
      MockTokenUpgradeable.transfer.selector,
      deployer,
      abi.encode(recipient, 100)
    );

    token.transfer(recipient, 100);
  }

  function test_nonOwnableSubject_reverts() public {
    vm.startPrank(deployer, deployer);

    PolicyProtectedNonOwnable nonOwnable = new PolicyProtectedNonOwnable(address(policyEngine));
    policyEngine.addPolicy(
      address(nonOwnable), PolicyProtectedNonOwnable.protectedFunction.selector, address(policy), new bytes32[](0)
    );

    vm.startPrank(tokenOwner, tokenOwner);

    _expectRejectedRevert(
      address(policy),
      "subject contract is not Ownable",
      PolicyProtectedNonOwnable.protectedFunction.selector,
      tokenOwner,
      ""
    );

    nonOwnable.protectedFunction();
  }
}
