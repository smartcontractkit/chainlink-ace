// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {RejectPolicy} from "@chainlink/policy-management/policies/RejectPolicy.sol";
import {MockToken} from "../helpers/MockToken.sol";
import {ERC3643MintBurnExtractor} from "@chainlink/policy-management/extractors/ERC3643MintBurnExtractor.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract RejectPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockToken public token;
  RejectPolicy public rejectPolicy;
  address public deployer;
  address public account;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    account = makeAddr("account");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    RejectPolicy rejectPolicyImpl = new RejectPolicy();
    rejectPolicy = RejectPolicy(_deployPolicy(address(rejectPolicyImpl), address(policyEngine), deployer, ""));

    token = MockToken(_deployMockToken(address(policyEngine)));

    // set up the rejectPolicy to check the recipient and origin address of token transfers
    ERC20TransferExtractor transferExtractor = new ERC20TransferExtractor();
    bytes32[] memory policyParameters = new bytes32[](2);
    policyParameters[0] = transferExtractor.PARAM_TO();
    policyParameters[1] = transferExtractor.PARAM_FROM();
    policyEngine.setExtractor(MockToken.transfer.selector, address(transferExtractor));
    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(rejectPolicy), policyParameters);
    // set up the rejectPolicy to check the mint account (single account)
    ERC3643MintBurnExtractor mintBurnExtractor = new ERC3643MintBurnExtractor();
    bytes32[] memory mintPolicyParams = new bytes32[](1);
    mintPolicyParams[0] = mintBurnExtractor.PARAM_ACCOUNT();
    policyEngine.setExtractor(MockToken.mint.selector, address(mintBurnExtractor));
    policyEngine.addPolicy(address(token), MockToken.mint.selector, address(rejectPolicy), mintPolicyParams);
  }

  function test_rejectAddress_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the reject list
    rejectPolicy.rejectAddress(account);
    vm.assertEq(rejectPolicy.addressRejected(account), true);
  }

  function test_addressRejected_alreadyInList_fails() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the reject list (setup and sanity check)
    rejectPolicy.rejectAddress(account);
    vm.assertEq(rejectPolicy.addressRejected(account), true);

    // add the sender to the reject list again (reverts)
    vm.expectRevert("Account already in reject list");
    rejectPolicy.rejectAddress(account);
  }

  function test_unrejectAddress_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the sender to the reject list (setup and sanity check)
    rejectPolicy.rejectAddress(account);
    vm.assertEq(rejectPolicy.addressRejected(account), true);

    // remove the sender from the reject list
    rejectPolicy.unrejectAddress(account);
    vm.assertEq(rejectPolicy.addressRejected(account), false);
  }

  function test_unrejectAddress_notInList_fails() public {
    vm.startPrank(deployer, deployer);

    // remove the sender from the reject list (reverts)
    vm.expectRevert("Account not in reject list");
    rejectPolicy.unrejectAddress(account);
  }

  function test_transfer_notInList_succeeds() public {
    vm.startPrank(account, account);

    // transfer from sender to recipient
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_inList_reverts() public {
    vm.startPrank(deployer, deployer);

    // add the recipient to the reject list
    rejectPolicy.rejectAddress(recipient);
    vm.assertEq(rejectPolicy.addressRejected(recipient), true);

    vm.startPrank(account, account);

    // transfer from sender to recipient (reverts)
    vm.expectRevert(
      _encodeRejectedRevert(MockToken.transfer.selector, address(rejectPolicy), "address is on reject list")
    );
    token.transfer(recipient, 100);
  }

  function test_transfer_allInList_reverts() public {
    vm.startPrank(deployer, deployer);

    // add the account and recipient to the reject list
    rejectPolicy.rejectAddress(recipient);
    vm.assertEq(rejectPolicy.addressRejected(recipient), true);
    rejectPolicy.rejectAddress(account);
    vm.assertEq(rejectPolicy.addressRejected(account), true);

    vm.startPrank(account, account);

    // transfer from sender to recipient (reverts)
    vm.expectRevert(
      _encodeRejectedRevert(MockToken.transfer.selector, address(rejectPolicy), "address is on reject list")
    );
    token.transfer(recipient, 100);
  }

  function test_transfer_removedFromList_succeeds() public {
    // add the address to the reject list (setup)
    vm.startPrank(deployer, deployer);
    rejectPolicy.rejectAddress(recipient);

    // transfer from address to recipient (sanity check)
    vm.startPrank(account, account);
    vm.expectRevert(
      _encodeRejectedRevert(MockToken.transfer.selector, address(rejectPolicy), "address is on reject list")
    );
    token.transfer(recipient, 100);

    // remove from the reject list
    vm.startPrank(deployer, deployer);
    rejectPolicy.unrejectAddress(recipient);

    // transfer from address to recipient
    vm.startPrank(account, account);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  function test_mint_notInList_success() public {
    vm.startPrank(deployer, deployer);
    token.mint(account, 100);
    vm.assertEq(token.balanceOf(account), 100);
  }

  function test_mint_inList_failure() public {
    vm.startPrank(deployer, deployer);
    // add account as rejected
    rejectPolicy.rejectAddress(account);
    vm.assertEq(rejectPolicy.addressRejected(account), true);
    vm.expectRevert(_encodeRejectedRevert(MockToken.mint.selector, address(rejectPolicy), "address is on reject list"));
    token.mint(account, 100);
  }

  function test_misconfiguration_failure() public {
    vm.startPrank(deployer);
    // misconfigure the rejectPolicy to check mint operations
    ERC3643MintBurnExtractor mintExtractor = new ERC3643MintBurnExtractor();
    policyEngine.setExtractor(MockToken.burn.selector, address(mintExtractor));
    policyEngine.addPolicy(address(token), MockToken.burn.selector, address(rejectPolicy), new bytes32[](0));

    bytes memory error = abi.encodeWithSignature("Error(string)", "expected at least 1 parameter");
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunError.selector, MockToken.burn.selector, address(rejectPolicy), error
      )
    );
    token.burn(recipient, 100);
  }
}
