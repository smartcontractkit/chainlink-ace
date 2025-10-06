// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {BypassPolicy} from "@chainlink/policy-management/policies/BypassPolicy.sol";
import {MockToken} from "../helpers/MockToken.sol";
import {ERC3643MintBurnExtractor} from "@chainlink/policy-management/extractors/ERC3643MintBurnExtractor.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract BypassPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockToken public token;
  BypassPolicy public bypassPolicy;
  address public deployer;
  address public account;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    account = makeAddr("account");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    policyEngine = _deployPolicyEngine(IPolicyEngine.PolicyResult.Rejected, deployer);

    BypassPolicy bypassPolicyImpl = new BypassPolicy();
    bypassPolicy = BypassPolicy(_deployPolicy(address(bypassPolicyImpl), address(policyEngine), deployer, ""));
    // add account by default
    bypassPolicy.allowAddress(account);

    token = MockToken(_deployMockToken(address(policyEngine)));

    // set up the bypassPolicy to check the recipient and origin address of token transfers
    ERC20TransferExtractor transferExtractor = new ERC20TransferExtractor();
    bytes32[] memory transferPolicyParams = new bytes32[](2);
    transferPolicyParams[0] = transferExtractor.PARAM_TO();
    transferPolicyParams[1] = transferExtractor.PARAM_FROM();
    policyEngine.setExtractor(MockToken.transfer.selector, address(transferExtractor));
    policyEngine.addPolicy(address(token), MockToken.transfer.selector, address(bypassPolicy), transferPolicyParams);
    // set up the bypassPolicy to check the mint account (single account)
    ERC3643MintBurnExtractor mintBurnExtractor = new ERC3643MintBurnExtractor();
    bytes32[] memory mintPolicyParams = new bytes32[](1);
    mintPolicyParams[0] = mintBurnExtractor.PARAM_ACCOUNT();
    policyEngine.setExtractor(MockToken.mint.selector, address(mintBurnExtractor));
    policyEngine.addPolicy(address(token), MockToken.mint.selector, address(bypassPolicy), mintPolicyParams);
  }

  function test_allowAddress_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the address to the allow list
    bypassPolicy.allowAddress(recipient);
    vm.assertEq(bypassPolicy.addressAllowed(recipient), true);
  }

  function test_allowAddress_alreadyInList_fails() public {
    vm.startPrank(deployer, deployer);

    // add the address to the bypass list (setup and sanity check)
    bypassPolicy.allowAddress(recipient);
    vm.assertEq(bypassPolicy.addressAllowed(recipient), true);

    // add the address to the bypass list again (reverts)
    vm.expectRevert("Account already in bypass list");
    bypassPolicy.allowAddress(recipient);
  }

  function test_disallowAddress_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the address to the bypass list (setup and sanity check)
    bypassPolicy.allowAddress(recipient);
    vm.assertEq(bypassPolicy.addressAllowed(recipient), true);

    // remove the address from the bypass list
    bypassPolicy.disallowAddress(recipient);
    vm.assertEq(bypassPolicy.addressAllowed(recipient), false);
  }

  function test_disallowAddress_notInList_fails() public {
    vm.startPrank(deployer, deployer);

    // remove the address from the bypass list (reverts)
    vm.expectRevert("Account not in bypass list");
    bypassPolicy.disallowAddress(recipient);
  }

  function test_transfer_inList_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the recipient to the bypass list
    bypassPolicy.allowAddress(recipient);
    vm.assertEq(bypassPolicy.addressAllowed(recipient), true);

    vm.startPrank(account, account);

    // transfer from address to recipient
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_notInList_fails() public {
    vm.startPrank(account, account);

    // transfer from address to recipient (reverts)
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyEngine.PolicyRunRejected.selector, MockToken.transfer.selector, address(0))
    );
    token.transfer(recipient, 100);
  }

  function test_transfer_removedFromList_fails() public {
    // add the address to the bypass list (setup)
    vm.startPrank(deployer, deployer);
    bypassPolicy.allowAddress(recipient);

    // transfer from address to recipient (sanity check)
    vm.startPrank(account, account);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);

    // remove from the bypass list
    vm.startPrank(deployer, deployer);
    bypassPolicy.disallowAddress(recipient);

    // transfer from address to recipient (should revert after removal)
    vm.startPrank(account, account);
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyEngine.PolicyRunRejected.selector, MockToken.transfer.selector, address(0))
    );
    token.transfer(recipient, 100);
  }

  function test_mint_inList_success() public {
    vm.startPrank(deployer, deployer);
    token.mint(account, 100);
    vm.assertEq(token.balanceOf(account), 100);
  }

  function test_mint_notInList_failure() public {
    vm.startPrank(deployer, deployer);
    vm.expectRevert(
      abi.encodeWithSelector(IPolicyEngine.PolicyRunRejected.selector, MockToken.mint.selector, address(0))
    );
    token.mint(recipient, 100);
  }

  function test_misconfiguration_failure() public {
    vm.startPrank(deployer);
    // misconfigure the bypassPolicy to check burn operations (no accounts)
    ERC3643MintBurnExtractor mintBurnExtractor = new ERC3643MintBurnExtractor();
    policyEngine.setExtractor(MockToken.burn.selector, address(mintBurnExtractor));
    policyEngine.addPolicy(address(token), MockToken.burn.selector, address(bypassPolicy), new bytes32[](0));

    bytes memory error = abi.encodeWithSignature("Error(string)", "expected at least 1 parameter");
    vm.expectRevert(
      abi.encodeWithSelector(
        IPolicyEngine.PolicyRunError.selector, MockToken.burn.selector, address(bypassPolicy), error
      )
    );
    token.burn(account, 100);
  }
}
