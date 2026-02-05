// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine, PolicyEngine} from "@chainlink/policy-management/core/PolicyEngine.sol";
import {ERC20TransferExtractor} from "@chainlink/policy-management/extractors/ERC20TransferExtractor.sol";
import {AllowPolicy} from "@chainlink/policy-management/policies/AllowPolicy.sol";
import {MockTokenUpgradeable} from "../helpers/MockTokenUpgradeable.sol";
import {ERC3643MintBurnExtractor} from "@chainlink/policy-management/extractors/ERC3643MintBurnExtractor.sol";
import {BaseProxyTest} from "../helpers/BaseProxyTest.sol";

contract AllowPolicyTest is BaseProxyTest {
  PolicyEngine public policyEngine;
  MockTokenUpgradeable public token;
  AllowPolicy public allowPolicy;
  address public deployer;
  address public account;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    account = makeAddr("account");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    policyEngine = _deployPolicyEngine(true, deployer);

    AllowPolicy allowPolicyImpl = new AllowPolicy();
    allowPolicy = AllowPolicy(_deployPolicy(address(allowPolicyImpl), address(policyEngine), deployer, ""));
    // add account by default
    allowPolicy.allowAddress(account);

    token = MockTokenUpgradeable(_deployMockToken(address(policyEngine)));

    // set up the allowPolicy to check the recipient and origin of token transfers (multiple accounts)
    ERC20TransferExtractor transferExtractor = new ERC20TransferExtractor();
    bytes32[] memory transferPolicyParams = new bytes32[](2);
    transferPolicyParams[0] = transferExtractor.PARAM_TO();
    transferPolicyParams[1] = transferExtractor.PARAM_FROM();
    policyEngine.setExtractor(MockTokenUpgradeable.transfer.selector, address(transferExtractor));
    policyEngine.addPolicy(
      address(token), MockTokenUpgradeable.transfer.selector, address(allowPolicy), transferPolicyParams
    );
    // set up the allowPolicy to check the mint account (single account)
    ERC3643MintBurnExtractor mintBurnExtractor = new ERC3643MintBurnExtractor();
    bytes32[] memory mintPolicyParams = new bytes32[](1);
    mintPolicyParams[0] = mintBurnExtractor.PARAM_ACCOUNT();
    policyEngine.setExtractor(MockTokenUpgradeable.mint.selector, address(mintBurnExtractor));
    policyEngine.addPolicy(address(token), MockTokenUpgradeable.mint.selector, address(allowPolicy), mintPolicyParams);
  }

  function test_allowAddress_succeeds() public {
    vm.startPrank(deployer, deployer);

    // Expect AddressAllowed event to be emitted with correct parameters
    vm.expectEmit(true, true, true, true);
    emit AllowPolicy.AddressAllowed(recipient);

    // add the address to the allow list
    allowPolicy.allowAddress(recipient);
    vm.assertEq(allowPolicy.addressAllowed(recipient), true);
  }

  function test_allowAddress_alreadyInList_fails() public {
    vm.startPrank(deployer, deployer);

    // add the address to the allow list (setup and sanity check)
    allowPolicy.allowAddress(recipient);
    vm.assertEq(allowPolicy.addressAllowed(recipient), true);

    // add the address to the allow list again (reverts)
    vm.expectRevert("Account already in allow list");
    allowPolicy.allowAddress(recipient);
  }

  function test_disallowAddress_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the address to the allow list (setup and sanity check)
    allowPolicy.allowAddress(recipient);
    vm.assertEq(allowPolicy.addressAllowed(recipient), true);

    // Expect AddressDisallowed event to be emitted with correct parameters
    vm.expectEmit(true, true, true, true);
    emit AllowPolicy.AddressDisallowed(recipient);

    // remove the address from the allow list
    allowPolicy.disallowAddress(recipient);
    vm.assertEq(allowPolicy.addressAllowed(recipient), false);
  }

  function test_disallowAddress_notInList_fails() public {
    vm.startPrank(deployer, deployer);

    // remove the address from the allow list (reverts)
    vm.expectRevert("Account not in allow list");
    allowPolicy.disallowAddress(recipient);
  }

  function test_transfer_inList_succeeds() public {
    vm.startPrank(deployer, deployer);

    // add the recipient to the allow list
    allowPolicy.allowAddress(recipient);
    vm.assertEq(allowPolicy.addressAllowed(recipient), true);

    vm.startPrank(account, account);

    // transfer from address to recipient
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);
  }

  function test_transfer_notInList_fails() public {
    vm.startPrank(account, account);

    // transfer from address to recipient (reverts)
    _expectRejectedRevert(
      address(allowPolicy),
      "address is not on allow list",
      MockTokenUpgradeable.transfer.selector,
      account,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_transfer_removedFromList_fails() public {
    // add the address to the allow list (setup)
    vm.startPrank(deployer, deployer);
    allowPolicy.allowAddress(recipient);

    // transfer from address to recipient (sanity check)
    vm.startPrank(account, account);
    token.transfer(recipient, 100);
    vm.assertEq(token.balanceOf(recipient), 100);

    // remove from the allow list
    vm.startPrank(deployer, deployer);
    allowPolicy.disallowAddress(recipient);

    // transfer from address to recipient (should revert after removal)
    vm.startPrank(account, account);
    _expectRejectedRevert(
      address(allowPolicy),
      "address is not on allow list",
      MockTokenUpgradeable.transfer.selector,
      account,
      abi.encode(recipient, 100)
    );
    token.transfer(recipient, 100);
  }

  function test_mint_inList_success() public {
    vm.startPrank(deployer, deployer);
    // account is allowed in set up
    token.mint(account, 100);
    vm.assertEq(token.balanceOf(account), 100);
  }

  function test_mint_notInList_failure() public {
    vm.startPrank(deployer, deployer);
    _expectRejectedRevert(
      address(allowPolicy),
      "address is not on allow list",
      MockTokenUpgradeable.mint.selector,
      deployer,
      abi.encode(recipient, 20)
    );
    token.mint(recipient, 20);
  }

  function test_misconfiguration_failure() public {
    vm.startPrank(deployer);
    // misconfigure the allowPolicy to check burn operations (no accounts)
    ERC3643MintBurnExtractor mintBurnExtractor = new ERC3643MintBurnExtractor();
    policyEngine.setExtractor(MockTokenUpgradeable.burn.selector, address(mintBurnExtractor));
    policyEngine.addPolicy(address(token), MockTokenUpgradeable.burn.selector, address(allowPolicy), new bytes32[](0));

    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: MockTokenUpgradeable.burn.selector,
      sender: deployer,
      data: abi.encode(account, 100),
      context: new bytes(0)
    });
    bytes memory error = abi.encodeWithSignature("InvalidParameters(string)", "expected at least 1 parameter");
    _expectRunError(address(allowPolicy), error, payload);
    token.burn(account, 100);
  }
}
