// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ERC20ApproveExtractor} from "@chainlink/policy-management/extractors/ERC20ApproveExtractor.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";

contract ERC20ApproveExtractorTest is Test {
  ERC20ApproveExtractor public extractor;
  address public deployer;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    extractor = new ERC20ApproveExtractor();

    vm.stopPrank();
  }

  function test_extract_approve_succeeds() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IERC20.approve.selector,
      data: abi.encode(recipient, 999),
      sender: deployer,
      context: ""
    });

    IPolicyEngine.Parameter[] memory params = extractor.extract(payload);
    vm.assertEq(params.length, 3);
    vm.assertEq(params[0].name, keccak256("account"));
    vm.assertEq(params[1].name, keccak256("spender"));
    vm.assertEq(params[2].name, keccak256("amount"));
    address approver = abi.decode(params[0].value, (address));
    vm.assertEq(approver, deployer);
    address spender = abi.decode(params[1].value, (address));
    vm.assertEq(spender, recipient);
    uint256 value = abi.decode(params[2].value, (uint256));
    vm.assertEq(value, 999);
  }

  function test_extract_transfer_fails() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IERC20.transfer.selector,
      data: abi.encode(recipient, 999),
      sender: deployer,
      context: ""
    });

    vm.expectPartialRevert(IPolicyEngine.UnsupportedSelector.selector);
    extractor.extract(payload);
  }
}
