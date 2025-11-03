// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ComplianceTokenForceTransferExtractor} from
  "@chainlink/policy-management/extractors/ComplianceTokenForceTransferExtractor.sol";
import {ComplianceTokenERC20} from "../../../tokens/erc-20/src/ComplianceTokenERC20.sol";

contract ComplianceTokenForceTransferExtractorTest is Test {
  ComplianceTokenForceTransferExtractor public extractor;
  address public deployer;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    extractor = new ComplianceTokenForceTransferExtractor();

    vm.stopPrank();
  }

  function test_extract_forcedTransfer_succeeds() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: ComplianceTokenERC20.forceTransfer.selector,
      data: abi.encode(deployer, recipient, 888),
      sender: deployer,
      context: ""
    });

    IPolicyEngine.Parameter[] memory params = extractor.extract(payload);
    vm.assertEq(params.length, 3);
    vm.assertEq(params[0].name, keccak256("from"));
    vm.assertEq(params[1].name, keccak256("to"));
    vm.assertEq(params[2].name, keccak256("amount"));
    address from = abi.decode(params[0].value, (address));
    vm.assertEq(from, deployer);
    address to = abi.decode(params[1].value, (address));
    vm.assertEq(to, recipient);
    uint256 value = abi.decode(params[2].value, (uint256));
    vm.assertEq(value, 888);
  }

  function test_extract_transfer_fails() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: ComplianceTokenERC20.transfer.selector,
      data: abi.encode(recipient, 3643),
      sender: deployer,
      context: ""
    });

    vm.expectPartialRevert(IPolicyEngine.UnsupportedSelector.selector);
    extractor.extract(payload);
  }
}
