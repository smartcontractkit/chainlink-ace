// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ERC3643MintBurnExtractor} from "@chainlink/policy-management/extractors/ERC3643MintBurnExtractor.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";

contract ERC3643MintBurnExtractorTest is Test {
  ERC3643MintBurnExtractor public extractor;
  address public deployer;
  address public recipient;

  function setUp() public {
    deployer = makeAddr("deployer");
    recipient = makeAddr("recipient");

    vm.startPrank(deployer, deployer);

    extractor = new ERC3643MintBurnExtractor();

    vm.stopPrank();
  }

  function test_extract_mint_succeeds() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.mint.selector,
      data: abi.encode(recipient, 123),
      sender: deployer,
      context: ""
    });

    IPolicyEngine.Parameter[] memory params = extractor.extract(payload);
    vm.assertEq(params.length, 2);
    vm.assertEq(params[0].name, keccak256("account"));
    vm.assertEq(params[1].name, keccak256("amount"));
    address user = abi.decode(params[0].value, (address));
    vm.assertEq(user, recipient);
    uint256 value = abi.decode(params[1].value, (uint256));
    vm.assertEq(value, 123);
  }

  function test_extract_burn_succeeds() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.burn.selector,
      data: abi.encode(recipient, 123),
      sender: deployer,
      context: ""
    });

    IPolicyEngine.Parameter[] memory params = extractor.extract(payload);
    vm.assertEq(params.length, 2);
    vm.assertEq(params[0].name, keccak256("account"));
    vm.assertEq(params[1].name, keccak256("amount"));
    address user = abi.decode(params[0].value, (address));
    vm.assertEq(user, recipient);
    uint256 value = abi.decode(params[1].value, (uint256));
    vm.assertEq(value, 123);
  }

  function test_extract_transfer_fails() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IERC20.transfer.selector,
      data: abi.encode(recipient, 123),
      sender: deployer,
      context: ""
    });

    vm.expectPartialRevert(IPolicyEngine.UnsupportedSelector.selector);
    extractor.extract(payload);
  }
}
