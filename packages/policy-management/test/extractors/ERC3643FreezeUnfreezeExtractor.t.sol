// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ERC3643FreezeUnfreezeExtractor} from
  "@chainlink/policy-management/extractors/ERC3643FreezeUnfreezeExtractor.sol";
import {IToken} from "../../../vendor/erc-3643/token/IToken.sol";

contract ERC3643FreezeUnfreezeExtractorTest is Test {
  ERC3643FreezeUnfreezeExtractor public extractor;
  address public deployer;
  address public holder;

  function setUp() public {
    deployer = makeAddr("deployer");
    holder = makeAddr("holder");

    vm.startPrank(deployer, deployer);

    extractor = new ERC3643FreezeUnfreezeExtractor();

    vm.stopPrank();
  }

  function test_extract_freeze_succeeds() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.freezePartialTokens.selector,
      data: abi.encode(holder, 36),
      sender: deployer,
      context: ""
    });

    IPolicyEngine.Parameter[] memory params = extractor.extract(payload);
    vm.assertEq(params.length, 2);
    vm.assertEq(params[0].name, keccak256("account"));
    vm.assertEq(params[1].name, keccak256("amount"));
    address account = abi.decode(params[0].value, (address));
    vm.assertEq(account, holder);
    uint256 value = abi.decode(params[1].value, (uint256));
    vm.assertEq(value, 36);
  }

  function test_extract_unfreeze_succeeds() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IToken.unfreezePartialTokens.selector,
      data: abi.encode(holder, 43),
      sender: deployer,
      context: ""
    });

    IPolicyEngine.Parameter[] memory params = extractor.extract(payload);
    vm.assertEq(params.length, 2);
    vm.assertEq(params[0].name, keccak256("account"));
    vm.assertEq(params[1].name, keccak256("amount"));
    address account = abi.decode(params[0].value, (address));
    vm.assertEq(account, holder);
    uint256 value = abi.decode(params[1].value, (uint256));
    vm.assertEq(value, 43);
  }

  function test_extract_transfer_fails() public {
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IERC20.transfer.selector,
      data: abi.encode(holder, 123),
      sender: deployer,
      context: ""
    });

    vm.expectPartialRevert(IPolicyEngine.UnsupportedSelector.selector);
    extractor.extract(payload);
  }
}
