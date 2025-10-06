// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {ERC20TransferValueExtractor} from "@chainlink/policy-management/extractors/ERC20TransferValueExtractor.sol";
import {MockAggregatorV3} from "../helpers/MockAggregatorV3.sol";

contract ERC20TransferValueExtractorTest is Test {
  uint8 public constant PRICE_FEED_DECIMALS = 8;
  int256 public constant PRICE_FEED_PRICE = 1234567890;

  MockAggregatorV3 public priceFeed;
  ERC20TransferValueExtractor public extractor;
  address public deployer;

  function setUp() public {
    deployer = makeAddr("deployer");

    vm.startPrank(deployer, deployer);

    priceFeed = new MockAggregatorV3(PRICE_FEED_PRICE, PRICE_FEED_DECIMALS);
    extractor = new ERC20TransferValueExtractor(address(priceFeed));

    vm.stopPrank();
  }

  function test_setPriceFeed_succeeds() public {
    vm.startPrank(deployer, deployer);
    MockAggregatorV3 priceFeed2 = new MockAggregatorV3(2345678901, 8);

    // set new price feed
    vm.expectEmit();
    emit ERC20TransferValueExtractor.PriceFeedSet(address(priceFeed2));
    extractor.setPriceFeed(address(priceFeed2));
    vm.assertEq(extractor.getPriceFeed(), address(priceFeed2));
  }

  function test_setPriceFeed_noEffect_fails() public {
    vm.startPrank(deployer, deployer);

    // set new price feed (reverts)
    vm.expectRevert("Price feed unchanged");
    extractor.setPriceFeed(address(priceFeed));
  }

  function test_extract_succeeds() public {
    vm.startPrank(deployer, deployer);
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: IERC20.transfer.selector,
      data: abi.encode(makeAddr("recipient"), 42 ether),
      sender: makeAddr("sender"),
      context: ""
    });

    uint256 value;
    IPolicyEngine.Parameter[] memory params;

    params = extractor.extract(payload);
    vm.assertEq(params.length, 3);
    vm.assertEq(params[0].name, keccak256("amount"));
    vm.assertEq(params[1].name, keccak256("priceFeedRoundId"));
    vm.assertEq(params[2].name, keccak256("priceFeedUpdatedAt"));
    value = abi.decode(params[0].value, (uint256));
    vm.assertEq(value, 1234567890 * 42 ether / 10 ** PRICE_FEED_DECIMALS);
  }
}
