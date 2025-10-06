// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";

contract MockAggregatorV3 is AggregatorV3Interface {
  int256 private s_price;
  uint8 private s_decimals;
  uint256 private s_updatedAt;

  constructor(int256 _initialPrice, uint8 _decimals) {
    s_price = _initialPrice;
    s_decimals = _decimals;
  }

  function setPrice(int256 newPrice) external {
    s_price = newPrice;
  }

  function setUpdatedAt(uint256 newUpdatedAt) external {
    s_updatedAt = newUpdatedAt;
  }

  function decimals() external view override returns (uint8) {
    return s_decimals;
  }

  function latestRoundData()
    external
    view
    override
    returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
  {
    return (0, s_price, 0, s_updatedAt, 0);
  }

  function description() external pure override returns (string memory) {
    return "Mock Aggregator";
  }

  function version() external pure override returns (uint256) {
    return 1;
  }

  function getRoundData(uint80 _roundId)
    external
    view
    override
    returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
  {}
}
