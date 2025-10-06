// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "@chainlink/policy-management/interfaces/IExtractor.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ERC20TransferValueExtractor
 * @notice An extractor that extracts the transfer amount from calldata and computes the price value using a price feed.
 * @dev The amount extracted is latestPrice * tokenAmount / 10^priceFeedDecimals. It DOES NOT account for the token's
 * decimals.
 */
contract ERC20TransferValueExtractor is IExtractor, Ownable {
  /// @notice The price feed contract used to get the latest price.
  AggregatorV3Interface private s_priceFeed;

  /**
   * @notice Emitted when the price feed is set.
   * @param priceFeed The address of the price feed contract
   */
  event PriceFeedSet(address priceFeed);

  /// @notice The parameter key for the amount.
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");
  /// @notice The parameter key for the price feed round ID.
  bytes32 public constant PARAM_PRICE_FEED_ROUND_ID = keccak256("priceFeedRoundId");
  /// @notice The parameter key for the price feed updated at timestamp.
  bytes32 public constant PARAM_PRICE_FEED_UPDATED_AT = keccak256("priceFeedUpdatedAt");

  /**
   * @param _priceFeed The address of the price feed contract.
   */
  constructor(address _priceFeed) Ownable(msg.sender) {
    if (_priceFeed != address(0)) {
      s_priceFeed = AggregatorV3Interface(_priceFeed);
      emit PriceFeedSet(_priceFeed);
    }
  }

  /**
   * @notice Set the price feed address.
   * @dev Throws if the new price feed is the same as the current one
   * @param _priceFeed The address of the price feed contract
   */
  function setPriceFeed(address _priceFeed) public onlyOwner {
    require(address(s_priceFeed) != _priceFeed, "Price feed unchanged");

    s_priceFeed = AggregatorV3Interface(_priceFeed);
    emit PriceFeedSet(_priceFeed);
  }

  /**
   * @notice Get the price feed address
   * @return priceFeedAddress The address of the price feed contract
   */
  function getPriceFeed() external view returns (address) {
    return address(s_priceFeed);
  }

  /**
   * @notice Extract the amount from the payload and compute value using price feed data
   * @dev The amount extracted is latestPrice * tokenAmount / 10^priceFeedDecimals. It DOES NOT account for the token's
   * decimals.
   * @param payload The payload to extract the data from
   * @return result [amount(uint256), priceFeedRoundId(uint80), priceFeedUpdatedAt(uint256)] The extracted parameters
   */
  function extract(IPolicyEngine.Payload calldata payload)
    external
    view
    override
    returns (IPolicyEngine.Parameter[] memory)
  {
    uint256 amount = 0;
    if (payload.selector == IERC20.transfer.selector) {
      (, amount) = abi.decode(payload.data, (address, uint256));
    } else if (payload.selector == IERC20.transferFrom.selector) {
      (,, amount) = abi.decode(payload.data, (address, address, uint256));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](3);

    if (address(s_priceFeed) == address(0)) {
      result[0] = IPolicyEngine.Parameter(PARAM_AMOUNT, abi.encode(amount));
    } else {
      (uint80 roundId, int256 price,, uint256 updatedAt,) = s_priceFeed.latestRoundData();
      uint256 amountInQuote = amount * uint256(price) / (10 ** s_priceFeed.decimals());

      result[0] = IPolicyEngine.Parameter(PARAM_AMOUNT, abi.encode(amountInQuote));
      result[1] = IPolicyEngine.Parameter(PARAM_PRICE_FEED_ROUND_ID, abi.encode(roundId));
      result[2] = IPolicyEngine.Parameter(PARAM_PRICE_FEED_UPDATED_AT, abi.encode(updatedAt));
    }

    return result;
  }
}
