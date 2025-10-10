// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title SecureMintPolicy
 * @notice A policy that ensures new token minting does not exceed available reserves.
 * @dev Extends Chainlink's `Policy` reference implementation.
 * This policy checks if minting a specified amount would cause the total supply of a token to exceed the reserve value
 * provided by a Chainlink price feed.
 *
 * ## Core Parameters
 *
 * - `s_reservesFeed`: The Chainlink AggregatorV3 price feed contract address used to retrieve the latest reserve value.
 * - `s_reserveMarginMode`: Specifies how the reserve margin is calculated. A positive reserve margin means that the
 * reserves must exceed the total supply of the token by a certain amount, while a negative reserve margin means that
 * the reserves can be less than the total supply by a certain amount.
 * - `s_reserveMarginAmount`: The margin amount used in the reserve margin calculation. If `s_reserveMarginMode` is
 * percentage-based, this represents a hundredth of a percent.
 * - `s_maxStalenessSeconds`: The maximum staleness seconds for the reserve price feed. 0 means no staleness check.
 *
 * ## Dependencies:
 * - **AggregatorV3Interface**: Used to retrieve the latest reserve value.
 * - **IERC20**: The policy assumes the `subject` contract implements ERC-20 and supports `totalSupply()`.
 */
contract SecureMintPolicy is Policy {
  /**
   * @notice Emitted when the PoR feed contract address is set.
   * @param reservesFeed The new Chainlink AggregatorV3 price feed contract address.
   */
  event ReservesFeedSet(address reservesFeed);
  /**
   * @notice Emitted when the margin mode is set.
   * @param mode The new margin mode.
   * @param amount The new margin amount.
   */
  event ReserveMarginSet(ReserveMarginMode mode, uint256 amount);
  /**
   * @notice Emitted when the max staleness seconds is set.
   * @param maxStalenessSeconds The new max staleness seconds. 0 means no staleness check.
   */
  event MaxStalenessSecondsSet(uint256 maxStalenessSeconds);

  /**
   * @notice The ReserveMarginMode enum specifies how the reserve margin is calculated. A positive reserve margin means
   * that the reserves must exceed the total supply of the token by a certain amount, while a negative reserve margin
   * means that the reserves can be less than the total supply by a certain amount.
   * @param None No margin is applied. Total mintable amount is equal to reserves.
   * @param PositivePercentage A positive percentage margin is applied. Total mintable amount is
   * reserves * (BASIS_POINTS - margin) / BASIS_POINTS.
   * @param PositiveAbsolute A positive absolute margin is applied. Total mintable amount is reserves - margin.
   * @param NegativePercentage A negative percentage margin is applied. Total mintable amount is
   * reserves * (BASIS_POINTS + margin) / BASIS_POINTS.
   * @param NegativeAbsolute A negative absolute margin is applied. Total mintable amount is reserves + margin.
   */
  enum ReserveMarginMode {
    None,
    PositivePercentage,
    PositiveAbsolute,
    NegativePercentage,
    NegativeAbsolute
  }

  /// @notice Basis points scale used for percentage calculations (1 basis point = 0.01%)
  uint256 private constant BASIS_POINTS = 10_000;

  /// @custom:storage-location erc7201:policy-management.SecureMintPolicy
  struct SecureMintPolicyStorage {
    /// @notice Chainlink AggregatorV3 price feed contract address.
    AggregatorV3Interface reservesFeed;
    /// @notice Specifies how the reserve margin is calculated.
    ReserveMarginMode reserveMarginMode;
    /// @notice The margin amount used in the reserve margin calculation. If reserveMarginMode is percentage-based, this
    /// represents a hundredth of a percent.
    uint256 reserveMarginAmount;
    /// @notice The maximum staleness seconds for the reserve price feed. 0 means no staleness check.
    uint256 maxStalenessSeconds;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.SecureMintPolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant SecureMintPolicyStorageLocation =
    0xce7aed3b7d424da898685a1d407ca1286fb1f81e854eae77e5e2276c63944900;

  function _getSecureMintPolicyStorage() private pure returns (SecureMintPolicyStorage storage $) {
    assembly {
      $.slot := SecureMintPolicyStorageLocation
    }
  }

  /**
   * @notice Configures the policy by setting the reserves feed and margin.
   * @param parameters ABI-encoded bytes containing [address reservesFeed, ReserveMarginMode reserveMarginMode, uint256
   * marginAmount, uint256 maxStalenessSeconds].
   */
  function configure(bytes calldata parameters) internal override {
    (address reservesFeed, ReserveMarginMode reserveMarginMode, uint256 marginAmount, uint256 maxStalenessSeconds) =
      abi.decode(parameters, (address, ReserveMarginMode, uint256, uint256));

    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage();
    $.reservesFeed = AggregatorV3Interface(reservesFeed);
    emit ReservesFeedSet(reservesFeed);

    _setReserveMargin(reserveMarginMode, marginAmount);

    $.maxStalenessSeconds = maxStalenessSeconds;
    emit MaxStalenessSecondsSet(maxStalenessSeconds);
  }

  /**
   * @notice Updates the Chainlink price feed used for reserve validation.
   * @dev Throws when address is the same as the current one.
   * @param reservesFeed The new Chainlink AggregatorV3 price feed contract address.
   */
  function setReservesFeed(address reservesFeed) external onlyOwner {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    require(reservesFeed != address($.reservesFeed), "feed same as current");
    $.reservesFeed = AggregatorV3Interface(reservesFeed);
    emit ReservesFeedSet(reservesFeed);
  }

  function _setReserveMargin(ReserveMarginMode mode, uint256 amount) internal {
    require(uint256(mode) <= 4, "Invalid margin mode");
    if (mode == ReserveMarginMode.PositivePercentage || mode == ReserveMarginMode.NegativePercentage) {
      require(amount <= BASIS_POINTS, "margin must be <= BASIS_POINTS for percentage modes");
    } else if (mode == ReserveMarginMode.PositiveAbsolute || mode == ReserveMarginMode.NegativeAbsolute) {
      require(amount > 0, "margin must be > 0 for absolute modes");
    }
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    $.reserveMarginMode = mode;
    $.reserveMarginAmount = amount;
    emit ReserveMarginSet(mode, amount);
  }

  /**
   * @notice Updates the reserve margin mode and amount.
   * @dev Throws when mode is invalid or both the mode and amount are the same as the current values.
   * @param mode The new reserve margin mode.
   * @param amount The new reserve margin amount. When mode is percentage-based, this represents a hundredth of a
   * percent.
   * @dev Precision Warning: When using percentage-based modes (PositivePercentage/NegativePercentage),
   * be aware that very small reserve values combined with high margin percentages may result in
   * zero mintable supply due to integer division rounding. Consider the minimum expected reserve
   * value and price feed decimals when setting percentage margins.
   *
   * For feeds with low precision or small values, consider using absolute margin modes instead.
   */
  function setReserveMargin(ReserveMarginMode mode, uint256 amount) external onlyOwner {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    require(mode != $.reserveMarginMode || amount != $.reserveMarginAmount, "margin same as current");
    _setReserveMargin(mode, amount);
  }

  /**
   * @notice Updates the maximum staleness seconds for the reserve price feed.
   * @dev Throws when the value is the same as the current value.
   * @param value The new maximum staleness seconds. 0 means no staleness check.
   */
  function setMaxStalenessSeconds(uint256 value) external onlyOwner {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    require(value != $.maxStalenessSeconds, "value same as current");
    $.maxStalenessSeconds = value;
    emit MaxStalenessSecondsSet(value);
  }

  /**
   * @notice Returns the current Chainlink price feed used for reserve validation.
   * @return address The address of the current Chainlink AggregatorV3 price feed contract.
   */
  function reservesFeed() external view returns (address) {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage();
    return address($.reservesFeed);
  }

  /**
   * @notice Returns the current margin mode.
   * @return reserveMarginMode The current margin mode.
   */
  function reserveMarginMode() external view returns (ReserveMarginMode) {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage();
    return $.reserveMarginMode;
  }

  /**
   * @notice Returns the current margin amount.
   * @return reserveMarginAmount The current margin amount.
   */
  function reserveMarginAmount() external view returns (uint256) {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage();
    return $.reserveMarginAmount;
  }

  /**
   * @notice Returns the current max staleness seconds.
   * @return maxStalenessSeconds The current max staleness seconds.
   */
  function maxStalenessSeconds() external view returns (uint256) {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage();
    return $.maxStalenessSeconds;
  }

  /**
   * @notice Calculates the total mintable amount based on the reserves and reserve margin mode.
   * @param reserves The current reserves value.
   * @return The total mintable amount.
   */
  function totalMintableSupply(uint256 reserves) internal view returns (uint256) {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    if ($.reserveMarginMode == ReserveMarginMode.None) {
      return reserves;
    } else if ($.reserveMarginMode == ReserveMarginMode.PositivePercentage) {
      // WARNING: May round to zero for very small reserves with high margins
      // e.g., reserves=1, margin=9999 → 1 * 1 / BASIS_POINTS = 0
      return reserves * (BASIS_POINTS - $.reserveMarginAmount) / BASIS_POINTS;
    } else if ($.reserveMarginMode == ReserveMarginMode.PositiveAbsolute) {
      if (reserves < $.reserveMarginAmount) {
        return 0;
      }
      return reserves - $.reserveMarginAmount;
    } else if ($.reserveMarginMode == ReserveMarginMode.NegativePercentage) {
      return reserves * (BASIS_POINTS + $.reserveMarginAmount) / BASIS_POINTS;
    } else if ($.reserveMarginMode == ReserveMarginMode.NegativeAbsolute) {
      return reserves + $.reserveMarginAmount;
    }
    revert("Invalid margin mode");
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param subject The address of the protected contract.
   * @param parameters [to(address),amount(uint256)] The parameters of the called method.
   * @return result The result of the policy check.
   */
  function run(
    address, /*caller*/
    address subject, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    require(parameters.length == 1, "expected 1 parameter");
    uint256 amount = abi.decode(parameters[0], (uint256));

    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    (, int256 reserve,, uint256 updatedAt,) = $.reservesFeed.latestRoundData();

    // reserve is not expected to be negative
    if (reserve < 0) {
      revert IPolicyEngine.PolicyRejected("reserve value is negative");
    }

    if ($.maxStalenessSeconds > 0 && block.timestamp - updatedAt > $.maxStalenessSeconds) {
      revert IPolicyEngine.PolicyRejected("reserve data is stale");
    }

    IERC20 token = IERC20(subject);
    if (amount + token.totalSupply() > totalMintableSupply(uint256(reserve))) {
      revert IPolicyEngine.PolicyRejected("mint would exceed available reserves");
    }

    return IPolicyEngine.PolicyResult.Continue;
  }
}
