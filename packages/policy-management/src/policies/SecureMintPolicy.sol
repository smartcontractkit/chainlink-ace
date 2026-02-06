// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
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
 * - `reservesFeed`: The Chainlink AggregatorV3 price feed contract address used to retrieve the latest reserve value.
 * - `reserveMarginMode`: Specifies how the reserve margin is calculated. A positive reserve margin means that the
 * reserves must exceed the total supply of the token by a certain amount, while a negative reserve margin means that
 * the reserves can be less than the total supply by a certain amount.
 * - `reserveMarginAmount`: The margin amount used in the reserve margin calculation. If `s_reserveMarginMode` is
 * percentage-based, this represents a hundredth of a percent.
 * - `maxStalenessSeconds`: The maximum staleness seconds for the reserve price feed. 0 means no staleness check.
 * - `tokenMetadata`: The subject token address and decimals used for reserve scaling.
 *
 * ## CRITICAL REQUIREMENT - Decimal Matching:
 * **The reserve feed MUST report values in the same decimals as the protected token.** If the token uses 18 decimals,
 * the reserve feed must also report reserves with 18 decimals. Mismatched decimals will cause incorrect reserve
 * calculations, potentially allowing over-minting or incorrectly blocking valid mints.
 *
 * ## Dependencies:
 * - **AggregatorV3Interface**: Used to retrieve the latest reserve value.
 * - **IERC20**: The policy assumes the `subject` contract implements ERC-20 and supports `totalSupply()`.
 */
contract SecureMintPolicy is Policy {
  string public constant override typeAndVersion = "SecureMintPolicy 1.0.0";

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
   * @notice Emitted when the token metadata is set.
   * @param tokenAddress The address of the token.
   * @param tokenDecimals The new token decimals.
   */
  event TokenMetadataSet(address tokenAddress, uint8 tokenDecimals);

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

  /**
   * @notice The token metadata for the subject token.
   * @param tokenAddress The address of the token.
   * @param tokenDecimals The decimals of the token.
   */
  struct TokenMetadata {
    address tokenAddress;
    uint8 tokenDecimals;
  }

  /**
   * @notice The reserve margin configuration parameters.
   * @param reserveMarginMode Specifies how the reserve margin is calculated.
   * @param reserveMarginAmount The margin amount used in the reserve margin calculation. If reserveMarginMode is
   * percentage-based, this represents a hundredth of a percent.
   */
  struct ReserveMarginConfigs {
    ReserveMarginMode reserveMarginMode;
    uint256 reserveMarginAmount;
  }

  /// @notice Basis points scale used for percentage calculations (1 basis point = 0.01%)
  uint256 private constant BASIS_POINTS = 10_000;

  /// @custom:storage-location erc7201:chainlink.ace.SecureMintPolicy
  struct SecureMintPolicyStorage {
    /// @notice Chainlink AggregatorV3 price feed contract address.
    AggregatorV3Interface reservesFeed;
    /// @notice Reserve margin configuration parameters.
    ReserveMarginConfigs reserveMarginConfigs;
    /// @notice The maximum staleness seconds for the reserve price feed. 0 means no staleness check.
    uint256 maxStalenessSeconds;
    /// @notice The token metadata for the subject token.
    TokenMetadata tokenMetadata;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.SecureMintPolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant SecureMintPolicyStorageLocation =
    0x26197021cc79312a76d982b1739b4e612ed06b5c85152dd5d767be949d417f00;

  function _getSecureMintPolicyStorage() private pure returns (SecureMintPolicyStorage storage $) {
    assembly {
      $.slot := SecureMintPolicyStorageLocation
    }
  }

  /**
   * @notice Configures the policy with the provided parameters.
   * @param parameters ABI-encoded bytes containing [address reservesFeed, ReserveMarginConfigs reserveMarginConfigs,
   * uint256 maxStalenessSeconds, TokenMetadata tokenMetadata].
   */
  function configure(bytes calldata parameters) internal override {
    (
      address reservesFeed,
      ReserveMarginConfigs memory reserveMarginConfigs,
      uint256 maxStalenessSeconds,
      TokenMetadata memory tokenMetadata
    ) = abi.decode(parameters, (address, ReserveMarginConfigs, uint256, TokenMetadata));

    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage();
    $.reservesFeed = AggregatorV3Interface(reservesFeed);
    emit ReservesFeedSet(reservesFeed);

    _setReserveMargin(reserveMarginConfigs.reserveMarginMode, reserveMarginConfigs.reserveMarginAmount);

    $.maxStalenessSeconds = maxStalenessSeconds;
    emit MaxStalenessSecondsSet(maxStalenessSeconds);

    _setTokenMetadata(tokenMetadata.tokenAddress, tokenMetadata.tokenDecimals);
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

  /**
   * @notice Updates the token metadata used for scaling when the token omits metadata.
   * @dev Throws when the token address does not match the current one or the decimals are the same as the current
   * value.
   * @param tokenAddress The address of the token.
   * @param tokenDecimals The new token decimals.
   */
  function setTokenMetadata(address tokenAddress, uint8 tokenDecimals) external onlyOwner {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    TokenMetadata memory tokenMetadata = $.tokenMetadata;
    require(tokenMetadata.tokenAddress == tokenAddress, "token address mismatch");
    require(tokenDecimals != tokenMetadata.tokenDecimals, "decimals same as current");
    _setTokenMetadata(tokenAddress, tokenDecimals);
  }

  function _setTokenMetadata(address tokenAddress, uint8 tokenDecimals) internal {
    require(tokenDecimals > 0, "decimals must be > 0");
    require(tokenDecimals <= 18, "decimals must be <= 18");
    require(tokenAddress != address(0), "token address is zero");
    try IERC20Metadata(tokenAddress).decimals() returns (uint8 value) {
      require(value == tokenDecimals, "decimals mismatch with token metadata");
    } catch {
      // Ignore error, use provided decimals
    }
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    TokenMetadata memory tokenMetadata = $.tokenMetadata;
    tokenMetadata.tokenAddress = tokenAddress;
    tokenMetadata.tokenDecimals = tokenDecimals;
    $.tokenMetadata = tokenMetadata;
    emit TokenMetadataSet(tokenAddress, tokenDecimals);
  }

  function _setReserveMargin(ReserveMarginMode mode, uint256 amount) internal {
    require(uint256(mode) <= 4, "Invalid margin mode");
    if (mode == ReserveMarginMode.PositivePercentage || mode == ReserveMarginMode.NegativePercentage) {
      require(amount <= BASIS_POINTS, "margin must be <= BASIS_POINTS for percentage modes");
    } else if (mode == ReserveMarginMode.PositiveAbsolute || mode == ReserveMarginMode.NegativeAbsolute) {
      require(amount > 0, "margin must be > 0 for absolute modes");
    }
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    $.reserveMarginConfigs.reserveMarginMode = mode;
    $.reserveMarginConfigs.reserveMarginAmount = amount;
    emit ReserveMarginSet(mode, amount);
  }

  /**
   * @notice Updates the reserve margin mode and amount.
   * @dev Throws when mode is invalid or both the mode and amount are the same as the current values.
   * @param reserveMarginMode The new reserve margin mode.
   * @param reserveMarginAmount The new reserve margin amount. When reserveMarginMode is percentage-based, this
   * represents a hundredth of a percent.
   * @dev Precision Warning: When using percentage-based modes (PositivePercentage/NegativePercentage),
   * be aware that very small reserve values combined with high margin percentages may result in
   * zero mintable supply due to integer division rounding. Consider the minimum expected reserve
   * value and price feed decimals when setting percentage margins.
   *
   * For feeds with low precision or small values, consider using absolute margin modes instead.
   */
  function setReserveMargin(ReserveMarginMode reserveMarginMode, uint256 reserveMarginAmount) external onlyOwner {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    require(
      reserveMarginMode != $.reserveMarginConfigs.reserveMarginMode
        || reserveMarginAmount != $.reserveMarginConfigs.reserveMarginAmount,
      "margin same as current"
    );
    _setReserveMargin(reserveMarginMode, reserveMarginAmount);
  }

  /**
   * @notice Updates the maximum staleness seconds for the reserve price feed.
   * @dev Throws when the value is the same as the current value.
   * @param maxStalenessSeconds The new maximum staleness seconds. 0 means no staleness check.
   */
  function setMaxStalenessSeconds(uint256 maxStalenessSeconds) external onlyOwner {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage(); // Gas optimization: single storage reference
    require(maxStalenessSeconds != $.maxStalenessSeconds, "value same as current");
    $.maxStalenessSeconds = maxStalenessSeconds;
    emit MaxStalenessSecondsSet(maxStalenessSeconds);
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
    return $.reserveMarginConfigs.reserveMarginMode;
  }

  /**
   * @notice Returns the current margin amount.
   * @return reserveMarginAmount The current margin amount.
   */
  function reserveMarginAmount() external view returns (uint256) {
    SecureMintPolicyStorage storage $ = _getSecureMintPolicyStorage();
    return $.reserveMarginConfigs.reserveMarginAmount;
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
    if ($.reserveMarginConfigs.reserveMarginMode == ReserveMarginMode.None) {
      return reserves;
    } else if ($.reserveMarginConfigs.reserveMarginMode == ReserveMarginMode.PositivePercentage) {
      // WARNING: May round to zero for very small reserves with high margins
      // e.g., reserves=1, margin=9999 → 1 * 1 / BASIS_POINTS = 0
      return (reserves * (BASIS_POINTS - $.reserveMarginConfigs.reserveMarginAmount)) / BASIS_POINTS;
    } else if ($.reserveMarginConfigs.reserveMarginMode == ReserveMarginMode.PositiveAbsolute) {
      if (reserves < $.reserveMarginConfigs.reserveMarginAmount) {
        return 0;
      }
      return reserves - $.reserveMarginConfigs.reserveMarginAmount;
    } else if ($.reserveMarginConfigs.reserveMarginMode == ReserveMarginMode.NegativePercentage) {
      return (reserves * (BASIS_POINTS + $.reserveMarginConfigs.reserveMarginAmount)) / BASIS_POINTS;
    } else if ($.reserveMarginConfigs.reserveMarginMode == ReserveMarginMode.NegativeAbsolute) {
      return reserves + $.reserveMarginConfigs.reserveMarginAmount;
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
    if (parameters.length != 1) {
      revert InvalidParameters("expected 1 parameter");
    }
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

    uint8 feedDecimals = $.reservesFeed.decimals();
    TokenMetadata memory tokenMetadata = $.tokenMetadata;
    // Scale reserve to token decimals even when the token omits metadata
    uint256 scaledReserve = uint256(reserve);
    if (tokenMetadata.tokenDecimals > feedDecimals) {
      uint256 factor = 10 ** (uint256(tokenMetadata.tokenDecimals) - uint256(feedDecimals));
      scaledReserve *= factor;
    } else if (tokenMetadata.tokenDecimals < feedDecimals) {
      uint256 factor = 10 ** (uint256(feedDecimals) - uint256(tokenMetadata.tokenDecimals));
      scaledReserve /= factor;
    }
    if (amount + IERC20Metadata(subject).totalSupply() > totalMintableSupply(scaledReserve)) {
      revert IPolicyEngine.PolicyRejected("mint would exceed available reserves");
    }

    return IPolicyEngine.PolicyResult.Continue;
  }
}
