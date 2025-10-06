// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title VolumeRatePolicy
 * @notice A policy for limiting the volume of transfers within a specified time period for each account.
 * @dev Implements Chainlink's Policy reference implementation and OpenZeppelin's Ownable for access control.
 * This policy enforces limits on the total amount transferred per account over a configurable time period.
 */
contract VolumeRatePolicy is Policy {
  /// @notice The transfer volume data of an account.
  struct TransferredAt {
    /// @notice The time period in which the transfer occurred.
    /// @dev calculated as block.timestamp / timePeriodDuration.
    uint256 timePeriod;
    /// @notice The duration of the time period. This is used to evict the data if the time period duration changes.
    uint256 timePeriodDuration;
    /// @notice The total amount transferred in the current time period.
    uint256 amount;
  }

  /// @notice Emitted when the maximum transfer amount is set.
  event MaxAmountSet(uint256 maxAmount);
  /// @notice Emitted when the time period duration is set.
  event TimePeriodDurationSet(uint256 timePeriodDuration);

  /// @custom:storage-location erc7201:policy-management.VolumeRatePolicy
  struct VolumeRatePolicyStorage {
    /// @notice The duration (in seconds) of the time period for tracking transfers.
    uint256 timePeriodDuration;
    /// @notice Tracks the transfer volume and time period for a specific account.
    mapping(address account => TransferredAt transferredAt) transferredAtByAmount;
    /// @notice The maximum allowed transfer amount within a single time period
    uint256 maxAmount;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.VolumeRatePolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant VolumeRatePolicyStorageLocation =
    0xcb25215b4838d4e292145a50fb0434197be06c30a5e619d206e7746dc76f7700;

  function _getVolumeRatePolicyStorage() private pure returns (VolumeRatePolicyStorage storage $) {
    assembly {
      $.slot := VolumeRatePolicyStorageLocation
    }
  }

  /**
   * @notice Configures the policy by setting the time period duration and the maximum allowed transfer amount.
   * @param parameters ABI-encoded bytes containing two `uint256` values: the time period duration and the max amount.
   *      - `timePeriodDuration`: The duration (in seconds) of the time period for tracking transfers.
   *      - `maxAmount`: The maximum allowed transfer amount within a single time period.
   */
  function configure(bytes calldata parameters) internal override {
    (uint256 timePeriodDuration, uint256 maxAmount) = abi.decode(parameters, (uint256, uint256));
    require(timePeriodDuration != 0, "Time period duration must be non-zero");
    VolumeRatePolicyStorage storage $ = _getVolumeRatePolicyStorage(); // Gas optimization: single storage reference
    $.timePeriodDuration = timePeriodDuration;
    $.maxAmount = maxAmount;
  }

  /**
   * @notice Sets the maximum transfer amount within a single time period.
   * @dev Reverts if the new maximum amount is the same as the current one.
   * @param _maxAmount The new maximum transfer amount.
   */
  function setMaxAmount(uint256 _maxAmount) public onlyOwner {
    VolumeRatePolicyStorage storage $ = _getVolumeRatePolicyStorage(); // Gas optimization: single storage reference
    require($.maxAmount != _maxAmount, "new max amount same as current max amount");
    $.maxAmount = _maxAmount;
    emit MaxAmountSet($.maxAmount);
  }

  /**
   * @notice Gets the maximum transfer amount within a single time period.
   * @return maxAmount The maximum transfer amount.
   */
  function getMaxAmount() public view returns (uint256) {
    VolumeRatePolicyStorage storage $ = _getVolumeRatePolicyStorage();
    return $.maxAmount;
  }

  /**
   * @notice Sets the time period duration for tracking transfers.
   * @dev All volume tracking will reset after time period duration change.
   * @param _timePeriodDuration The duration (in seconds) of the time period.
   */
  function setTimePeriodDuration(uint256 _timePeriodDuration) public onlyOwner {
    require(_timePeriodDuration != 0, "Time period duration must be non-zero");
    VolumeRatePolicyStorage storage $ = _getVolumeRatePolicyStorage(); // Gas optimization: single storage reference
    require($.timePeriodDuration != _timePeriodDuration, "new duration same as current duration");
    $.timePeriodDuration = _timePeriodDuration;
    emit TimePeriodDurationSet($.timePeriodDuration);
  }

  /**
   * @notice Gets the time period duration for tracking transfers.
   * @return timePeriodDuration The duration (in seconds) of the time period.
   */
  function getTimePeriodDuration() public view returns (uint256) {
    VolumeRatePolicyStorage storage $ = _getVolumeRatePolicyStorage();
    return $.timePeriodDuration;
  }

  /**
   * @notice Decodes the parameters.
   * @param parameters [amount(uint256), from(address)] The parameters of the called method.
   * @return data The transfer amount and the sender address.
   */
  function _extractParameters(bytes[] calldata parameters) internal pure returns (uint256, address) {
    require(parameters.length == 2, "expected 2 parameters");

    uint256 amount = abi.decode(parameters[0], (uint256));
    address account = abi.decode(parameters[1], (address));

    return (amount, account);
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param parameters [amount(uint256), from(address)] The parameters of the called method.
   * @return result The result of the policy check.
   */
  function run(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    (uint256 amount, address account) = _extractParameters(parameters);

    VolumeRatePolicyStorage storage $ = _getVolumeRatePolicyStorage(); // Gas optimization: single storage reference
    uint256 timePeriod = block.timestamp / $.timePeriodDuration;

    TransferredAt memory transferredAt = $.transferredAtByAmount[account];

    if (timePeriod == transferredAt.timePeriod && transferredAt.timePeriodDuration == $.timePeriodDuration) {
      if (transferredAt.amount + amount > $.maxAmount) {
        return IPolicyEngine.PolicyResult.Rejected;
      } else {
        return IPolicyEngine.PolicyResult.Continue;
      }
    }

    if (amount > $.maxAmount) {
      return IPolicyEngine.PolicyResult.Rejected;
    }

    return IPolicyEngine.PolicyResult.Continue;
  }

  /**
   * @notice Runs after the policy check if the check was successful, and updates the transfer volume tracking for
   * the account. This function is called by the policy engine after run() succeeds but before the protected
   * target function executes.
   * @param parameters [from(address), amount(uint256)] The parameters of the called method.
   */
  function postRun(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata /*context*/
  )
    public
    override
    onlyPolicyEngine
  {
    (uint256 amount, address account) = _extractParameters(parameters);

    VolumeRatePolicyStorage storage $ = _getVolumeRatePolicyStorage(); // Gas optimization: single storage reference
    uint256 timePeriod = block.timestamp / $.timePeriodDuration;

    TransferredAt storage transferredAt = $.transferredAtByAmount[account];

    if (transferredAt.timePeriod == timePeriod && transferredAt.timePeriodDuration == $.timePeriodDuration) {
      transferredAt.amount += amount;
    } else {
      transferredAt.timePeriod = timePeriod;
      transferredAt.timePeriodDuration = $.timePeriodDuration;
      transferredAt.amount = amount;
    }
  }
}
