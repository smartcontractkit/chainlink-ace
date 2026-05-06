// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title IntervalPolicy
 * @notice A policy that enforces execution within specific time intervals, based on configurable time slots.
 * @dev Implements Chainlink's `Policy` interface and OpenZeppelin's `Ownable` for access control.
 *      The policy checks whether the current time slot falls within a configured start slot and end slot
 *      in a repeating cycle.
 *
 * ## Core Parameters
 *
 * - `s_slotDuration`: The duration (in seconds) of each individual slot. For instance, 3600 for a 1-hour slot.
 * - `s_cycleSize`: The total number of slots in each repeating cycle (e.g., 24 slots for a daily cycle).
 * - `s_cycleOffset`: An offset (in “slots”) added to the cycle when computing the current slot.
 * - `s_startSlot`: The lowest (inclusive) slot index within the cycle for which execution is allowed.
 * - `s_endSlot`: The highest (exclusive) slot index within the cycle for which execution is allowed.
 *
 * Each cycle is effectively indexed from `0` to `s_cycleSize - 1`. The policy “resets” back to slot 0
 * after `s_cycleSize` slots, repeating indefinitely.
 *
 * ## Example Usages
 *
 * ### 1. Hour-Based Execution (Daily Cycle)
 * ```
 * IntervalPolicy(11, 17, 3600, 24, 0)
 * ```
 * - `s_cycleSize = 24`, corresponding to the 24 hours in a day.
 * - Execution is allowed from slot `11` (which corresponds to ~ 11:00 UTC) to slot `17` (~17:00 UTC).
 *
 * ### 2. Day-Based Execution (Weekly Cycle)
 * ```
 * IntervalPolicy(1, 6, 86400, 7, 4)
 * ```
 * - `s_cycleSize = 7`, a weekly cycle (one slot per day).
 * - Execution is allowed from slot `1` (Monday) to slot `6` (Saturday),
 *   with a 4-slot offset, effectively shifting the cycle start.
 */
contract IntervalPolicy is Policy {
  string public constant override typeAndVersion = "IntervalPolicy 1.0.0";

  /**
   * @notice Emitted when the start slot is updated.
   * @param startSlot The new start slot (inclusive).
   */
  event StartSlotSet(uint256 startSlot);

  /**
   * @notice Emitted when the end slot is updated.
   * @param endSlot The new end slot (exclusive).
   */
  event EndSlotSet(uint256 endSlot);

  /**
   * @notice Emitted when cycle parameters are updated.
   * @param slotDuration The duration (in seconds) of each slot.
   * @param cycleSize The total number of slots in each repeating cycle.
   * @param cycleOffset The offset (in slots) applied when computing the current slot index.
   */
  event CycleParametersSet(uint256 slotDuration, uint256 cycleSize, uint256 cycleOffset);

  /**
   * @notice The cycle parameters for the interval policy.
   * @param slotDuration Duration (in seconds) of each slot (e.g., 3600 for 1 hour, 86400 for 1 day).
   * @param cycleSize Total count of slots in each repeating cycle (e.g., 24 for daily hours, 7 for days in a week).
   * @param cycleOffset An offset (in slots) added to the computed slot index before taking modulo `cycleSize`.
   */
  struct CycleParameters {
    uint256 slotDuration;
    uint256 cycleSize;
    uint256 cycleOffset;
  }

  /// @custom:storage-location erc7201:chainlink.ace.IntervalPolicy
  struct IntervalPolicyStorage {
    /// @notice Cycle parameters (slot duration, cycle size, and cycle offset).
    CycleParameters cycleParams;
    /// @notice Starting slot index (inclusive) within the cycle where execution is allowed.
    uint256 startSlot;
    /// @notice Ending slot index (exclusive) within the cycle where execution is allowed.
    uint256 endSlot;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.IntervalPolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant IntervalPolicyStorageLocation =
    0xf4d2d1ec39bef5e25c2fa41ecc5189c68f679323f7f598f7e6231997bb5b8700;

  function _getIntervalPolicyStorage() private pure returns (IntervalPolicyStorage storage $) {
    assembly {
      $.slot := IntervalPolicyStorageLocation
    }
  }

  /**
   * @notice Configures the policy with the specified parameters.
   * @dev The `parameters` input must be the ABI encoding of the following:
   *      - startSlot (uint256)
   *      - endSlot (uint256)
   *      - CycleParameters struct
   *
   * @param parameters ABI-encoded bytes containing the configuration parameters.
   */
  function configure(bytes calldata parameters) internal override onlyInitializing {
    IntervalPolicyStorage storage $ = _getIntervalPolicyStorage();
    (uint256 startSlot, uint256 endSlot, CycleParameters memory cycleParams) =
      abi.decode(parameters, (uint256, uint256, CycleParameters));

    require(startSlot < endSlot, "End slot must be greater than start slot");
    require(cycleParams.cycleSize > 0, "Cycle size must be > 0");
    require(endSlot <= cycleParams.cycleSize, "Cycle size must be >= end slot");
    require(cycleParams.slotDuration > 0, "Slot duration must be > 0");
    require(cycleParams.cycleOffset < cycleParams.cycleSize, "Cycle offset must be < cycle size");

    $.startSlot = startSlot;
    $.endSlot = endSlot;
    $.cycleParams = cycleParams;

    emit StartSlotSet(startSlot);
    emit EndSlotSet(endSlot);
    emit CycleParametersSet(cycleParams.slotDuration, cycleParams.cycleSize, cycleParams.cycleOffset);
  }

  /**
   * @notice Updates the start slot within the cycle.
   * @dev Must be less than the current end slot. Only callable by the owner.
   * @param startSlot The new start slot (inclusive).
   */
  function setStartSlot(uint256 startSlot) public onlyOwner {
    IntervalPolicyStorage storage $ = _getIntervalPolicyStorage();
    require(startSlot < $.endSlot, "New start slot must be < end slot");
    $.startSlot = startSlot;
    emit StartSlotSet(startSlot);
  }

  /**
   * @notice Updates the end slot within the cycle.
   * @dev Must be greater than the current start slot and less than the cycle size. Only callable by the owner.
   * @param endSlot The new end slot (exclusive).
   */
  function setEndSlot(uint256 endSlot) public onlyOwner {
    IntervalPolicyStorage storage $ = _getIntervalPolicyStorage();
    require(endSlot > $.startSlot, "End slot must be greater than start slot");
    require(endSlot <= $.cycleParams.cycleSize, "End slot must be <= cycle size");
    $.endSlot = endSlot;
    emit EndSlotSet(endSlot);
  }

  /**
   * @notice Updates the slot duration, cycle size, and cycle offset parameters.
   * @dev Ensures the current `s_endSlot` remains valid under the new cycle size. Only callable by owner.
   * @param slotDuration  The duration of each slot in seconds. Must be > 0.
   * @param cycleSize     The total number of slots in each cycle. Must be > current `s_endSlot`.
   * @param cycleOffset   The offset (in slots) applied to the computed time slot. Must be < `cycleSize`.
   */
  function setCycleParameters(uint256 slotDuration, uint256 cycleSize, uint256 cycleOffset) public onlyOwner {
    IntervalPolicyStorage storage $ = _getIntervalPolicyStorage();
    require(slotDuration > 0, "Slot duration must be > 0");
    require(cycleSize >= $.endSlot, "New cycle size must be >= end slot");
    require(cycleOffset < cycleSize, "Cycle offset must be < cycle size");

    $.cycleParams.slotDuration = slotDuration;
    $.cycleParams.cycleSize = cycleSize;
    $.cycleParams.cycleOffset = cycleOffset;
    emit CycleParametersSet(slotDuration, cycleSize, cycleOffset);
  }

  /**
   * @notice Retrieves the current start slot within the cycle.
   * @return The start slot index (inclusive).
   */
  function getStartSlot() public view returns (uint256) {
    IntervalPolicyStorage storage $ = _getIntervalPolicyStorage();
    return $.startSlot;
  }

  /**
   * @notice Retrieves the current end slot within the cycle.
   * @return The end slot index (exclusive).
   */
  function getEndSlot() public view returns (uint256) {
    IntervalPolicyStorage storage $ = _getIntervalPolicyStorage();
    return $.endSlot;
  }

  /**
   * @notice Retrieves the cycle parameters.
   * @return slotDuration The duration (in seconds) of each slot.
   * @return cycleSize    The total number of slots in each repeating cycle.
   * @return cycleOffset  The offset (in slots) applied when computing the current slot index.
   */
  function getCycleParameters() public view returns (uint256 slotDuration, uint256 cycleSize, uint256 cycleOffset) {
    IntervalPolicyStorage storage $ = _getIntervalPolicyStorage();
    return ($.cycleParams.slotDuration, $.cycleParams.cycleSize, $.cycleParams.cycleOffset);
  }

  /**
   * @notice Determines whether execution is allowed based on the current slot and configured start/end slots.
   * @param caller      The account attempting to run the policy (unused).
   * @param subject     The protected contract of the policy call (unused).
   * @param parameters  Additional parameters (unused).
   * @param context     Additional context (unused).
   *
   * @return A PolicyResult enum indicating `Continue` if the current slot is within [startSlot, endSlot),
   *         or `Rejected` otherwise.
   */
  function run(
    address caller,
    address subject,
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata context
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    // Unused in this specific policy
    caller;
    subject;
    parameters;
    context;

    // Gas optimization: load storage reference once
    IntervalPolicyStorage storage $ = _getIntervalPolicyStorage();

    // calculate the current slot in an overflow-safe way
    uint256 base = (block.timestamp / $.cycleParams.slotDuration) % $.cycleParams.cycleSize;
    uint256 currentSlot = addmod(base, $.cycleParams.cycleOffset, $.cycleParams.cycleSize);

    if (currentSlot >= $.startSlot && currentSlot < $.endSlot) {
      return IPolicyEngine.PolicyResult.Continue;
    }
    revert IPolicyEngine.PolicyRejected("execution outside allowed time interval");
  }
}
