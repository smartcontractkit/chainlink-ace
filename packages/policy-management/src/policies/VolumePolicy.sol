// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title VolumePolicy
 * @notice A policy that validates transaction amount parameters against configured minimum and maximum limits.
 * @dev This policy operates on the amount argument passed to protected functions, not on actual token transfers.
 * For tokens with transfer fees, deflationary mechanisms, or other non-standard behaviors, the actual transferred
 * amount may differ from the amount parameter this policy validates against.
 */
contract VolumePolicy is Policy {
  /**
   * @notice Emitted when the maximum volume limit is set.
   * @param maxAmount The maximum amount parameter limit. If set to 0, there is no maximum limit.
   */
  event MaxVolumeSet(uint256 maxAmount);
  /**
   * @notice Emitted when the minimum volume limit is set.
   * @param minAmount The minimum amount parameter limit. If set to 0, there is no minimum limit.
   */
  event MinVolumeSet(uint256 minAmount);

  /// @custom:storage-location erc7201:policy-management.VolumePolicy
  struct VolumePolicyStorage {
    /// @notice The maximum amount parameter limit. If set to 0, there is no maximum limit.
    uint256 maxAmount;
    /// @notice The minimum amount parameter limit. If set to 0, there is no minimum limit.
    uint256 minAmount;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.VolumePolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant VolumePolicyStorageLocation =
    0x5bb13fe9284039d01609a8e5ed913ad65a3c270b5906b4fd9932815137778200;

  function _getVolumePolicyStorage() private pure returns (VolumePolicyStorage storage $) {
    assembly {
      $.slot := VolumePolicyStorageLocation
    }
  }

  /**
   * @notice Configures the policy by setting minimum and maximum amount parameter limits.
   * @param parameters ABI-encoded bytes containing two `uint256` values: the min and max amount limits.
   *      - `minAmount`: The minimum amount parameter limit, 0 for no minimum.
   *      - `maxAmount`: The maximum amount parameter limit, 0 for no maximum.
   * @dev These limits apply to function parameters, not actual token transfer amounts.
   */
  function configure(bytes calldata parameters) internal override {
    VolumePolicyStorage storage $ = _getVolumePolicyStorage();
    ($.minAmount, $.maxAmount) = abi.decode(parameters, (uint256, uint256));
    require($.maxAmount > $.minAmount || $.maxAmount == 0, "maxAmount must be greater than minAmount");
  }

  /**
   * @notice Sets the maximum amount parameter limit for the policy.
   * @param maxAmount The maximum amount parameter limit.
   * @dev Reverts if the new max amount is less than or equal to the min amount (unless maxAmount is 0),
   * or if it is the same as the current max amount.
   */
  function setMax(uint256 maxAmount) public onlyOwner {
    VolumePolicyStorage storage $ = _getVolumePolicyStorage();
    require(maxAmount > $.minAmount || maxAmount == 0, "maxAmount must be greater than minAmount");
    require(maxAmount != $.maxAmount, "maxAmount cannot be the same as current maxAmount");
    $.maxAmount = maxAmount;
    emit MaxVolumeSet(maxAmount);
  }

  /**
   * @notice Gets the current maximum amount parameter limit for the policy.
   * @return maxAmount The current maximum amount parameter limit. If 0, there is no maximum limit.
   */
  function getMax() public view returns (uint256) {
    VolumePolicyStorage storage $ = _getVolumePolicyStorage();
    return $.maxAmount;
  }

  /**
   * @notice Sets the minimum amount parameter limit for the policy.
   * @param minAmount The minimum amount parameter limit.
   * @dev Reverts if the new min amount is greater than or equal to the max amount (unless maxAmount is 0),
   * or if it is the same as the current min amount.
   */
  function setMin(uint256 minAmount) public onlyOwner {
    VolumePolicyStorage storage $ = _getVolumePolicyStorage();
    require(minAmount < $.maxAmount || $.maxAmount == 0, "minAmount must be less than maxAmount");
    require(minAmount != $.minAmount, "minAmount cannot be the same as current minAmount");
    $.minAmount = minAmount;
    emit MinVolumeSet(minAmount);
  }

  /**
   * @notice Gets the current minimum amount parameter limit for the policy.
   * @return minAmount The current minimum amount parameter limit. If 0, there is no minimum limit.
   */
  function getMin() public view returns (uint256) {
    VolumePolicyStorage storage $ = _getVolumePolicyStorage();
    return $.minAmount;
  }

  /**
   * @notice Function called by the policy engine to validate amount parameters against configured limits.
   * @param parameters [amount(uint256)] The parameters of the called method.
   * @return result The result of the policy check.
   * @dev This policy validates the amount argument passed to a protected function, not actual token transfers.
   * For tokens with fees, rebasing, or other non-standard behaviors, the actual transferred amount may differ.
   */
  function run(
    address, /* caller */
    address, /* subject */
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata /* context */
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    require(parameters.length == 1, "expected 1 parameter");
    uint256 amount = abi.decode(parameters[0], (uint256));

    // Gas optimization: load storage reference once
    VolumePolicyStorage storage $ = _getVolumePolicyStorage();
    if (($.maxAmount != 0 && amount > $.maxAmount) || amount < $.minAmount) {
      revert IPolicyEngine.PolicyRejected("amount outside allowed volume limits");
    }

    return IPolicyEngine.PolicyResult.Continue;
  }
}
