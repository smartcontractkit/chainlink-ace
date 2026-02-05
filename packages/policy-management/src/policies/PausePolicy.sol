// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title PausePolicy
 * @notice A policy that can be toggled to pause or unpause execution.
 */
contract PausePolicy is Policy {
  string public constant override typeAndVersion = "PausePolicy 1.0.0";

  /**
   * @notice Emitted when the pause state of the policy is changed.
   * @param paused The new paused state of the policy.
   */
  event PauseStateChanged(bool indexed paused);

  /// @custom:storage-location erc7201:chainlink.ace.PausePolicy
  struct PausePolicyStorage {
    /// @notice Indicates whether the policy is currently paused.
    bool paused;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.PausePolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant PausePolicyStorageLocation =
    0x01c1af587392cfb490379a9a612447321a931c0d85a3a629efe3ab1cd68d0200;

  function _getPausePolicyStorage() private pure returns (PausePolicyStorage storage $) {
    assembly {
      $.slot := PausePolicyStorageLocation
    }
  }

  /// @notice Returns whether the policy is currently paused.
  function s_paused() public view returns (bool) {
    PausePolicyStorage storage $ = _getPausePolicyStorage();
    return $.paused;
  }

  /**
   * @notice Configures the policy with a paused state.
   * @dev This function follows OZ's initializable pattern and should be called only once.
   *      param _paused(bool)        The initial paused state of the policy.
   */
  function configure(bytes calldata parameters) internal override onlyInitializing {
    PausePolicyStorage storage $ = _getPausePolicyStorage();
    $.paused = abi.decode(parameters, (bool));
  }

  function setPausedState(bool paused) public onlyOwner {
    PausePolicyStorage storage $ = _getPausePolicyStorage();
    require($.paused != paused, "new paused state must be different from current paused state");
    $.paused = paused;
    emit PauseStateChanged($.paused);
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @return result The result of the policy check.
   */
  function run(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata, /*parameters*/
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    // Gas optimization: load storage reference once
    PausePolicyStorage storage $ = _getPausePolicyStorage();
    if ($.paused) {
      revert IPolicyEngine.PolicyRejected("contract is paused");
    } else {
      return IPolicyEngine.PolicyResult.Continue;
    }
  }
}
