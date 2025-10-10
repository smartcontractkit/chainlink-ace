// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

/**
 * @title PausePolicy
 * @notice A policy that can be toggled to pause or unpause execution.
 */
contract PausePolicy is Policy {
  /// @custom:storage-location erc7201:policy-management.PausePolicy
  struct PausePolicyStorage {
    /// @notice Indicates whether the policy is currently paused.
    bool paused;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.PausePolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant PausePolicyStorageLocation =
    0xaefcbf6c17ae27ba80ec8ef292ac0e1afc8fd1fc954a25eef0882c51e609eb00;

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

  /// @notice Sets the paused state of the policy.
  function pause() public onlyOwner {
    PausePolicyStorage storage $ = _getPausePolicyStorage();
    require(!$.paused, "already paused");
    $.paused = true;
  }

  /// @notice Sets the paused state of the policy to false.
  function unpause() public onlyOwner {
    PausePolicyStorage storage $ = _getPausePolicyStorage();
    require($.paused, "already unpaused");
    $.paused = false;
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
