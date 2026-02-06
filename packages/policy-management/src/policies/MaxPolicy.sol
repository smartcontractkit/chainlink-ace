// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {Policy} from "../core/Policy.sol";

/**
 * @title MaxPolicy
 * @notice A policy that rejects requests if the maximum amount is exceeded (amount does not accumulate between calls).
 */
contract MaxPolicy is Policy {
  string public constant override typeAndVersion = "MaxPolicy 1.0.0";

  /// @custom:storage-location erc7201:chainlink.ace.MaxPolicy
  struct MaxPolicyStorage {
    uint256 max;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.MaxPolicy")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant MaxPolicyStorageLocation = 0x02973c4e98711cfb712c36db17418ada2bb95a6216267426efdf4ae114fe9a00;

  function _getMaxPolicyStorage() private pure returns (MaxPolicyStorage storage $) {
    assembly {
      $.slot := MaxPolicyStorageLocation
    }
  }

  /**
   * @notice Configures the policy with a maximum threshold.
   * @dev The `parameters` input must be the ABI encoding of a single unsigned integer (`uint256`).
   *
   * @param parameters ABI-encoded bytes containing a single `uint256` representing the maximum value.
   */
  function configure(bytes calldata parameters) internal override onlyInitializing {
    MaxPolicyStorage storage $ = _getMaxPolicyStorage();
    uint256 max = abi.decode(parameters, (uint256));
    $.max = max;
  }

  function setMax(uint256 max) public onlyOwner {
    MaxPolicyStorage storage $ = _getMaxPolicyStorage();
    $.max = max;
  }

  function getMax() public view returns (uint256) {
    MaxPolicyStorage storage $ = _getMaxPolicyStorage();
    return $.max;
  }

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
    // expected parameters: [size(uint256)]
    // solhint-disable-next-line gas-custom-errors
    if (parameters.length != 1) {
      revert InvalidParameters("expected 1 parameter");
    }
    uint256 size = abi.decode(parameters[0], (uint256));

    MaxPolicyStorage storage $ = _getMaxPolicyStorage();
    if (size > $.max) {
      revert IPolicyEngine.PolicyRejected("amount exceeds maximum limit");
    }
    return IPolicyEngine.PolicyResult.Continue;
  }
}
