// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {Policy} from "../core/Policy.sol";

/**
 * @title OnlyOwnerPolicy
 * @notice A policy that only allows the policy owner to call the method, similar to `Ownable` from OpenZeppelin.
 */
contract OnlyOwnerPolicy is Policy {
  function run(
    address caller,
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
    // expected parameters: none
    // solhint-disable-next-line gas-custom-errors
    if (parameters.length != 0) {
      revert IPolicyEngine.InvalidConfiguration("expected 0 parameters");
    }

    if (caller != owner()) {
      revert IPolicyEngine.PolicyRejected("caller is not the policy owner");
    }
    return IPolicyEngine.PolicyResult.Continue;
  }
}
