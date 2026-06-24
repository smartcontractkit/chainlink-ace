// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../../../../policy-management/src/interfaces/IPolicyEngine.sol";
import {Policy} from "../../../../policy-management/src/core/Policy.sol";

contract ExpectedContextPolicy is Policy {
  string public constant override typeAndVersion = "ExpectedContextPolicy 1.1.1";

  bytes private s_expectedContext;

  function configure(bytes calldata parameters) internal override onlyInitializing {
    bytes memory expectedContext = abi.decode(parameters, (bytes));
    s_expectedContext = expectedContext;
  }

  function run(
    address,
    address,
    bytes4,
    bytes[] calldata,
    bytes calldata context
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    if (keccak256(s_expectedContext) == keccak256(context)) {
      return IPolicyEngine.PolicyResult.Continue;
    }
    revert IPolicyEngine.PolicyRejected("context does not match expected value");
  }
}
