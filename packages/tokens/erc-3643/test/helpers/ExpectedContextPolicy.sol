// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

contract ExpectedContextPolicy is Policy {
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
