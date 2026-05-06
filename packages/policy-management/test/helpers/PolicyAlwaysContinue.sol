// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.20;

import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {Policy} from "../../src/core/Policy.sol";

contract PolicyAlwaysContinue is Policy {
  string public constant override typeAndVersion = "PolicyAlwaysContinue 1.0.0";

  function run(
    address,
    address,
    bytes4,
    bytes[] calldata,
    bytes calldata
  )
    public
    pure
    override
    returns (IPolicyEngine.PolicyResult)
  {
    return IPolicyEngine.PolicyResult.Continue;
  }
}
