// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "../../src/interfaces/IExtractor.sol";
import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";
import {MockToken} from "./MockToken.sol";

contract MockTokenExtractor is IExtractor {
  bytes32 public constant PARAM_FROM = keccak256("from");
  bytes32 public constant PARAM_TO = keccak256("to");
  bytes32 public constant PARAM_AMOUNT = keccak256("amount");

  function extract(IPolicyEngine.Payload calldata payload) public pure returns (IPolicyEngine.Parameter[] memory) {
    address from = address(0);
    address to = address(0);
    uint256 amount = 0;

    if (payload.selector == MockToken.transfer.selector || payload.selector == MockToken.transferWithContext.selector) {
      from = payload.sender;
      (to, amount) = abi.decode(payload.data, (address, uint256));
    } else if (payload.selector == MockToken.transferFrom.selector) {
      (from, to, amount) = abi.decode(payload.data, (address, address, uint256));
    } else {
      revert IPolicyEngine.UnsupportedSelector(payload.selector);
    }

    IPolicyEngine.Parameter[] memory result = new IPolicyEngine.Parameter[](3);
    result[0] = IPolicyEngine.Parameter(PARAM_FROM, abi.encode(from));
    result[1] = IPolicyEngine.Parameter(PARAM_TO, abi.encode(to));
    result[2] = IPolicyEngine.Parameter(PARAM_AMOUNT, abi.encode(amount));

    return result;
  }
}
