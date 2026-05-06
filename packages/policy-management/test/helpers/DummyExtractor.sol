// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IExtractor} from "../../src/interfaces/IExtractor.sol";
import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";

contract DummyExtractor is IExtractor {
  string public constant override typeAndVersion = "DummyExtractor 1.0.0";

  function extract(IPolicyEngine.Payload calldata) external pure override returns (IPolicyEngine.Parameter[] memory) {
    return new IPolicyEngine.Parameter[](0);
  }
}
