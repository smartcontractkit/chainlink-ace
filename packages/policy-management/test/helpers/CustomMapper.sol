// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IMapper} from "../../src/interfaces/IMapper.sol";
import {IPolicyEngine} from "../../src/interfaces/IPolicyEngine.sol";

contract CustomMapper is IMapper {
  string public constant override typeAndVersion = "CustomMapper 1.0.0";

  bytes[] private s_mappedParameters;

  function setMappedParameters(bytes[] memory mappedParameters) public {
    s_mappedParameters = mappedParameters;
  }

  function map(IPolicyEngine.Parameter[] calldata /*extractedParameters*/ )
    external
    view
    override
    returns (bytes[] memory)
  {
    bytes[] memory results = new bytes[](s_mappedParameters.length);
    for (uint256 i = 0; i < s_mappedParameters.length; i++) {
      results[i] = s_mappedParameters[i];
    }
    return results;
  }
}
