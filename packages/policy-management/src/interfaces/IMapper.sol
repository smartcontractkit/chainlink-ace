// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "./IPolicyEngine.sol";

/**
 * @title IMapper
 * @dev Interface for mapping extracted parameters to a list of policy parameters.
 */
interface IMapper {
  /**
   * @notice Maps extracted parameters to a list of policy parameters.
   * @param extractedParameters The extracted parameters.
   * @return The mapped parameters.
   */
  function map(IPolicyEngine.Parameter[] calldata extractedParameters) external view returns (bytes[] memory);
}
