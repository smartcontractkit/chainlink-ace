// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "./IPolicyEngine.sol";

/**
 * @title IExtractor
 * @dev Interface for extracting parameters from a payload.
 */
interface IExtractor {
  /**
   * @notice Extracts parameters from a payload.
   * @param payload The payload to extract parameters from.
   * @return The extracted parameters.
   */
  function extract(IPolicyEngine.Payload calldata payload) external view returns (IPolicyEngine.Parameter[] memory);
}
