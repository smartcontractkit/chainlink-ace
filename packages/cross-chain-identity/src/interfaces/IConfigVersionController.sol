// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

/**
 * @title IConfigVersionController
 * @notice Interface for version-checked configuration control.
 * @author Chainlink
 */
interface IConfigVersionController {
  /**
   * @notice Emitted whenever a configuration action is applied.
   * @param previousVersion The version before the configuration action.
   * @param newVersion The version after the configuration action.
   * @param selector The selector of the applied configuration action.
   * @param configCall The full ABI-encoded configuration call.
   */
  event ConfigurationUpdated(
    uint256 indexed previousVersion, uint256 indexed newVersion, bytes4 indexed selector, bytes configCall
  );

  /**
   * @notice Applies a configuration action after validating the current version.
   * @param expectedCurrentVersion The version the caller expects before applying the change.
   * @param configCall ABI-encoded call data for a supported configuration action.
   * @return newVersion The updated configuration version.
   */
  function configure(uint256 expectedCurrentVersion, bytes calldata configCall) external returns (uint256 newVersion);

  /**
   * @notice Returns the current configuration version.
   * @return The current version (1 after initializer completes; increments on each successful `configure`).
   */
  function getConfigVersion() external view returns (uint256);
}
