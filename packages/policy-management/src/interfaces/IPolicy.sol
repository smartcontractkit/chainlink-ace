// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "./IPolicyEngine.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IPolicy
 * @dev Interface for running a policy.
 */
interface IPolicy is IERC165 {
  /**
   * @notice Hook called upon installation of the policy.
   * @param selector The selector of the policy.
   */
  function onInstall(bytes4 selector) external;

  /**
   * @notice Hook called upon uninstallation of the policy.
   * @param selector The selector of the policy.
   */
  function onUninstall(bytes4 selector) external;

  /**
   * @notice Runs the policy.
   * @param caller The address of the account which is calling the subject protected by the policy engine.
   * @param subject The address of the contract which is being protected by the policy engine.
   * @param selector The selector of the method being called on the protected contract.
   * @param parameters The parameters to use for running the policy.
   * @param context Additional information or authorization to perform the operation.
   * @return The result of running the policy.
   */
  function run(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] calldata parameters,
    bytes calldata context
  )
    external
    view
    returns (IPolicyEngine.PolicyResult);

  /**
   * @notice Runs after the policy check if the check was successful, and MAY mutate state. State mutations SHOULD
   * consider state relative to the target, as the policy MAY be shared across multiple targets.
   * @param caller The address of the account which is calling the subject protected by the policy engine.
   * @param subject The address of the contract which is being protected by the policy engine.
   * @param selector The selector of the method being called on the protected contract.
   * @param parameters The parameters to use for running the policy.
   * @param context Additional information or authorization to perform the operation.
   */
  function postRun(
    address caller,
    address subject,
    bytes4 selector,
    bytes[] calldata parameters,
    bytes calldata context
  )
    external;
}
