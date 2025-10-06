// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IPolicyProtected
 * @dev Interface for attaching a policy engine to a smart contract.
 */
interface IPolicyProtected is IERC165 {
  /**
   * @notice Emitted when a policy engine is attached to the contract.
   * @param policyEngine The policy engine attached.
   */
  event PolicyEngineAttached(address indexed policyEngine);

  /**
   * @notice Attaches a policy engine to the current contract.
   * @param policyEngine The policy engine to attach.
   */
  function attachPolicyEngine(address policyEngine) external;

  /**
   * @notice Gets the policy engine attached to the current contract.
   * @return The policy engine attached to the contract.
   */
  function getPolicyEngine() external view returns (address);

  /**
   * @notice Sets the context for the current transaction.
   * @dev WARNING: The context is stored per sender and is not automatically linked to a specific transaction or
   * function call. Ensure that context is set and consumed atomically and that race conditions or reentrancy do not
   * result in stale or mismatched context usage.
   * @param context The context to set.
   */
  function setContext(bytes calldata context) external;

  /**
   * @notice Gets the context for the current transaction.
   * @return The context for the transaction.
   */
  function getContext() external view returns (bytes memory);

  /**
   * @notice Clears the context for the current transaction.
   */
  function clearContext() external;
}
