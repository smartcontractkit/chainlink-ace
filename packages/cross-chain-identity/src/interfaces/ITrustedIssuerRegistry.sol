// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

/**
 * @title ITrustedIssuerRegistry
 * @dev Interface for managing trusted issuers in the system.
 */
interface ITrustedIssuerRegistry {
  // ------------------------------------------------------------------------
  // Events
  // ------------------------------------------------------------------------

  /**
   * @notice Emitted when a new trusted issuer is added.
   * @param issuerIdHash The keccak256 hash of the issuerId string (indexed for filtering).
   * @param issuerId The original issuerId string (human-readable, not indexed).
   */
  event TrustedIssuerAdded(bytes32 indexed issuerIdHash, string issuerId);

  /**
   * @notice Emitted when a trusted issuer is removed.
   * @param issuerIdHash The keccak256 hash of the issuerId string (indexed for filtering).
   * @param issuerId The original issuerId string (human-readable, not indexed).
   */
  event TrustedIssuerRemoved(bytes32 indexed issuerIdHash, string issuerId);

  // ------------------------------------------------------------------------
  // Logic
  // ------------------------------------------------------------------------

  /**
   * @notice Adds a new trusted issuer.
   * @param issuerId The issuerId string of the issuer.
   * @param context Additional information or authorization to perform the operation.
   */
  function addTrustedIssuer(string memory issuerId, bytes calldata context) external;

  /**
   * @notice Removes a trusted issuer.
   * @param issuerId The issuerId string of the issuer to remove.
   * @param context Additional information or authorization to perform the operation.
   */
  function removeTrustedIssuer(string memory issuerId, bytes calldata context) external;

  // ------------------------------------------------------------------------
  // View
  // ------------------------------------------------------------------------

  /**
   * @notice Checks if a issuerId corresponds to a trusted issuer.
   * @param issuerId The issuerId string to check.
   * @return True if the issuerId is trusted, false otherwise.
   */
  function isTrustedIssuer(string memory issuerId) external view returns (bool);

  /**
   * @notice Returns the list of all trusted issuer identifiers (hashed).
   * @return An array of keccak256 hashes of trusted issuerIds.
   */
  function getTrustedIssuers() external view returns (bytes32[] memory);
}
