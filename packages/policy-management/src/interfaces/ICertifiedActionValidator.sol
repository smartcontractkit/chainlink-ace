// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

interface ICertifiedActionValidator {
  struct Permit {
    bytes32 permitId;
    address caller;
    address subject;
    bytes4 selector;
    bytes[] parameters;
    bytes metadata;
    uint64 maxUses;
    uint48 expiry;
  }

  struct SignedPermit {
    Permit permit;
    bytes signature;
  }

  /**
   * @notice Emitted when an issuer is allowed to sign permits.
   * @param issuerKey The key of the issuer.
   */
  event IssuerAllowed(bytes issuerKey);

  /**
   * @notice Emitted when an issuer is disallowed from signing permits.
   * @param issuerKey The key of the issuer.
   */
  event IssuerDisAllowed(bytes issuerKey);

  /**
   * @notice Emitted when a permit is stored.
   * @param permitId The ID of the permit.
   */
  event PermitStored(bytes32 indexed permitId);

  /**
   * @notice Emitted when a permit is used.
   * @param permitId The ID of the permit.
   */
  event PermitUsed(bytes32 indexed permitId);

  /**
   * @notice Emitted when a permit is revoked.
   * @param permitId The ID of the permit.
   */
  event PermitRevoked(bytes32 indexed permitId);

  /// @notice Error emitted when a permit signature is invalid.
  error InvalidSignature(bytes32 permitId);
  /// @notice Error emitted when a permit has expired.
  error PermitExpired(bytes32 permitId, uint48 expiration);
  /// @notice Error emitted when an issuer is already allowed or disallowed.
  error IssuerAllowedAlreadySet(bytes issuerKey, bool allowed);
  /// @notice Error emitted when a permit has already been presented.
  error PermitAlreadyPresented(bytes32 permitId);
  /// @notice Error emitted when a permit has been revoked.
  error PermitAlreadyRevoked(bytes32 permitId);

  /**
   * @notice Presents and stores a permit in the validator. Since only 1 valid permit for the same intent is allowed,
   * presenting a new permit will override any previous permit for the same intent. Note that the act of presenting a
   * permit override any ability for a context permit for the same intent.
   * @param permit The permit to present.
   * @param signature The signature of the permit.
   */
  function present(Permit calldata permit, bytes calldata signature) external;

  /**
   * @notice Checks if a permit is valid.
   * @param permit The permit to check.
   * @param signature The signature of the permit.
   * @return True if the permit is valid, false otherwise.
   */
  function check(Permit calldata permit, bytes calldata signature) external view returns (bool);

  /**
   * @notice Revokes a permit.
   * @param permitId The ID of the permit to revoke.
   */
  function revoke(bytes32 permitId) external;

  /**
   * @notice Gets the usage count of a permit.
   * @param permitId The ID of the permit.
   * @return The usage count of the permit.
   */
  function getUsage(bytes32 permitId) external view returns (uint256);

  /**
   * @notice Allows an issuer to sign permits.
   * @param issuerKey The key of the issuer.
   */
  function allowIssuer(bytes calldata issuerKey) external;

  /**
   * @notice Disallows an issuer from signing permits.
   * @param issuerKey The key of the issuer.
   */
  function disAllowIssuer(bytes calldata issuerKey) external;

  /**
   * @notice Gets if an issuer is allowed to sign permits.
   * @param issuerKey The key of the issuer.
   * @return True if the issuer is allowed, false otherwise.
   */
  function getIssuerAllowed(bytes calldata issuerKey) external view returns (bool);
}
