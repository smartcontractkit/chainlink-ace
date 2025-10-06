// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

/**
 * @title ICredentialRequirements
 * @dev The interface for specifying the required credentials of an application/token.
 */
interface ICredentialRequirements {
  /// @notice Error emitted when a requirement already exists.
  error RequirementExists(bytes32 requirementId);
  /// @notice Error emitted when a requirement is not found.
  error RequirementNotFound(bytes32 requirementId);
  /// @notice Error emitted when a source has already been added.
  error SourceExists(bytes32 credentialTypeId, address identityRegistry, address credentialRegistry);
  /// @notice Error emitted when a credential source is not found.
  error CredentialSourceNotFound(bytes32 credentialTypeId, address identityRegistry, address credentialRegistry);
  /// @notice Error emitted when an invalid requirement configuration was attempted.
  error InvalidRequirementConfiguration(string errorReason);

  /**
   * @dev The struct for a credential requirement. A requirement is a common identifier that encompasses a list of
   * credentials that satisfies the requirement, how many validations are required of the credential.
   * A credential requirement could be 'invert'. This means that the requirement is satisfied if the credential
   * is not validated in the credential registry. This is useful for requirements that are satisfied by the absence of
   * a credential.
   */
  struct CredentialRequirement {
    bytes32[] credentialTypeIds;
    uint256 minValidations;
    bool invert;
  }

  /**
   * @dev The struct for a credential source. A `source` is an identity registry and credential registry pair. The
   * IIdentityRegistry maps local addresses to the common cross-chain identifier (CCID). The ICredentialRegistry
   * maps a CCID with one or more credentials, and each credential mapping can optionally have additional data.
   * A data validator contract can optionally be provided, and if present, is used to validate the data associated
   * with the credential.
   */
  struct CredentialSource {
    address identityRegistry;
    address credentialRegistry;
    address dataValidator;
  }

  /**
   * @dev The input struct used to add a new credential requirement.
   *
   * @param requirementId The identifier of the requirement.
   * @param credentialTypeIds The credential type identifier(s) that satisfy the requirement.
   * @param minValidations The minimum number of validations required for the requirement.
   * @param invert If the requirement is satisfied by the absence of all of the credential(s).
   */
  struct CredentialRequirementInput {
    bytes32 requirementId;
    bytes32[] credentialTypeIds;
    uint256 minValidations;
    bool invert;
  }

  /**
   * @dev The input struct used to add a new credential source.
   *
   * @param credentialTypeId The credential type identifier.
   * @param identityRegistry The address of the identity registry.
   * @param credentialRegistry The address of the credential registry.
   * @param dataValidator The address of the data validator contract.
   */
  struct CredentialSourceInput {
    bytes32 credentialTypeId;
    address identityRegistry;
    address credentialRegistry;
    address dataValidator;
  }

  /**
   * @notice Emitted when a new credential requirement is added.
   * @param requirementId The identifier of the requirement.
   * @param credentialTypeIds The credential type identifiers that satisfy the requirement.
   * @param minValidations The minimum number of validations required for the requirement.
   * @param invert Whether the requirement is satisfied by the absence of all of the credential(s).
   */
  event CredentialRequirementAdded(
    bytes32 indexed requirementId, bytes32[] credentialTypeIds, uint256 minValidations, bool invert
  );

  /**
   * @notice Emitted when a credential requirement is removed.
   * @param requirementId The identifier of the requirement.
   * @param credentialTypeIds The list of credential type identifiers that satisfy the requirement.
   * @param minValidations The minimum number of validations required for the requirement.
   * @param invert Whether the requirement was satisfied by the absence of all of the credential(s).
   */
  event CredentialRequirementRemoved(
    bytes32 indexed requirementId, bytes32[] credentialTypeIds, uint256 minValidations, bool invert
  );

  /**
   * @notice Emitted when a new credential source is added.
   * @param credentialTypeId The credential type identifier.
   * @param identityRegistry The address of the identity registry.
   * @param credentialRegistry The address of the credential registry.
   * @param dataValidator The address of the data validator contract.
   */
  event CredentialSourceAdded(
    bytes32 indexed credentialTypeId,
    address indexed identityRegistry,
    address indexed credentialRegistry,
    address dataValidator
  );

  /**
   * @notice Emitted when a credential source is removed.
   * @param credentialTypeId The credential type identifier.
   * @param identityRegistry The address of the identity registry.
   * @param credentialRegistry The address of the credential registry.
   * @param dataValidator The address of the data validator contract.
   */
  event CredentialSourceRemoved(
    bytes32 indexed credentialTypeId,
    address indexed identityRegistry,
    address indexed credentialRegistry,
    address dataValidator
  );

  /**
   * @notice Adds a new credential requirement.
   *
   * - MUST revert with `RequirementExists` if the requirement already exists.
   * - MUST emit the `CredentialRequirementAdded` event.
   *
   * @param CredentialRequirementInput The input struct used to add a new credential requirement.
   */
  function addCredentialRequirement(CredentialRequirementInput memory CredentialRequirementInput) external;

  /**
   * @notice Removes a credential requirement.
   *
   * - MUST revert with `RequirementNotFound` if the requirement does not exist.
   * - MUST emit the `CredentialRequirementRemoved` event.
   *
   * @param requirementId The identifier of the requirement.
   */
  function removeCredentialRequirement(bytes32 requirementId) external;

  /**
   * @notice Gets a credential requirement.
   * @param requirementId The identifier of the requirement.
   * @return The credential requirement.
   */
  function getCredentialRequirement(bytes32 requirementId) external view returns (CredentialRequirement memory);

  /**
   * @notice Get all of the credential requirement identifiers.
   * @return The credential requirement identifiers.
   */
  function getCredentialRequirementIds() external view returns (bytes32[] memory);

  /**
   * @notice Adds a new credential source.
   *
   * - MUST revert with `SourceExists` if the source already exists.
   * - MUST emit the `CredentialSourceAdded` event.
   *
   * @param CredentialSourceInput The input struct used to add a new credential source.
   */
  function addCredentialSource(CredentialSourceInput memory CredentialSourceInput) external;

  /**
   * @notice Removes a credential source.
   *
   * - MUST revert with `CredentialSourceNotFound` if the source does not exist.
   * - MUST emit the `CredentialSourceRemoved` event.
   *
   * @param credentialTypeId The credential type identifier.
   * @param identityRegistry The address of the identity registry.
   * @param credentialRegistry The address of the credential registry.
   */
  function removeCredentialSource(
    bytes32 credentialTypeId,
    address identityRegistry,
    address credentialRegistry
  )
    external;

  /**
   * @notice Gets all credential sources.
   * @param credentialTypeId The credential type identifier.
   * @return The credential sources.
   */
  function getCredentialSources(bytes32 credentialTypeId) external view returns (CredentialSource[] memory);
}
