// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ICredentialRequirements} from "./ICredentialRequirements.sol";

interface IGroupedCredentialRequirements {
  enum RoutingKind {
    Attestation,
    Data
  }

  struct RoutingConfig {
    bytes32[] credentialTypeIds;
    RoutingKind kind;
    bytes32[] criteria;
    /// @notice Minimum number of distinct routing credential sources that must match before this group is selected.
    uint256 minValidations;
  }

  /// @notice Group creation input (routing only).
  struct GroupInput {
    bytes32 groupId;
    bytes32[] routingCredentialTypeIds;
    RoutingKind routingKind;
    bytes32[] routingCriteria;
    /// @notice Minimum routing matches required (distinct configured sources that satisfy routing rules).
    uint256 routingMinValidations;
  }

  /// @notice Group requirement creation input (flat, keyed by groupId).
  struct GroupRequirementInput {
    bytes32 groupId;
    bytes32 requirementId;
    bytes32[] credentialTypeIds;
    uint256 minValidations;
    bool invert;
  }

  /// @notice Group source creation input (flat, keyed by groupId).
  struct GroupSourceInput {
    bytes32 groupId;
    bytes32 credentialTypeId;
    address identityRegistry;
    address credentialRegistry;
    address dataValidator;
  }

  error GroupExists(bytes32 groupId);
  error GroupNotFound(bytes32 groupId);
  error InvalidGroupConfiguration(string reason);
  error RoutingOverlap(bytes32 compositeKey, bytes32 existingGroupId, bytes32 newGroupId);
  error MaxGroupsReached();
  error MultipleSourcesForDataRouting(bytes32 groupId, bytes32 credentialTypeId);

  /**
   * @notice Adds a credential validation group.
   * @param input Group routing to add.
   */
  function addGroup(GroupInput calldata input) external;

  /**
   * @notice Removes a credential validation group.
   * @param groupId The group identifier to remove.
   */
  function removeGroup(bytes32 groupId) external;

  /**
   * @notice Updates the routing configuration for a credential validation group.
   * @param groupId The group identifier to update.
   * @param routing The new routing configuration.
   */
  function updateGroupRouting(bytes32 groupId, RoutingConfig calldata routing) external;

  /**
   * @notice Adds a credential requirement to a group.
   * @param groupId The group identifier to add the requirement to.
   * @param requirementId The credential requirement identifier.
   * @param credentialTypeIds The credential type IDs that satisfy this requirement.
   * @param minValidations The minimum number of validations required.
   * @param invert Whether the requirement is inverted.
   */
  function addGroupRequirement(
    bytes32 groupId,
    bytes32 requirementId,
    bytes32[] calldata credentialTypeIds,
    uint256 minValidations,
    bool invert
  )
    external;

  /**
   * @notice Removes a credential requirement from a group.
   * @param groupId The group identifier to remove the requirement from.
   * @param requirementId The requirement identifier to remove.
   */
  function removeGroupRequirement(bytes32 groupId, bytes32 requirementId) external;

  /**
   * @notice Adds a credential source to a group.
   * @param groupId The group identifier to add the source to.
   * @param credentialTypeId The credential type identifier for the source.
   * @param identityRegistry The identity registry address for the source.
   * @param credentialRegistry The credential registry address for the source.
   * @param dataValidator The optional data validator address for the source.
   */
  function addGroupSource(
    bytes32 groupId,
    bytes32 credentialTypeId,
    address identityRegistry,
    address credentialRegistry,
    address dataValidator
  )
    external;

  /**
   * @notice Removes a credential source from a group.
   * @param groupId The group identifier to remove the source from.
   * @param credentialTypeId The credential type identifier for the source.
   * @param identityRegistry The identity registry address for the source.
   * @param credentialRegistry The credential registry address for the source.
   */
  function removeGroupSource(
    bytes32 groupId,
    bytes32 credentialTypeId,
    address identityRegistry,
    address credentialRegistry
  )
    external;

  /**
   * @notice Gets all configured group identifiers.
   * @return groupIds The configured group identifiers.
   */
  function getGroupIds() external view returns (bytes32[] memory);

  /**
   * @notice Gets the routing configuration for a group.
   * @param groupId The group identifier to query.
   * @return routing The group's routing configuration.
   */
  function getGroupRouting(bytes32 groupId) external view returns (RoutingConfig memory);

  /**
   * @notice Gets all credential requirement identifiers for a group.
   * @param groupId The group identifier to query.
   * @return requirementIds The group credential requirement identifiers.
   */
  function getGroupRequirementIds(bytes32 groupId) external view returns (bytes32[] memory);

  /**
   * @notice Gets a credential requirement from a group.
   * @param groupId The group identifier to query.
   * @param requirementId The requirement identifier to query.
   * @return requirement The group's credential requirement.
   */
  function getGroupRequirement(
    bytes32 groupId,
    bytes32 requirementId
  )
    external
    view
    returns (ICredentialRequirements.CredentialRequirement memory);

  /**
   * @notice Gets credential sources for a group and credential type.
   * @param groupId The group identifier to query.
   * @param credentialTypeId The credential type identifier to query.
   * @return sources The configured credential sources.
   */
  function getGroupSources(
    bytes32 groupId,
    bytes32 credentialTypeId
  )
    external
    view
    returns (ICredentialRequirements.CredentialSource[] memory);

  event GroupAdded(bytes32 indexed groupId, RoutingConfig routing);
  event GroupRemoved(bytes32 indexed groupId);
  event GroupRoutingUpdated(bytes32 indexed groupId, RoutingConfig oldRouting, RoutingConfig newRouting);

  event GroupCredentialRequirementAdded(
    bytes32 indexed groupId,
    bytes32 indexed requirementId,
    bytes32[] credentialTypeIds,
    uint256 minValidations,
    bool invert
  );
  event GroupCredentialRequirementRemoved(
    bytes32 indexed groupId,
    bytes32 indexed requirementId,
    bytes32[] credentialTypeIds,
    uint256 minValidations,
    bool invert
  );
  event GroupCredentialSourceAdded(
    bytes32 indexed groupId,
    bytes32 indexed credentialTypeId,
    address indexed identityRegistry,
    address credentialRegistry,
    address dataValidator
  );
  event GroupCredentialSourceRemoved(
    bytes32 indexed groupId,
    bytes32 indexed credentialTypeId,
    address indexed identityRegistry,
    address credentialRegistry,
    address dataValidator
  );
}
