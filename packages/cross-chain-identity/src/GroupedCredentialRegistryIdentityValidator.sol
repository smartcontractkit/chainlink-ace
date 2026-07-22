// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ICredentialDataValidator} from "./interfaces/ICredentialDataValidator.sol";
import {ICredentialRegistry} from "./interfaces/ICredentialRegistry.sol";
import {ICredentialRequirements} from "./interfaces/ICredentialRequirements.sol";
import {IGroupedCredentialRequirements} from "./interfaces/IGroupedCredentialRequirements.sol";
import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {IIdentityValidator} from "./interfaces/IIdentityValidator.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract GroupedCredentialRegistryIdentityValidator is
  OwnableUpgradeable,
  IIdentityValidator,
  IGroupedCredentialRequirements
{
  uint256 private constant MAX_GROUPS = 8;
  uint256 private constant MAX_REQUIREMENTS_PER_GROUP = 8;
  uint256 private constant MAX_REQUIREMENT_SOURCES = 8;
  uint256 private constant MAX_CREDENTIAL_TYPES_PER_REQUIREMENT = 32;
  uint256 private constant MAX_ROUTING_TYPES_PER_GROUP = 32;
  uint256 private constant MAX_CRITERIA_PER_GROUP = 32;

  struct Group {
    RoutingConfig routing;
    bool exists;
  }

  /// @custom:storage-location erc7201:chainlink.ace.GroupedCredentialRegistryIdentityValidator
  struct GroupedCredentialRegistryIdentityValidatorStorage {
    bytes32[] groupIds;
    mapping(bytes32 groupId => Group group) groups;
    mapping(bytes32 groupId => bytes32[] requirementIds) groupRequirementIds;
    mapping(bytes32 groupId => mapping(bytes32 requirementId => ICredentialRequirements.CredentialRequirement))
      groupRequirements;
    mapping(bytes32 groupId => mapping(bytes32 credentialTypeId => ICredentialRequirements.CredentialSource[]))
      groupSources;
    mapping(bytes32 compositeKey => bytes32 groupId) routingIndex;
    // Tracks the credential type ids that currently have at least one source per group, so all source storage can be
    // enumerated and cleared when a group is removed.
    mapping(bytes32 groupId => bytes32[] credentialTypeIds) groupSourceTypeIds;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.GroupedCredentialRegistryIdentityValidator")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant groupedCredentialRegistryIdentityValidatorStorageLocation =
    0x8546998661239c9e2989622406beb4a5077b25e9cddb4671d6ec9fbe20667200;

  /**
   * @notice Returns the grouped credential validator storage pointer.
   * @return $ Namespaced grouped credential validator storage.
   */
  function _groupedStorage() internal pure returns (GroupedCredentialRegistryIdentityValidatorStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := groupedCredentialRegistryIdentityValidatorStorageLocation
    }
  }

  // disabling initializers on the implementation contract itself
  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  /**
   * @notice Initializes the grouped credential validator with flat group configuration.
   * @param groups Group routing configurations to add.
   * @param groupRequirements Group requirements to add.
   * @param groupSources Group sources to add.
   */
  function initialize(
    GroupInput[] memory groups,
    GroupRequirementInput[] memory groupRequirements,
    GroupSourceInput[] memory groupSources
  )
    public
    virtual
    initializer
  {
    __GroupedCredentialRegistryIdentityValidator_init(groups, groupRequirements, groupSources);
  }

  /**
   * @notice Initializes ownership and grouped credential validator configuration.
   * @param groups Group routing configurations to add.
   * @param groupRequirements Group requirements to add.
   * @param groupSources Group sources to add.
   */
  function __GroupedCredentialRegistryIdentityValidator_init(
    GroupInput[] memory groups,
    GroupRequirementInput[] memory groupRequirements,
    GroupSourceInput[] memory groupSources
  )
    internal
    onlyInitializing
  {
    __Ownable_init(msg.sender);
    __GroupedCredentialRegistryIdentityValidator_init_unchained(groups, groupRequirements, groupSources);
  }

  /**
   * @notice Initializes grouped credential validator configuration without initializing inherited contracts.
   * @param groups Group routing configurations to add.
   * @param groupRequirements Group requirements to add.
   * @param groupSources Group sources to add.
   */
  function __GroupedCredentialRegistryIdentityValidator_init_unchained(
    GroupInput[] memory groups,
    GroupRequirementInput[] memory groupRequirements,
    GroupSourceInput[] memory groupSources
  )
    internal
    onlyInitializing
  {
    for (uint256 i = 0; i < groups.length; i++) {
      _addGroup(groups[i]);
    }
    for (uint256 i = 0; i < groupSources.length; i++) {
      _requireGroup(groupSources[i].groupId);
      _addGroupSource(
        groupSources[i].groupId,
        ICredentialRequirements.CredentialSourceInput(
          groupSources[i].credentialTypeId,
          groupSources[i].identityRegistry,
          groupSources[i].credentialRegistry,
          groupSources[i].dataValidator
        )
      );
    }
    for (uint256 i = 0; i < groupRequirements.length; i++) {
      _requireGroup(groupRequirements[i].groupId);
      _addGroupRequirement(
        groupRequirements[i].groupId,
        ICredentialRequirements.CredentialRequirementInput(
          groupRequirements[i].requirementId,
          groupRequirements[i].credentialTypeIds,
          groupRequirements[i].minValidations,
          groupRequirements[i].invert
        )
      );
    }
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function addGroup(GroupInput calldata input) external override onlyOwner {
    _addGroup(input);
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function removeGroup(bytes32 groupId) external override onlyOwner {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    _requireGroup(groupId);
    _clearRoutingIndex(groupId, $.groups[groupId].routing);

    uint256 length = $.groupIds.length;
    for (uint256 i = 0; i < length; i++) {
      if ($.groupIds[i] == groupId) {
        for (uint256 j = i; j < length - 1; j++) {
          $.groupIds[j] = $.groupIds[j + 1];
        }
        $.groupIds.pop();
        break;
      }
    }

    bytes32[] memory requirementIds = $.groupRequirementIds[groupId];
    for (uint256 i = 0; i < requirementIds.length; i++) {
      delete $.groupRequirements[groupId][requirementIds[i]];
    }
    delete $.groupRequirementIds[groupId];

    bytes32[] memory sourceTypeIds = $.groupSourceTypeIds[groupId];
    for (uint256 i = 0; i < sourceTypeIds.length; i++) {
      delete $.groupSources[groupId][sourceTypeIds[i]];
    }
    delete $.groupSourceTypeIds[groupId];

    delete $.groups[groupId];
    emit GroupRemoved(groupId);
  }

  /**
   * @notice Removes a credential type id from a group's source-type tracking array.
   * @param groupId The group identifier that owns the tracked credential type.
   * @param credentialTypeId The credential type identifier to stop tracking.
   */
  function _removeGroupSourceTypeId(bytes32 groupId, bytes32 credentialTypeId) private {
    bytes32[] storage typeIds = _groupedStorage().groupSourceTypeIds[groupId];
    uint256 length = typeIds.length;
    for (uint256 i = 0; i < length; i++) {
      if (typeIds[i] == credentialTypeId) {
        typeIds[i] = typeIds[length - 1];
        typeIds.pop();
        return;
      }
    }
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function updateGroupRouting(bytes32 groupId, RoutingConfig calldata routing) external override onlyOwner {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    _requireGroup(groupId);
    _validateRoutingConfig(routing);

    RoutingConfig memory oldRouting = $.groups[groupId].routing;
    _clearRoutingIndex(groupId, oldRouting);
    _reserveRoutingIndex(groupId, routing);
    $.groups[groupId].routing = routing;
    _validateDataRoutingSourceCardinality(groupId, routing);
    emit GroupRoutingUpdated(groupId, oldRouting, $.groups[groupId].routing);
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function addGroupRequirement(
    bytes32 groupId,
    bytes32 requirementId,
    bytes32[] calldata credentialTypeIds,
    uint256 minValidations,
    bool invert
  )
    external
    override
    onlyOwner
  {
    _requireGroup(groupId);
    _addGroupRequirement(
      groupId,
      ICredentialRequirements.CredentialRequirementInput(requirementId, credentialTypeIds, minValidations, invert)
    );
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function removeGroupRequirement(bytes32 groupId, bytes32 requirementId) external override onlyOwner {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    _requireGroup(groupId);

    uint256 length = $.groupRequirementIds[groupId].length;
    for (uint256 i = 0; i < length; i++) {
      if ($.groupRequirementIds[groupId][i] == requirementId) {
        $.groupRequirementIds[groupId][i] = $.groupRequirementIds[groupId][length - 1];
        $.groupRequirementIds[groupId].pop();

        ICredentialRequirements.CredentialRequirement memory requirement = $.groupRequirements[groupId][requirementId];
        emit GroupCredentialRequirementRemoved(
          groupId, requirementId, requirement.credentialTypeIds, requirement.minValidations, requirement.invert
        );
        delete $.groupRequirements[groupId][requirementId];
        return;
      }
    }
    revert ICredentialRequirements.RequirementNotFound(requirementId);
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function addGroupSource(
    bytes32 groupId,
    bytes32 credentialTypeId,
    address identityRegistry,
    address credentialRegistry,
    address dataValidator
  )
    external
    override
    onlyOwner
  {
    _requireGroup(groupId);
    _addGroupSource(
      groupId,
      ICredentialRequirements.CredentialSourceInput(
        credentialTypeId, identityRegistry, credentialRegistry, dataValidator
      )
    );
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function removeGroupSource(
    bytes32 groupId,
    bytes32 credentialTypeId,
    address identityRegistry,
    address credentialRegistry
  )
    external
    override
    onlyOwner
  {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    _requireGroup(groupId);
    bytes32 sourceId = keccak256(abi.encodePacked(identityRegistry, credentialRegistry));
    uint256 length = $.groupSources[groupId][credentialTypeId].length;
    for (uint256 i = 0; i < length; i++) {
      ICredentialRequirements.CredentialSource memory existing = $.groupSources[groupId][credentialTypeId][i];
      if (keccak256(abi.encodePacked(existing.identityRegistry, existing.credentialRegistry)) == sourceId) {
        $.groupSources[groupId][credentialTypeId][i] = $.groupSources[groupId][credentialTypeId][length - 1];
        $.groupSources[groupId][credentialTypeId].pop();
        if (length == 1) {
          // Removed the last source for this credential type; stop tracking it for this group.
          _removeGroupSourceTypeId(groupId, credentialTypeId);
        }
        emit GroupCredentialSourceRemoved(
          groupId, credentialTypeId, identityRegistry, credentialRegistry, existing.dataValidator
        );
        return;
      }
    }
    revert ICredentialRequirements.CredentialSourceNotFound(credentialTypeId, identityRegistry, credentialRegistry);
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function getGroupIds() external view override returns (bytes32[] memory) {
    return _groupedStorage().groupIds;
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function getGroupRouting(bytes32 groupId) public view override returns (RoutingConfig memory) {
    _requireGroup(groupId);
    return _groupedStorage().groups[groupId].routing;
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function getGroupRequirementIds(bytes32 groupId) external view override returns (bytes32[] memory) {
    _requireGroup(groupId);
    return _groupedStorage().groupRequirementIds[groupId];
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function getGroupRequirement(
    bytes32 groupId,
    bytes32 requirementId
  )
    public
    view
    override
    returns (ICredentialRequirements.CredentialRequirement memory)
  {
    _requireGroup(groupId);
    return _groupedStorage().groupRequirements[groupId][requirementId];
  }

  /// @inheritdoc IGroupedCredentialRequirements
  function getGroupSources(
    bytes32 groupId,
    bytes32 credentialTypeId
  )
    public
    view
    override
    returns (ICredentialRequirements.CredentialSource[] memory)
  {
    _requireGroup(groupId);
    return _groupedStorage().groupSources[groupId][credentialTypeId];
  }

  /// @inheritdoc IIdentityValidator
  function validate(address account, bytes calldata context) public view virtual override returns (bool) {
    (bool routed, bytes32 groupId) = _route(account, context);
    return routed && _validateGroup(account, groupId, context);
  }

  /**
   * @notice Adds a credential validation group.
   * @param input Group routing to add.
   */
  function _addGroup(GroupInput memory input) internal {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    bytes32 groupId = input.groupId;
    if (groupId == bytes32(0)) {
      revert InvalidGroupConfiguration("groupId must not be zero");
    }
    if ($.groups[groupId].exists) {
      revert GroupExists(groupId);
    }
    if ($.groupIds.length >= MAX_GROUPS) {
      revert MaxGroupsReached();
    }

    RoutingConfig memory routing = RoutingConfig({
      credentialTypeIds: input.routingCredentialTypeIds,
      kind: input.routingKind,
      criteria: input.routingCriteria,
      minValidations: input.routingMinValidations
    });
    _validateRoutingConfig(routing);
    _reserveRoutingIndex(groupId, routing);
    $.groupIds.push(groupId);
    $.groups[groupId] = Group(routing, true);

    emit GroupAdded(groupId, $.groups[groupId].routing);
  }

  /**
   * @notice Adds a credential requirement to a group.
   * @param groupId The group identifier to add the requirement to.
   * @param input The credential requirement to add.
   */
  function _addGroupRequirement(
    bytes32 groupId,
    ICredentialRequirements.CredentialRequirementInput memory input
  )
    internal
  {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    if (input.requirementId == 0) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("requirementId cannot be 0");
    }
    if (input.minValidations == 0) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("minValidations must be greater than 0");
    }
    if ($.groupRequirementIds[groupId].length >= MAX_REQUIREMENTS_PER_GROUP) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("Max requirements reached");
    }
    if (input.credentialTypeIds.length == 0 || input.credentialTypeIds.length > MAX_CREDENTIAL_TYPES_PER_REQUIREMENT) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("Invalid credential types length");
    }
    for (uint256 i = 0; i < $.groupRequirementIds[groupId].length; i++) {
      if ($.groupRequirementIds[groupId][i] == input.requirementId) {
        revert ICredentialRequirements.RequirementExists(input.requirementId);
      }
    }

    $.groupRequirementIds[groupId].push(input.requirementId);
    $.groupRequirements[groupId][input.requirementId] =
      ICredentialRequirements.CredentialRequirement(input.credentialTypeIds, input.minValidations, input.invert);
    emit GroupCredentialRequirementAdded(
      groupId, input.requirementId, input.credentialTypeIds, input.minValidations, input.invert
    );
  }

  /**
   * @notice Validates the basic shape of a credential source input.
   * @dev Mirrors the single-validator sanitisation: rejects zero registries, zero credential type, and a
   * non-contract data validator. `view` (not `pure`) because it inspects `dataValidator.code.length`.
   * @param input The credential source to validate.
   */
  function _validateGroupSourceInput(ICredentialRequirements.CredentialSourceInput memory input) private view {
    if (input.identityRegistry == address(0)) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("identityRegistry cannot be address(0)");
    }
    if (input.credentialRegistry == address(0)) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("credentialRegistry cannot be address(0)");
    }
    if (input.credentialTypeId == 0) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("credentialTypeId cannot be 0");
    }
    if (input.dataValidator != address(0) && input.dataValidator.code.length == 0) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("dataValidator is not a contract");
    }
  }

  /**
   * @notice Adds a credential source to a group.
   * @param groupId The group identifier to add the source to.
   * @param input The credential source to add.
   */
  function _addGroupSource(bytes32 groupId, ICredentialRequirements.CredentialSourceInput memory input) internal {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    _validateGroupSourceInput(input);
    uint256 length = $.groupSources[groupId][input.credentialTypeId].length;
    if (length >= MAX_REQUIREMENT_SOURCES) {
      revert ICredentialRequirements.InvalidRequirementConfiguration("Max credential sources for credential type");
    }

    bytes32 sourceId = keccak256(abi.encodePacked(input.identityRegistry, input.credentialRegistry));
    for (uint256 i = 0; i < length; i++) {
      ICredentialRequirements.CredentialSource memory existing = $.groupSources[groupId][input.credentialTypeId][i];
      if (keccak256(abi.encodePacked(existing.identityRegistry, existing.credentialRegistry)) == sourceId) {
        revert ICredentialRequirements.SourceExists(
          input.credentialTypeId, input.identityRegistry, input.credentialRegistry
        );
      }
    }

    RoutingConfig storage routing = $.groups[groupId].routing;
    if (routing.kind == RoutingKind.Data && _routingContainsType(routing, input.credentialTypeId) && length >= 1) {
      revert MultipleSourcesForDataRouting(groupId, input.credentialTypeId);
    }

    if (length == 0) {
      // First source for this credential type in this group; track the type so it can be cleared on group removal.
      $.groupSourceTypeIds[groupId].push(input.credentialTypeId);
    }
    $.groupSources[groupId][input.credentialTypeId].push(
      ICredentialRequirements.CredentialSource(input.identityRegistry, input.credentialRegistry, input.dataValidator)
    );
    emit GroupCredentialSourceAdded(
      groupId, input.credentialTypeId, input.identityRegistry, input.credentialRegistry, input.dataValidator
    );
  }

  /**
   * @notice Validates that an account satisfies every requirement in a group.
   * @param account The account to validate.
   * @param groupId The group identifier to validate against.
   * @param context Encoded validation context passed through to credential and data validation.
   * @return valid True when all group requirements are satisfied.
   */
  function _validateGroup(address account, bytes32 groupId, bytes calldata context) internal view returns (bool) {
    bytes32[] storage requirementIds = _groupedStorage().groupRequirementIds[groupId];
    for (uint256 i = 0; i < requirementIds.length; i++) {
      if (!_validateRequirement(account, groupId, requirementIds[i], context)) {
        return false;
      }
    }
    return true;
  }

  /**
   * @notice Validates that an account satisfies a specific group requirement.
   * @param account The account to validate.
   * @param groupId The group identifier containing the requirement.
   * @param requirementId The requirement identifier to validate.
   * @param context Encoded validation context passed through to credential and data validation.
   * @return valid True when the requirement has enough valid credentials.
   */
  function _validateRequirement(
    address account,
    bytes32 groupId,
    bytes32 requirementId,
    bytes calldata context
  )
    internal
    view
    returns (bool)
  {
    ICredentialRequirements.CredentialRequirement storage requirement =
      _groupedStorage().groupRequirements[groupId][requirementId];
    uint256 validations = 0;
    for (uint256 i = 0; i < requirement.credentialTypeIds.length; i++) {
      ICredentialRequirements.CredentialSource[] storage sources =
        _groupedStorage().groupSources[groupId][requirement.credentialTypeIds[i]];
      for (uint256 j = 0; j < sources.length; j++) {
        if (_sourceSatisfiesCredential(
            account, sources[j], requirement.credentialTypeIds[i], requirement.invert, context
          )) {
          validations++;
          if (validations >= requirement.minValidations) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * @notice Routes an account to the first matching credential validation group.
   * @dev Groups are evaluated in insertion order; the first match wins.
   * @param account The account to route.
   * @param context Encoded validation context passed through to credential and data validation.
   * @return routed True when a routing match was found.
   * @return groupId The matched group identifier.
   */
  function _route(address account, bytes calldata context) internal view returns (bool, bytes32) {
    bytes32[] storage groupIds = _groupedStorage().groupIds;
    for (uint256 i = 0; i < groupIds.length; i++) {
      if (_routingMatches(account, groupIds[i], context)) {
        return (true, groupIds[i]);
      }
    }
    return (false, bytes32(0));
  }

  /**
   * @notice Checks whether an account matches a group's routing configuration.
   * @param account The account to route.
   * @param groupId The group identifier to test.
   * @param context Encoded validation context passed through to credential and data validation.
   * @return matches True when at least `routing.minValidations` routing credential sources match.
   */
  function _routingMatches(address account, bytes32 groupId, bytes calldata context) internal view returns (bool) {
    RoutingConfig storage routing = _groupedStorage().groups[groupId].routing;
    uint256 validations = 0;
    for (uint256 i = 0; i < routing.credentialTypeIds.length; i++) {
      bytes32 credentialTypeId = routing.credentialTypeIds[i];
      ICredentialRequirements.CredentialSource[] storage sources =
        _groupedStorage().groupSources[groupId][credentialTypeId];
      for (uint256 j = 0; j < sources.length; j++) {
        (bool matched,,) = _routingSourceMatchDetails(account, sources[j], credentialTypeId, routing, context);
        if (matched) {
          validations++;
          if (validations >= routing.minValidations) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * @notice Resolves routing match details for a single credential source.
   * @dev Data-based routing matches only on the stored credential payload, so its granularity is bounded by the
   * credential schema chosen by the issuer. The contract can only distinguish boundaries that already exist in the
   * payload: a broad `country`-only credential cannot, for example, separate a sub-country region or territory from the
   * rest of the country. For geography-sensitive use cases where future sanctions or jurisdiction carve-outs may
   * matter,
   * issue credentials with granular schemas (for example separate region or territory identifiers) rather than a single
   * broad country field; otherwise expressing newly required boundaries later requires revoking and reissuing richer
   * credentials or adding new credential types.
   * @param account The account to route.
   * @param source The credential source to validate.
   * @param credentialTypeId The credential type identifier to validate.
   * @param routing The routing configuration to test.
   * @param context Encoded validation context passed through to credential and data validation.
   * @return matched True when the source satisfies the routing configuration.
   * @return ccid Cross-chain identity when matched.
   * @return credentialData Credential payload used for data routing (empty for attestation routing).
   */
  function _routingSourceMatchDetails(
    address account,
    ICredentialRequirements.CredentialSource storage source,
    bytes32 credentialTypeId,
    RoutingConfig storage routing,
    bytes calldata context
  )
    internal
    view
    returns (bool matched, bytes32 ccid, bytes memory credentialData)
  {
    bool valid;
    (valid, ccid, credentialData) = _sourceCredentialData(account, source, credentialTypeId, false, context);
    if (!valid) {
      return (false, ccid, credentialData);
    }
    if (routing.kind == RoutingKind.Attestation) {
      return (true, ccid, "");
    }
    bool dataFetched;
    bytes memory fetchedCredentialData;
    (dataFetched, fetchedCredentialData) = _getCredentialData(source, ccid, credentialTypeId);
    if (!dataFetched) {
      return (false, ccid, credentialData);
    }
    credentialData = fetchedCredentialData;
    bytes32 dataHash = keccak256(abi.encode(credentialData));
    for (uint256 i = 0; i < routing.criteria.length; i++) {
      if (dataHash == routing.criteria[i]) {
        return (true, ccid, credentialData);
      }
    }
    return (false, ccid, credentialData);
  }

  /**
   * @notice Checks whether a credential source satisfies a credential requirement.
   * @param account The account to validate.
   * @param source The credential source to validate.
   * @param credentialTypeId The credential type identifier to validate.
   * @param invert Whether the credential requirement is inverted.
   * @param context Encoded validation context passed through to credential and data validation.
   * @return valid True when the source satisfies the requirement.
   */
  function _sourceSatisfiesCredential(
    address account,
    ICredentialRequirements.CredentialSource storage source,
    bytes32 credentialTypeId,
    bool invert,
    bytes calldata context
  )
    internal
    view
    returns (bool)
  {
    (bool valid,,) = _sourceCredentialData(account, source, credentialTypeId, invert, context);
    return valid;
  }

  /**
   * @notice Resolves identity and credential data for a source credential validation.
   * @param account The account to validate.
   * @param source The credential source to validate.
   * @param credentialTypeId The credential type identifier to validate.
   * @param invert Whether the credential requirement is inverted.
   * @param context Encoded validation context passed through to credential and data validation.
   * @return valid True when the source satisfies the credential validation.
   * @return ccid The resolved cross-chain identity.
   * @return credentialData Credential data used by a configured data validator.
   */
  function _sourceCredentialData(
    address account,
    ICredentialRequirements.CredentialSource storage source,
    bytes32 credentialTypeId,
    bool invert,
    bytes calldata context
  )
    internal
    view
    returns (bool, bytes32, bytes memory)
  {
    bytes32 ccid;
    try IIdentityRegistry(source.identityRegistry).getIdentity(account) returns (bytes32 resolvedCCID) {
      ccid = resolvedCCID;
    } catch {
      return (false, bytes32(0), "");
    }
    if (ccid == bytes32(0)) {
      // missing identity for an inverted requirement is considered a validation, matching the flat validator
      return (invert, bytes32(0), "");
    }

    bool credentialExists;
    try ICredentialRegistry(source.credentialRegistry).validate(ccid, credentialTypeId, context) returns (bool valid) {
      credentialExists = valid;
    } catch {
      return (false, ccid, "");
    }

    if (invert) {
      return (!credentialExists, ccid, "");
    }
    if (!credentialExists) {
      return (false, ccid, "");
    }
    if (source.dataValidator == address(0)) {
      return (true, ccid, "");
    }

    return _validateSourceCredentialData(account, source, ccid, credentialTypeId, context);
  }

  /**
   * @notice Runs a configured data validator against fetched credential data.
   * @param account The account to validate.
   * @param source The credential source containing the data validator.
   * @param ccid The resolved cross-chain identity.
   * @param credentialTypeId The credential type identifier to validate.
   * @param context Encoded validation context passed through to data validation.
   * @return valid True when the data validator accepts the credential data.
   * @return resolvedCcid The resolved cross-chain identity.
   * @return credentialData The validated credential data.
   */
  function _validateSourceCredentialData(
    address account,
    ICredentialRequirements.CredentialSource storage source,
    bytes32 ccid,
    bytes32 credentialTypeId,
    bytes calldata context
  )
    private
    view
    returns (bool, bytes32, bytes memory)
  {
    (bool dataFetched, bytes memory credentialData) = _getCredentialData(source, ccid, credentialTypeId);
    if (!dataFetched) {
      return (false, ccid, "");
    }
    try ICredentialDataValidator(source.dataValidator)
      .validateCredentialData(ccid, account, credentialTypeId, credentialData, context) returns (
      bool dataValid
    ) {
      if (!dataValid) {
        return (false, ccid, "");
      }
    } catch {
      return (false, ccid, "");
    }

    return (true, ccid, credentialData);
  }

  /**
   * @notice Fetches credential data from a credential registry.
   * @param source The credential source containing the credential registry.
   * @param ccid The cross-chain identity to query.
   * @param credentialTypeId The credential type identifier to query.
   * @return fetched True when credential data was fetched successfully.
   * @return credentialData The fetched credential data.
   */
  function _getCredentialData(
    ICredentialRequirements.CredentialSource storage source,
    bytes32 ccid,
    bytes32 credentialTypeId
  )
    internal
    view
    returns (bool, bytes memory)
  {
    try ICredentialRegistry(source.credentialRegistry).getCredential(ccid, credentialTypeId) returns (
      ICredentialRegistry.Credential memory credential
    ) {
      return (true, credential.credentialData);
    } catch {
      return (false, "");
    }
  }

  /**
   * @notice Validates routing input bounds and kind-specific fields.
   * @param routing The routing input to validate.
   */
  function _validateRoutingConfig(RoutingConfig memory routing) internal pure {
    if (routing.minValidations == 0) {
      revert InvalidGroupConfiguration("routing minValidations must be greater than 0");
    }
    if (routing.credentialTypeIds.length == 0 || routing.credentialTypeIds.length > MAX_ROUTING_TYPES_PER_GROUP) {
      revert InvalidGroupConfiguration("Invalid routing credential types length");
    }
    if (routing.kind == RoutingKind.Attestation && routing.criteria.length != 0) {
      revert InvalidGroupConfiguration("Attestation routing must not include criteria");
    }
    if (
      routing.kind == RoutingKind.Data
        && (routing.criteria.length == 0 || routing.criteria.length > MAX_CRITERIA_PER_GROUP)
    ) {
      revert InvalidGroupConfiguration("Invalid criteria length");
    }
  }

  /**
   * @notice Reserves routing composite keys for a group.
   * @param groupId The group identifier that owns the routing keys.
   * @param routing The routing input whose keys should be reserved.
   */
  function _reserveRoutingIndex(bytes32 groupId, RoutingConfig memory routing) internal {
    for (uint256 i = 0; i < routing.credentialTypeIds.length; i++) {
      if (routing.kind == RoutingKind.Attestation) {
        _reserveCompositeKey(groupId, _compositeKey(routing.credentialTypeIds[i], bytes32(0)));
      } else {
        for (uint256 j = 0; j < routing.criteria.length; j++) {
          _reserveCompositeKey(groupId, _compositeKey(routing.credentialTypeIds[i], routing.criteria[j]));
        }
      }
    }
  }

  /**
   * @notice Reserves a single routing composite key for a group.
   * @param groupId The group identifier that owns the composite key.
   * @param compositeKey The routing composite key to reserve.
   */
  function _reserveCompositeKey(bytes32 groupId, bytes32 compositeKey) private {
    bytes32 existingGroupId = _groupedStorage().routingIndex[compositeKey];
    if (existingGroupId != bytes32(0) && existingGroupId != groupId) {
      revert RoutingOverlap(compositeKey, existingGroupId, groupId);
    }
    _groupedStorage().routingIndex[compositeKey] = groupId;
  }

  /**
   * @notice Clears routing composite keys owned by a group.
   * @param groupId The group identifier that owns the routing keys.
   * @param routing The routing configuration whose keys should be cleared.
   */
  function _clearRoutingIndex(bytes32 groupId, RoutingConfig memory routing) internal {
    for (uint256 i = 0; i < routing.credentialTypeIds.length; i++) {
      if (routing.kind == RoutingKind.Attestation) {
        _clearCompositeKey(groupId, _compositeKey(routing.credentialTypeIds[i], bytes32(0)));
      } else {
        for (uint256 j = 0; j < routing.criteria.length; j++) {
          _clearCompositeKey(groupId, _compositeKey(routing.credentialTypeIds[i], routing.criteria[j]));
        }
      }
    }
  }

  /**
   * @notice Clears a routing composite key if it is owned by a group.
   * @param groupId The group identifier expected to own the composite key.
   * @param compositeKey The routing composite key to clear.
   */
  function _clearCompositeKey(bytes32 groupId, bytes32 compositeKey) private {
    if (_groupedStorage().routingIndex[compositeKey] == groupId) {
      delete _groupedStorage().routingIndex[compositeKey];
    }
  }

  /**
   * @notice Validates source cardinality for data-based routing credential types.
   * @param groupId The group identifier whose sources should be checked.
   * @param routing The routing input to check.
   */
  function _validateDataRoutingSourceCardinality(bytes32 groupId, RoutingConfig memory routing) internal view {
    if (routing.kind != RoutingKind.Data) {
      return;
    }
    for (uint256 i = 0; i < routing.credentialTypeIds.length; i++) {
      if (_groupedStorage().groupSources[groupId][routing.credentialTypeIds[i]].length > 1) {
        revert MultipleSourcesForDataRouting(groupId, routing.credentialTypeIds[i]);
      }
    }
  }

  /**
   * @notice Computes the routing composite key for a credential type and criterion hash.
   * @param typeId The credential type identifier.
   * @param criterion The criterion hash for data routing, or `bytes32(0)` for attestation routing.
   * @return compositeKey The computed routing composite key.
   */
  function _compositeKey(bytes32 typeId, bytes32 criterion) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(typeId, criterion));
  }

  /**
   * @notice Checks whether routing includes a credential type identifier.
   * @param routing The routing configuration to check.
   * @param credentialTypeId The credential type identifier to find.
   * @return contains True when routing includes the credential type identifier.
   */
  function _routingContainsType(RoutingConfig storage routing, bytes32 credentialTypeId) internal view returns (bool) {
    for (uint256 i = 0; i < routing.credentialTypeIds.length; i++) {
      if (routing.credentialTypeIds[i] == credentialTypeId) {
        return true;
      }
    }
    return false;
  }

  /**
   * @notice Reverts when a group does not exist.
   * @param groupId The group identifier to require.
   */
  function _requireGroup(bytes32 groupId) internal view {
    if (!_groupedStorage().groups[groupId].exists) {
      revert GroupNotFound(groupId);
    }
  }
}
