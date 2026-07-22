// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {GroupedCredentialRegistryIdentityValidator} from "./GroupedCredentialRegistryIdentityValidator.sol";
import {ICredentialRequirements} from "./interfaces/ICredentialRequirements.sol";
import {IGroupedCredentialRequirements} from "./interfaces/IGroupedCredentialRequirements.sol";
import {IIdentityValidator} from "./interfaces/IIdentityValidator.sol";
import {IPolicyEngine} from "@chainlink/policy-management/interfaces/IPolicyEngine.sol";
import {Policy} from "@chainlink/policy-management/core/Policy.sol";

contract GroupedIdentityValidatorPolicy is Policy, GroupedCredentialRegistryIdentityValidator {
  string public constant override typeAndVersion = "GroupedIdentityValidatorPolicy 1.2.0";

  /**
   * @notice Authorize the following configuration functions:
   * - addGroup
   * - removeGroup
   * - updateGroupRouting
   * - addGroupRequirement
   * - removeGroupRequirement
   * - addGroupSource
   * - removeGroupSource
   */
  function authorizeConfigSelector(bytes4 selector) public pure override returns (bool) {
    return (selector == this.addGroup.selector || selector == this.removeGroup.selector
        || selector == this.updateGroupRouting.selector || selector == this.addGroupRequirement.selector
        || selector == this.removeGroupRequirement.selector || selector == this.addGroupSource.selector
        || selector == this.removeGroupSource.selector);
  }

  /**
   * @notice Configures the policy by setting up grouped credential routing and validation requirements.
   * @dev The `parameters` input must be the ABI encoding of (GroupInput[], GroupRequirementInput[],
   * GroupSourceInput[]). Each GroupInput includes `routingMinValidations`: distinct routing sources that must match.
   * @param parameters ABI-encoded grouped credential configuration.
   */
  function configure(bytes calldata parameters) internal override onlyInitializing {
    if (parameters.length == 0) {
      __GroupedCredentialRegistryIdentityValidator_init_unchained(
        new IGroupedCredentialRequirements.GroupInput[](0),
        new IGroupedCredentialRequirements.GroupRequirementInput[](0),
        new IGroupedCredentialRequirements.GroupSourceInput[](0)
      );
      return;
    }

    (
      IGroupedCredentialRequirements.GroupInput[] memory groups,
      IGroupedCredentialRequirements.GroupRequirementInput[] memory groupRequirements,
      IGroupedCredentialRequirements.GroupSourceInput[] memory groupSources
    ) = abi.decode(
      parameters,
      (
        IGroupedCredentialRequirements.GroupInput[],
        IGroupedCredentialRequirements.GroupRequirementInput[],
        IGroupedCredentialRequirements.GroupSourceInput[]
      )
    );
    __GroupedCredentialRegistryIdentityValidator_init_unchained(groups, groupRequirements, groupSources);
  }

  /**
   * @notice Function to be called by the policy engine to check if execution is allowed.
   * @param parameters Encoded policy parameters.
   *        [account(address),...] List of accounts to route and validate.
   * @param context Encoded policy context passed through to credential and data validation.
   * @return result Continue when every account routes to at least one group and satisfies the first matched group's
   * requirements.
   */
  function run(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata context
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    if (parameters.length < 1) {
      revert InvalidParameters("expected at least 1 parameter");
    }

    for (uint256 i = 0; i < parameters.length; i++) {
      if (parameters[i].length != 32) {
        revert InvalidParameters("parameter not address-encoded");
      }
      address account = abi.decode(parameters[i], (address));
      (bool routed, bytes32 groupId) = _route(account, context);
      if (!routed) {
        revert IPolicyEngine.PolicyRejected("no routing match");
      }
      if (!_validateGroup(account, groupId, context)) {
        revert IPolicyEngine.PolicyRejected("group requirements failed");
      }
    }
    return IPolicyEngine.PolicyResult.Continue;
  }

  /**
   * @notice Runs after successful policy checks and emits identity validation events for each account.
   * @param parameters Encoded policy parameters.
   *        [account(address),...] List of accounts to emit validation events for.
   * @param context Encoded policy context passed through to credential and data validation.
   */
  function postRun(
    address, /*caller*/
    address, /*subject*/
    bytes4, /*selector*/
    bytes[] calldata parameters,
    bytes calldata context
  )
    public
    override
    onlyPolicyEngine
  {
    for (uint256 i = 0; i < parameters.length; i++) {
      address account = abi.decode(parameters[i], (address));
      _emitIdentityValidatedForAccount(account, context);
    }
  }

  /**
   * @notice Emits identity validation events for the routed group and its requirements.
   * @param account Account whose identity validation should be emitted.
   * @param context Encoded policy context passed through to credential and data validation.
   */
  function _emitIdentityValidatedForAccount(address account, bytes calldata context) internal {
    bytes32[] storage groupIds = _groupedStorage().groupIds;
    for (uint256 i = 0; i < groupIds.length; i++) {
      bytes32 groupId = groupIds[i];
      if (!_routingMatches(account, groupId, context)) {
        continue;
      }
      if (!_validateGroup(account, groupId, context)) {
        return;
      }
      _emitForRouting(account, groupId, context);
      _emitForGroupRequirements(account, groupId, context);
      return;
    }
  }

  /**
   * @notice Emits identity validation events for routing credential sources that satisfied the routing threshold.
   * @param account Account whose routing validations should be emitted.
   * @param groupId Group identifier selected by routing.
   * @param context Encoded policy context passed through to credential and data validation.
   */
  function _emitForRouting(address account, bytes32 groupId, bytes calldata context) internal {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    RoutingConfig storage routing = $.groups[groupId].routing;
    uint256 validations = 0;
    for (uint256 i = 0; i < routing.credentialTypeIds.length; i++) {
      bytes32 credentialTypeId = routing.credentialTypeIds[i];
      ICredentialRequirements.CredentialSource[] storage sources = $.groupSources[groupId][credentialTypeId];
      for (uint256 j = 0; j < sources.length; j++) {
        (bool matched, bytes32 ccid, bytes memory credentialData) =
          _routingSourceMatchDetails(account, sources[j], credentialTypeId, routing, context);
        if (!matched) {
          continue;
        }

        ICredentialRequirements.CredentialSource memory source = sources[j];
        _emitIdentityValidated(account, ccid, credentialTypeId, source, credentialData);
        validations++;
        if (validations >= routing.minValidations) {
          return;
        }
      }
    }
  }

  /**
   * @notice Emits identity validation events for the credential requirements in a routed group.
   * @param account Account whose group requirement validations should be emitted.
   * @param groupId Group identifier selected by routing.
   * @param context Encoded policy context passed through to credential and data validation.
   */
  function _emitForGroupRequirements(address account, bytes32 groupId, bytes calldata context) internal {
    GroupedCredentialRegistryIdentityValidatorStorage storage $ = _groupedStorage();
    bytes32[] storage requirementIds = $.groupRequirementIds[groupId];
    for (uint256 i = 0; i < requirementIds.length; i++) {
      ICredentialRequirements.CredentialRequirement storage requirement =
        $.groupRequirements[groupId][requirementIds[i]];
      uint256 validations = 0;

      for (uint256 j = 0; j < requirement.credentialTypeIds.length; j++) {
        bytes32 credentialTypeId = requirement.credentialTypeIds[j];
        ICredentialRequirements.CredentialSource[] storage sources = $.groupSources[groupId][credentialTypeId];
        for (uint256 k = 0; k < sources.length; k++) {
          (bool valid, bytes32 ccid, bytes memory credentialData) =
            _sourceCredentialData(account, sources[k], credentialTypeId, requirement.invert, context);
          if (!valid) {
            continue;
          }

          ICredentialRequirements.CredentialSource memory source = sources[k];
          _emitIdentityValidated(
            account, ccid, credentialTypeId, source, requirement.invert ? bytes("") : credentialData
          );
          validations++;
          if (validations >= requirement.minValidations) {
            break;
          }
        }
        if (validations >= requirement.minValidations) {
          break;
        }
      }
    }
  }

  /**
   * @notice Emits a single identity validation event.
   * @param account Account whose identity was validated.
   * @param ccid Cross-chain identity resolved for the account.
   * @param credentialTypeId Credential type that satisfied validation.
   * @param source Credential source that provided the validation.
   * @param credentialData Credential data used to compute the emitted hash when a data validator is configured.
   */
  function _emitIdentityValidated(
    address account,
    bytes32 ccid,
    bytes32 credentialTypeId,
    ICredentialRequirements.CredentialSource memory source,
    bytes memory credentialData
  )
    internal
  {
    emit IdentityValidated(
      account,
      ccid,
      credentialTypeId,
      source.credentialRegistry,
      source.dataValidator,
      _credentialDataHash(source.dataValidator, credentialData)
    );
  }

  /**
   * @notice Computes the credential data hash emitted with identity validation events.
   * @param dataValidator Data validator configured for the credential source, if any.
   * @param credentialData Credential data to hash.
   * @return credentialDataHash Hash of credential data, or zero when no data validator is configured.
   */
  function _credentialDataHash(address dataValidator, bytes memory credentialData) internal pure returns (bytes32) {
    if (dataValidator == address(0)) {
      return bytes32(0);
    }
    return keccak256(credentialData);
  }

  /**
   * @notice Checks whether this contract implements an interface.
   * @param interfaceId Interface identifier to check.
   * @return supported True when the interface is supported.
   */
  function supportsInterface(bytes4 interfaceId) public view override(Policy) returns (bool) {
    return interfaceId == type(IIdentityValidator).interfaceId || super.supportsInterface(interfaceId);
  }
}
