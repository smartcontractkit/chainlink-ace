// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ICredentialRequirements} from "./interfaces/ICredentialRequirements.sol";
import {IIdentityValidator} from "./interfaces/IIdentityValidator.sol";
import {ICredentialDataValidator} from "./interfaces/ICredentialDataValidator.sol";
import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {ICredentialRegistry} from "./interfaces/ICredentialRegistry.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract CredentialRegistryIdentityValidator is OwnableUpgradeable, ICredentialRequirements, IIdentityValidator {
  uint256 private constant MAX_REQUIREMENTS = 8;
  uint256 private constant MAX_REQUIREMENT_SOURCES = 8;

  /// @custom:storage-location erc7201:cross-chain-identity.CredentialRegistryIdentityValidator
  struct CredentialRegistryIdentityValidatorStorage {
    bytes32[] requirements;
    mapping(bytes32 requirementId => CredentialRequirement credentialRequirement) credentialRequirementMap;
    mapping(bytes32 credential => CredentialSource[] sources) credentialSources;
  }

  // keccak256(abi.encode(uint256(keccak256("cross-chain-identity.CredentialRegistryIdentityValidator")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant credentialRegistryIdentityValidatorStorageLocation =
    0xc27301a28eb510a5458d7558b8bccbf4cdde3a4546d3bf041997133950e7d200;

  function _credentialRegistryIdentityValidatorStorage()
    private
    pure
    returns (CredentialRegistryIdentityValidatorStorage storage $)
  {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := credentialRegistryIdentityValidatorStorageLocation
    }
  }

  /**
   * @dev Initializes the credential validator and sets the initial credential sources and requirements.
   * @param credentialSourceInputs The credential sources to add.
   * @param credentialRequirementInputs The credential requirements to add.
   */
  function initialize(
    CredentialSourceInput[] memory credentialSourceInputs,
    CredentialRequirementInput[] memory credentialRequirementInputs
  )
    public
    virtual
    initializer
  {
    __CredentialRegistryIdentitityValidator_init(credentialSourceInputs, credentialRequirementInputs);
  }

  function __CredentialRegistryIdentitityValidator_init(
    CredentialSourceInput[] memory credentialSourceInputs,
    CredentialRequirementInput[] memory credentialRequirementInputs
  )
    internal
    onlyInitializing
  {
    __Ownable_init(msg.sender);
    __CredentialRegistryIdentitityValidator_init_unchained(credentialSourceInputs, credentialRequirementInputs);
  }

  function __CredentialRegistryIdentitityValidator_init_unchained(
    CredentialSourceInput[] memory credentialSourceInputs,
    CredentialRequirementInput[] memory credentialRequirementInputs
  )
    internal
    onlyInitializing
  {
    uint256 length = credentialSourceInputs.length;
    for (uint256 i = 0; i < length; i++) {
      _addCredentialSource(credentialSourceInputs[i]);
    }
    length = credentialRequirementInputs.length;
    for (uint256 i = 0; i < length; i++) {
      _addCredentialRequirement(credentialRequirementInputs[i]);
    }
  }

  function _addCredentialRequirement(CredentialRequirementInput memory input) internal {
    uint256 minValidations = input.minValidations;
    if (minValidations == 0) {
      revert InvalidRequirementConfiguration("minValidations must be greater than 0");
    }
    uint256 length = _credentialRegistryIdentityValidatorStorage().requirements.length;
    if (length >= MAX_REQUIREMENTS) {
      revert InvalidRequirementConfiguration("Max requirements reached");
    }
    bytes32 requirementId = input.requirementId;
    for (uint256 i = 0; i < length; i++) {
      if (_credentialRegistryIdentityValidatorStorage().requirements[i] == requirementId) {
        revert RequirementExists(requirementId);
      }
    }
    bytes32[] memory credentialTypeIds = input.credentialTypeIds;
    _credentialRegistryIdentityValidatorStorage().requirements.push(requirementId);
    _credentialRegistryIdentityValidatorStorage().credentialRequirementMap[requirementId] =
      CredentialRequirement(credentialTypeIds, minValidations, input.invert);
    emit CredentialRequirementAdded(requirementId, credentialTypeIds, minValidations, input.invert);
  }

  /// @inheritdoc ICredentialRequirements
  function addCredentialRequirement(CredentialRequirementInput memory input) public virtual override onlyOwner {
    _addCredentialRequirement(input);
  }

  /// @inheritdoc ICredentialRequirements
  function removeCredentialRequirement(bytes32 requirementId) public virtual override onlyOwner {
    uint256 length = _credentialRegistryIdentityValidatorStorage().requirements.length;
    for (uint256 i = 0; i < length; i++) {
      if (_credentialRegistryIdentityValidatorStorage().requirements[i] == requirementId) {
        _credentialRegistryIdentityValidatorStorage().requirements[i] =
          _credentialRegistryIdentityValidatorStorage().requirements[length - 1];
        _credentialRegistryIdentityValidatorStorage().requirements.pop();

        CredentialRequirement memory requirement =
          _credentialRegistryIdentityValidatorStorage().credentialRequirementMap[requirementId];

        emit CredentialRequirementRemoved(
          requirementId, requirement.credentialTypeIds, requirement.minValidations, requirement.invert
        );
        delete _credentialRegistryIdentityValidatorStorage().credentialRequirementMap[requirementId];
        return;
      }
    }
    revert RequirementNotFound(requirementId);
  }

  /// @inheritdoc ICredentialRequirements
  function getCredentialRequirement(bytes32 requirementId)
    public
    view
    virtual
    override
    returns (CredentialRequirement memory)
  {
    return _credentialRegistryIdentityValidatorStorage().credentialRequirementMap[requirementId];
  }

  /// @inheritdoc ICredentialRequirements
  function getCredentialRequirementIds() public view virtual override returns (bytes32[] memory) {
    return _credentialRegistryIdentityValidatorStorage().requirements;
  }

  function _addCredentialSource(CredentialSourceInput memory input) internal {
    address identityRegistry = input.identityRegistry;
    address credentialRegistry = input.credentialRegistry;
    bytes32 credentialTypeId = input.credentialTypeId;
    bytes32 sourceId = keccak256(abi.encodePacked(identityRegistry, credentialRegistry));
    uint256 length = _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId].length;
    if (length >= MAX_REQUIREMENT_SOURCES) {
      revert InvalidRequirementConfiguration("Max credential sources reached for credential type");
    }
    for (uint256 i = 0; i < length; i++) {
      // Load the entire source struct into memory once
      CredentialSource memory existingSource =
        _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId][i];

      bytes32 foundSourceId =
        keccak256(abi.encodePacked(existingSource.identityRegistry, existingSource.credentialRegistry));
      if (foundSourceId == sourceId) {
        revert SourceExists(credentialTypeId, identityRegistry, credentialRegistry);
      }
    }
    address dataValidator = input.dataValidator;
    _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId].push(
      CredentialSource(identityRegistry, credentialRegistry, dataValidator)
    );
    emit CredentialSourceAdded(credentialTypeId, identityRegistry, credentialRegistry, dataValidator);
  }

  /// @inheritdoc ICredentialRequirements
  function addCredentialSource(CredentialSourceInput memory input) public virtual override onlyOwner {
    _addCredentialSource(input);
  }

  /// @inheritdoc ICredentialRequirements
  function removeCredentialSource(
    bytes32 credentialTypeId,
    address identityRegistry,
    address credentialRegistry
  )
    public
    virtual
    override
    onlyOwner
  {
    bytes32 sourceId = keccak256(abi.encodePacked(identityRegistry, credentialRegistry));
    uint256 length = _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId].length;
    for (uint256 i = 0; i < length; i++) {
      // Load the entire source struct into memory once
      CredentialSource memory existingSource =
        _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId][i];

      bytes32 foundSourceId =
        keccak256(abi.encodePacked(existingSource.identityRegistry, existingSource.credentialRegistry));
      if (foundSourceId == sourceId) {
        _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId][i] =
          _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId][length - 1];
        _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId].pop();
        emit CredentialSourceRemoved(
          credentialTypeId, identityRegistry, credentialRegistry, existingSource.dataValidator
        );
        return;
      }
    }
    revert CredentialSourceNotFound(credentialTypeId, identityRegistry, credentialRegistry);
  }

  /// @inheritdoc ICredentialRequirements
  function getCredentialSources(bytes32 credential) public view virtual override returns (CredentialSource[] memory) {
    return _credentialRegistryIdentityValidatorStorage().credentialSources[credential];
  }

  /// @inheritdoc IIdentityValidator
  function validate(address account, bytes calldata context) public view virtual override returns (bool) {
    uint256 length = _credentialRegistryIdentityValidatorStorage().requirements.length;
    for (uint256 i = 0; i < length; i++) {
      if (!_validateRequirement(account, _credentialRegistryIdentityValidatorStorage().requirements[i], context)) {
        return false;
      }
    }
    return true;
  }

  function _validateRequirement(
    address account,
    bytes32 requirementId,
    bytes calldata context
  )
    internal
    view
    virtual
    returns (bool)
  {
    CredentialRequirement memory requirement =
      _credentialRegistryIdentityValidatorStorage().credentialRequirementMap[requirementId];
    uint256 validations = 0;
    for (uint256 i = 0; i < requirement.credentialTypeIds.length; i++) {
      validations = _validateCredential(
        account, requirement.credentialTypeIds[i], validations, requirement.minValidations, requirement.invert, context
      );
      if (validations >= requirement.minValidations) {
        return true;
      }
    }
    return false;
  }

  function _validateCredential(
    address account,
    bytes32 credentialTypeId,
    uint256 currentValidations,
    uint256 minValidations,
    bool invert,
    bytes calldata context
  )
    internal
    view
    virtual
    returns (uint256)
  {
    uint256 validations = currentValidations;
    uint256 length = _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId].length;
    for (uint256 i = 0; i < length; i++) {
      CredentialSource memory source =
        _credentialRegistryIdentityValidatorStorage().credentialSources[credentialTypeId][i];
      bytes32 ccid = IIdentityRegistry(source.identityRegistry).getIdentity(account);
      if (ccid == 0) {
        continue; // identity not found in this registry
      }

      if (
        _validateCredentialWithRegistry(
          ccid, account, source.credentialRegistry, source.dataValidator, credentialTypeId, invert, context
        )
      ) {
        validations++;
      }
      if (validations >= minValidations) {
        return validations;
      }
    }
    return validations;
  }

  function _validateCredentialWithRegistry(
    bytes32 ccid,
    address account,
    address credentialRegistry,
    address dataValidator,
    bytes32 credential,
    bool invert,
    bytes calldata context
  )
    internal
    view
    virtual
    returns (bool)
  {
    // Check if credential exists and is valid in registry
    bool credentialExists;
    try ICredentialRegistry(credentialRegistry).validate(ccid, credential, context) returns (bool valid) {
      credentialExists = valid;
    } catch {
      credentialExists = false;
    }

    // For inverted credentials: return true only if credential doesn't exist
    if (invert) {
      return !credentialExists;
    }

    // For normal credentials: credential must exist to proceed
    if (!credentialExists) {
      return false;
    }

    // No data validator means credential is valid
    if (dataValidator == address(0)) {
      return true;
    }

    // Validate credential data
    bytes memory credentialData = ICredentialRegistry(credentialRegistry).getCredential(ccid, credential).credentialData;

    try ICredentialDataValidator(dataValidator).validateCredentialData(
      ccid, account, credential, credentialData, context
    ) returns (bool valid) {
      return valid;
    } catch {
      return false;
    }
  }
}
