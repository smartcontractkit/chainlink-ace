// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IExtractor} from "../interfaces/IExtractor.sol";
import {IMapper} from "../interfaces/IMapper.sol";
import {IPolicy} from "../interfaces/IPolicy.sol";
import {Policy} from "./Policy.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

contract PolicyEngine is Initializable, AccessControlUpgradeable, IPolicyEngine {
  string public constant override typeAndVersion = "PolicyEngine 1.0.0";

  uint256 private constant MAX_POLICIES = 8;
  bytes32 public constant POLICY_CONFIG_ADMIN_ROLE = keccak256("POLICY_CONFIG_ADMIN_ROLE");
  bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

  /// @custom:storage-location erc7201:chainlink.ace.PolicyEngine
  struct PolicyEngineStorage {
    bool defaultPolicyAllow;
    mapping(bytes4 selector => address extractor) extractorBySelector;
    mapping(address policy => address mapper) policyMappers;
    mapping(address policy => uint256 configVersion) policyConfigVersions;
    mapping(address target => bool attached) targetAttached;
    mapping(address target => mapping(bytes4 selector => address[] policies)) targetPolicies;
    mapping(address target => mapping(bytes4 selector => mapping(address policy => bytes32[] policyParameterNames)))
      targetPolicyParameters;
    mapping(address target => bool hasTargetDefault) targetHasDefault;
    mapping(address target => bool targetDefaultPolicyAllow) targetDefaultPolicyAllow;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.PolicyEngine")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant policyEngineStorageLocation =
    0x9876d26c639ec5f9246047c1a6b3d2d4c94a7f0dd7848b1a4f882f50fcb29f00;

  function _policyEngineStorage() private pure returns (PolicyEngineStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := policyEngineStorageLocation
    }
  }

  constructor() {
    _disableInitializers();
  }

  /**
   * @dev Initializes the policy engine.
   * @param defaultAllow The default policy result. True to allow, false to reject.
   */
  function initialize(bool defaultAllow, address initialOwner) public virtual initializer {
    __PolicyEngine_init(defaultAllow, initialOwner);
  }

  function __PolicyEngine_init(bool defaultAllow, address initialOwner) internal onlyInitializing {
    __PolicyEngine_init_unchained(defaultAllow, initialOwner);
    __AccessControl_init_unchained();
  }

  function __PolicyEngine_init_unchained(bool defaultAllow, address initialOwner) internal onlyInitializing {
    _policyEngineStorage().defaultPolicyAllow = defaultAllow;
    emit DefaultPolicyAllowSet(defaultAllow);
    _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
    _grantRole(ADMIN_ROLE, initialOwner);
    _grantRole(POLICY_CONFIG_ADMIN_ROLE, initialOwner);
  }

  /// @inheritdoc IPolicyEngine
  function attach() public {
    _attachTarget(msg.sender);
  }

  function _attachTarget(address target) internal {
    if (_policyEngineStorage().targetAttached[target]) {
      revert IPolicyEngine.TargetAlreadyAttached(target);
    }
    _policyEngineStorage().targetAttached[target] = true;
    emit TargetAttached(target);
  }

  /// @inheritdoc IPolicyEngine
  function detach() public {
    _detachTarget(msg.sender);
  }

  function _detachTarget(address target) internal {
    if (!_policyEngineStorage().targetAttached[target]) {
      revert IPolicyEngine.TargetNotAttached(target);
    }
    _policyEngineStorage().targetAttached[target] = false;
    emit TargetDetached(target);
  }

  /// @inheritdoc IPolicyEngine
  function setDefaultPolicyAllow(bool defaultAllow) public onlyRole(ADMIN_ROLE) {
    _policyEngineStorage().defaultPolicyAllow = defaultAllow;
    emit DefaultPolicyAllowSet(defaultAllow);
  }

  /// @inheritdoc IPolicyEngine
  function setTargetDefaultPolicyAllow(address target, bool defaultAllow) public onlyRole(ADMIN_ROLE) {
    PolicyEngineStorage storage $ = _policyEngineStorage();
    $.targetHasDefault[target] = true;
    $.targetDefaultPolicyAllow[target] = defaultAllow;
    emit TargetDefaultPolicyAllowSet(target, defaultAllow);
  }

  /// @inheritdoc IPolicyEngine
  function setPolicyMapper(address policy, address mapper) public onlyRole(ADMIN_ROLE) {
    _policyEngineStorage().policyMappers[policy] = mapper;
    emit PolicyMapperSet(policy, mapper);
  }

  /// @inheritdoc IPolicyEngine
  function getPolicyMapper(address policy) external view returns (address) {
    return _policyEngineStorage().policyMappers[policy];
  }

  /// @inheritdoc IPolicyEngine
  function check(IPolicyEngine.Payload calldata payload) public view virtual override {
    address[] memory policies = _policyEngineStorage().targetPolicies[msg.sender][payload.selector];

    if (policies.length == 0) {
      _checkDefaultPolicyAllowRevert(msg.sender, payload);
      return;
    }

    IPolicyEngine.Parameter[] memory extractedParameters = _extractParameters(payload);
    for (uint256 i = 0; i < policies.length; i++) {
      address policy = policies[i];

      bytes[] memory policyParameterValues = _policyParameterValues(
        policy,
        _policyEngineStorage().targetPolicyParameters[msg.sender][payload.selector][policy],
        extractedParameters,
        payload
      );
      try IPolicy(policy).run(payload.sender, msg.sender, payload.selector, policyParameterValues, payload.context)
      returns (IPolicyEngine.PolicyResult policyResult) {
        if (policyResult == IPolicyEngine.PolicyResult.Allowed) {
          return;
        } // else continue to next policy
      } catch (bytes memory err) {
        _handlePolicyError(payload, policy, err);
      }
    }

    _checkDefaultPolicyAllowRevert(msg.sender, payload);
  }

  /// @inheritdoc IPolicyEngine
  function run(IPolicyEngine.Payload calldata payload) public virtual override {
    address[] memory policies = _policyEngineStorage().targetPolicies[msg.sender][payload.selector];
    IPolicyEngine.Parameter[] memory extractedParameters = _extractParameters(payload);
    if (policies.length == 0) {
      _checkDefaultPolicyAllowRevert(msg.sender, payload);
      emit PolicyRunComplete(payload.sender, msg.sender, payload.selector, extractedParameters, payload.context);
      return;
    }

    for (uint256 i = 0; i < policies.length; i++) {
      address policy = policies[i];

      bytes[] memory policyParameterValues = _policyParameterValues(
        policy,
        _policyEngineStorage().targetPolicyParameters[msg.sender][payload.selector][policy],
        extractedParameters,
        payload
      );
      try IPolicy(policy).run(payload.sender, msg.sender, payload.selector, policyParameterValues, payload.context)
      returns (IPolicyEngine.PolicyResult policyResult) {
        // solhint-disable-next-line no-empty-blocks
        try IPolicy(policy).postRun(
          payload.sender, msg.sender, payload.selector, policyParameterValues, payload.context
        ) {} catch (bytes memory err) {
          revert IPolicyEngine.PolicyPostRunError(policy, err, payload);
        }
        if (policyResult == IPolicyEngine.PolicyResult.Allowed) {
          emit PolicyRunComplete(payload.sender, msg.sender, payload.selector, extractedParameters, payload.context);
          return;
        }
      } catch (bytes memory err) {
        _handlePolicyError(payload, policy, err);
      }
    }

    _checkDefaultPolicyAllowRevert(msg.sender, payload);
    emit PolicyRunComplete(payload.sender, msg.sender, payload.selector, extractedParameters, payload.context);
  }

  /// @inheritdoc IPolicyEngine
  function setExtractor(bytes4 selector, address extractor) public virtual override onlyRole(ADMIN_ROLE) {
    _setExtractor(selector, extractor);
  }

  /// @inheritdoc IPolicyEngine
  function setExtractors(bytes4[] calldata selectors, address extractor) public virtual override onlyRole(ADMIN_ROLE) {
    for (uint256 i = 0; i < selectors.length; i++) {
      _setExtractor(selectors[i], extractor);
    }
  }

  function _setExtractor(bytes4 selector, address extractor) internal {
    _policyEngineStorage().extractorBySelector[selector] = extractor;
    emit ExtractorSet(selector, extractor);
  }

  /// @inheritdoc IPolicyEngine
  function getExtractor(bytes4 selector) public view virtual override returns (address) {
    return _policyEngineStorage().extractorBySelector[selector];
  }

  /// @inheritdoc IPolicyEngine
  function addPolicy(
    address target,
    bytes4 selector,
    address policy,
    bytes32[] calldata policyParameterNames
  )
    public
    virtual
    override
    onlyRole(ADMIN_ROLE)
  {
    _checkPolicyConfiguration(target, selector, policy);
    _policyEngineStorage().targetPolicies[target][selector].push(policy);
    _policyEngineStorage().targetPolicyParameters[target][selector][policy] = policyParameterNames;
    IPolicy(policy).onInstall(selector);
    emit PolicyAdded(
      target, selector, policy, _policyEngineStorage().targetPolicies[target][selector].length - 1, policyParameterNames
    );
  }

  /// @inheritdoc IPolicyEngine
  function addPolicyAt(
    address target,
    bytes4 selector,
    address policy,
    bytes32[] calldata policyParameterNames,
    uint256 position
  )
    public
    virtual
    override
    onlyRole(ADMIN_ROLE)
  {
    address[] storage policies = _policyEngineStorage().targetPolicies[target][selector];
    if (position > policies.length) {
      revert Policy.InvalidParameters("Position is greater than the number of policies");
    }
    _checkPolicyConfiguration(target, selector, policy);
    policies.push();
    for (uint256 i = policies.length - 1; i > position; i--) {
      policies[i] = policies[i - 1];
    }
    policies[position] = policy;
    _policyEngineStorage().targetPolicyParameters[target][selector][policy] = policyParameterNames;
    IPolicy(policy).onInstall(selector);
    emit PolicyAddedAt(target, selector, policy, position, policyParameterNames, policies);
  }

  /// @inheritdoc IPolicyEngine
  function removePolicy(address target, bytes4 selector, address policy) public virtual override onlyRole(ADMIN_ROLE) {
    address[] storage policies = _policyEngineStorage().targetPolicies[target][selector];
    address removedPolicy = address(0);
    for (uint256 i = 0; i < policies.length; i++) {
      if (policies[i] == policy) {
        removedPolicy = policies[i];
        for (uint256 j = i; j < policies.length - 1; j++) {
          policies[j] = policies[j + 1];
        }
        policies.pop();
        emit PolicyRemoved(target, selector, policy);
        break;
      }
    }
    if (removedPolicy != address(0)) {
      IPolicy(policy).onUninstall(selector);
    }
  }

  /// @inheritdoc IPolicyEngine
  function getPolicies(
    address target,
    bytes4 selector
  )
    public
    view
    virtual
    override
    returns (address[] memory policies)
  {
    return _policyEngineStorage().targetPolicies[target][selector];
  }

  function setPolicyConfiguration(
    address policy,
    uint256 configVersion,
    bytes4 configSelector,
    bytes calldata configData
  )
    public
    virtual
    override
    onlyRole(POLICY_CONFIG_ADMIN_ROLE)
  {
    if (_policyEngineStorage().policyConfigVersions[policy] != configVersion) {
      revert IPolicyEngine.PolicyConfigurationVersionError(
        policy, configVersion, _policyEngineStorage().policyConfigVersions[policy]
      );
    }
    _policyEngineStorage().policyConfigVersions[policy]++;
    (bool success, bytes memory result) = policy.call(abi.encodePacked(configSelector, configData));
    if (!success) {
      revert IPolicyEngine.PolicyConfigurationError(policy, result);
    }
    emit PolicyConfigured(policy, configVersion, configSelector, configData);
  }

  function getPolicyConfigVersion(address policy) public view virtual override returns (uint256) {
    return _policyEngineStorage().policyConfigVersions[policy];
  }

  function _handlePolicyError(Payload memory payload, address policy, bytes memory err) internal pure {
    (bytes4 errorSelector, bytes memory errorData) = _decodeError(err);
    if (errorSelector == IPolicyEngine.PolicyRejected.selector) {
      revert IPolicyEngine.PolicyRunRejected(policy, abi.decode(errorData, (string)), payload);
    } else {
      revert IPolicyEngine.PolicyRunError(policy, err, payload);
    }
  }

  function _checkDefaultPolicyAllowRevert(address target, IPolicyEngine.Payload memory payload) private view {
    PolicyEngineStorage storage $ = _policyEngineStorage();
    bool defaultAllow = $.defaultPolicyAllow;
    if ($.targetHasDefault[target]) {
      defaultAllow = $.targetDefaultPolicyAllow[target];
    }
    if (!defaultAllow) {
      revert IPolicyEngine.PolicyRunRejected(address(0), "no policy allowed the action and default is reject", payload);
    }
  }

  function _checkPolicyConfiguration(address target, bytes4 selector, address policy) private view {
    if (policy == address(0)) {
      revert Policy.InvalidParameters("Policy address cannot be zero");
    }
    if (_policyEngineStorage().targetPolicies[target][selector].length >= MAX_POLICIES) {
      revert Policy.InvalidParameters("Maximum policies reached");
    }
    address[] memory policies = _policyEngineStorage().targetPolicies[target][selector];
    for (uint256 i = 0; i < policies.length; i++) {
      if (policies[i] == policy) {
        revert Policy.InvalidParameters("Policy already added");
      }
    }
  }

  function _extractParameters(IPolicyEngine.Payload memory payload)
    private
    view
    returns (IPolicyEngine.Parameter[] memory)
  {
    IExtractor extractor = IExtractor(_policyEngineStorage().extractorBySelector[payload.selector]);
    IPolicyEngine.Parameter[] memory extractedParameters;

    if (address(extractor) == address(0)) {
      return extractedParameters;
    }

    try extractor.extract(payload) returns (IPolicyEngine.Parameter[] memory _extractedParameters) {
      extractedParameters = _extractedParameters;
    } catch (bytes memory err) {
      revert IPolicyEngine.ExtractorError(address(extractor), err, payload);
    }

    return extractedParameters;
  }

  function _policyParameterValues(
    address policy,
    bytes32[] memory policyParameterNames,
    IPolicyEngine.Parameter[] memory extractedParameters,
    IPolicyEngine.Payload memory payload
  )
    private
    view
    returns (bytes[] memory)
  {
    address mapper = _policyEngineStorage().policyMappers[policy];
    // use custom mapper if set
    if (mapper != address(0)) {
      try IMapper(mapper).map(extractedParameters) returns (bytes[] memory mappedParameters) {
        return mappedParameters;
      } catch (bytes memory err) {
        revert IPolicyEngine.PolicyMapperError(policy, err, payload);
      }
    }

    bytes[] memory policyParameterValues = new bytes[](policyParameterNames.length);

    uint256 parameterCount = policyParameterNames.length;
    if (parameterCount == 0) {
      return policyParameterValues;
    }

    uint256 mappedParameterCount = 0;
    for (uint256 i = 0; i < extractedParameters.length; i++) {
      for (uint256 j = 0; j < parameterCount; j++) {
        if (extractedParameters[i].name == policyParameterNames[j]) {
          policyParameterValues[j] = extractedParameters[i].value;
          mappedParameterCount++;
          break;
        }
      }
      if (mappedParameterCount == parameterCount) {
        return policyParameterValues;
      }
    }
    revert Policy.InvalidParameters("Missing policy parameters");
  }

  function _decodeError(bytes memory err) internal pure returns (bytes4, bytes memory) {
    // If the error length is less than 4, it is not a valid error
    if (err.length < 4) {
      return (0, err);
    }
    bytes4 selector = bytes4(err);
    bytes memory errorData = new bytes(err.length - 4);
    for (uint256 i = 0; i < err.length - 4; i++) {
      errorData[i] = err[i + 4];
    }
    return (selector, errorData);
  }
}
