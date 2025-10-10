// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IExtractor} from "../interfaces/IExtractor.sol";
import {IMapper} from "../interfaces/IMapper.sol";
import {IPolicy} from "../interfaces/IPolicy.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract PolicyEngine is Initializable, OwnableUpgradeable, IPolicyEngine {
  uint256 private constant MAX_POLICIES = 8;

  /// @custom:storage-location erc7201:policy-management.PolicyEngine
  struct PolicyEngineStorage {
    bool defaultPolicyAllow;
    mapping(bytes4 selector => address extractor) extractorBySelector;
    mapping(address policy => address mapper) policyMappers;
    mapping(address target => bool attached) targetAttached;
    mapping(address target => mapping(bytes4 selector => address[] policies)) targetPolicies;
    mapping(address target => mapping(bytes4 selector => mapping(address policy => bytes32[] policyParameterNames)))
      targetPolicyParameters;
    mapping(address target => bool hasTargetDefault) targetHasDefault;
    mapping(address target => bool targetDefaultPolicyAllow) targetDefaultPolicyAllow;
  }

  // keccak256(abi.encode(uint256(keccak256("policy-management.PolicyEngine")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant policyEngineStorageLocation =
    0xa1f0e32dde2a220dbeed9998863e2afeb333bc7b502562572bef1aa4cf5bf300;

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
    __PolicyEngine_init_unchained(defaultAllow);
    __Ownable_init(initialOwner);
  }

  function __PolicyEngine_init_unchained(bool defaultAllow) internal onlyInitializing {
    _policyEngineStorage().defaultPolicyAllow = defaultAllow;
  }

  /// @inheritdoc IPolicyEngine
  // TODO: need to review the permissioing of this function
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
  // TODO: need to review the permissioing of this function
  function detach() public {
    if (!_policyEngineStorage().targetAttached[msg.sender]) {
      revert IPolicyEngine.TargetNotAttached(msg.sender);
    }
    _policyEngineStorage().targetAttached[msg.sender] = false;
    emit TargetDetached(msg.sender);
  }

  /// @inheritdoc IPolicyEngine
  function setDefaultPolicyAllow(bool defaultAllow) public onlyOwner {
    _policyEngineStorage().defaultPolicyAllow = defaultAllow;
    emit DefaultPolicyAllowSet(defaultAllow);
  }

  /// @inheritdoc IPolicyEngine
  function setTargetDefaultPolicyAllow(address target, bool defaultAllow) public onlyOwner {
    PolicyEngineStorage storage $ = _policyEngineStorage();
    $.targetHasDefault[target] = true;
    $.targetDefaultPolicyAllow[target] = defaultAllow;
    emit TargetDefaultPolicyAllowSet(target, defaultAllow);
  }

  /// @inheritdoc IPolicyEngine
  function setPolicyMapper(address policy, address mapper) public onlyOwner {
    _policyEngineStorage().policyMappers[policy] = mapper;
  }

  /// @inheritdoc IPolicyEngine
  function getPolicyMapper(address policy) external view returns (address) {
    return _policyEngineStorage().policyMappers[policy];
  }

  /// @inheritdoc IPolicyEngine
  function check(IPolicyEngine.Payload calldata payload) public view virtual override {
    address[] memory policies = _policyEngineStorage().targetPolicies[msg.sender][payload.selector];

    if (policies.length == 0) {
      _checkDefaultPolicyAllowRevert(msg.sender, payload.selector);
      return;
    }

    IPolicyEngine.Parameter[] memory extractedParameters = _extractParameters(payload);
    for (uint256 i = 0; i < policies.length; i++) {
      address policy = policies[i];

      bytes[] memory policyParameterValues = _policyParameterValues(
        policy, _policyEngineStorage().targetPolicyParameters[msg.sender][payload.selector][policy], extractedParameters
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

    _checkDefaultPolicyAllowRevert(msg.sender, payload.selector);
  }

  /// @inheritdoc IPolicyEngine
  function run(IPolicyEngine.Payload calldata payload) public virtual override {
    address[] memory policies = _policyEngineStorage().targetPolicies[msg.sender][payload.selector];
    if (policies.length == 0) {
      _checkDefaultPolicyAllowRevert(msg.sender, payload.selector);
      emit PolicyRunComplete(payload.sender, msg.sender, payload.selector);
      return;
    }

    IPolicyEngine.Parameter[] memory extractedParameters = _extractParameters(payload);
    for (uint256 i = 0; i < policies.length; i++) {
      address policy = policies[i];

      bytes[] memory policyParameterValues = _policyParameterValues(
        policy, _policyEngineStorage().targetPolicyParameters[msg.sender][payload.selector][policy], extractedParameters
      );
      try IPolicy(policy).run(payload.sender, msg.sender, payload.selector, policyParameterValues, payload.context)
      returns (IPolicyEngine.PolicyResult policyResult) {
        // solhint-disable-next-line no-empty-blocks
        try IPolicy(policy).postRun(
          payload.sender, msg.sender, payload.selector, policyParameterValues, payload.context
        ) {} catch (bytes memory err) {
          revert IPolicyEngine.PolicyPostRunError(payload.selector, policy, err);
        }
        if (policyResult == IPolicyEngine.PolicyResult.Allowed) {
          emit PolicyRunComplete(payload.sender, msg.sender, payload.selector);
          return;
        }
      } catch (bytes memory err) {
        _handlePolicyError(payload, policy, err);
      }
    }

    _checkDefaultPolicyAllowRevert(msg.sender, payload.selector);
    emit PolicyRunComplete(payload.sender, msg.sender, payload.selector);
  }

  /// @inheritdoc IPolicyEngine
  function setExtractor(bytes4 selector, address extractor) public virtual override onlyOwner {
    _policyEngineStorage().extractorBySelector[selector] = extractor;
    emit ExtractorSet(selector, extractor);
  }

  /// @inheritdoc IPolicyEngine
  function setExtractors(bytes4[] calldata selectors, address extractor) public virtual override onlyOwner {
    for (uint256 i = 0; i < selectors.length; i++) {
      setExtractor(selectors[i], extractor);
    }
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
    onlyOwner
  {
    _checkPolicyConfiguration(target, selector, policy);
    IPolicy(policy).onInstall(selector);
    _policyEngineStorage().targetPolicies[target][selector].push(policy);
    _policyEngineStorage().targetPolicyParameters[target][selector][policy] = policyParameterNames;
    emit PolicyAdded(target, selector, policy);
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
    onlyOwner
  {
    address[] storage policies = _policyEngineStorage().targetPolicies[target][selector];
    if (position > policies.length) {
      revert IPolicyEngine.InvalidConfiguration("Position is greater than the number of policies");
    }
    _checkPolicyConfiguration(target, selector, policy);
    IPolicy(policy).onInstall(selector);
    policies.push();
    for (uint256 i = policies.length - 1; i > position; i--) {
      policies[i] = policies[i - 1];
    }
    policies[position] = policy;
    _policyEngineStorage().targetPolicyParameters[target][selector][policy] = policyParameterNames;
    emit PolicyAdded(target, selector, policy);
  }

  /// @inheritdoc IPolicyEngine
  function removePolicy(address target, bytes4 selector, address policy) public virtual override onlyOwner {
    address[] storage policies = _policyEngineStorage().targetPolicies[target][selector];
    for (uint256 i = 0; i < policies.length; i++) {
      if (policies[i] == policy) {
        IPolicy(policy).onUninstall(selector);

        for (uint256 j = i; j < policies.length - 1; j++) {
          policies[j] = policies[j + 1];
        }

        policies.pop();
        emit PolicyRemoved(target, selector, policy);
        return;
      }
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

  function _handlePolicyError(Payload memory payload, address policy, bytes memory err) internal pure {
    (bytes4 errorSelector, bytes memory errorData) = _decodeError(err);
    if (errorSelector == IPolicyEngine.PolicyRejected.selector) {
      revert IPolicyEngine.PolicyRunRejected(payload.selector, policy, abi.decode(errorData, (string)));
    } else {
      revert IPolicyEngine.PolicyRunError(payload.selector, policy, err);
    }
  }

  function _checkDefaultPolicyAllowRevert(address target, bytes4 selector) private view {
    PolicyEngineStorage storage $ = _policyEngineStorage();
    bool defaultAllow = $.defaultPolicyAllow;
    if ($.targetHasDefault[target]) {
      defaultAllow = $.targetDefaultPolicyAllow[target];
    }
    if (!defaultAllow) {
      revert IPolicyEngine.PolicyRunRejected(0, address(0), "no policy allowed the action and default is reject");
    }
  }

  function _checkPolicyConfiguration(address target, bytes4 selector, address policy) private view {
    if (policy == address(0)) {
      revert IPolicyEngine.InvalidConfiguration("Policy address cannot be zero");
    }
    if (_policyEngineStorage().targetPolicies[target][selector].length >= MAX_POLICIES) {
      revert IPolicyEngine.InvalidConfiguration("Maximum policies reached");
    }
    address[] memory policies = _policyEngineStorage().targetPolicies[target][selector];
    for (uint256 i = 0; i < policies.length; i++) {
      if (policies[i] == policy) {
        revert IPolicyEngine.InvalidConfiguration("Policy already added");
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
      revert IPolicyEngine.ExtractorError(payload.selector, address(extractor), err);
    }

    return extractedParameters;
  }

  function _policyParameterValues(
    address policy,
    bytes32[] memory policyParameterNames,
    IPolicyEngine.Parameter[] memory extractedParameters
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
        revert IPolicyEngine.PolicyMapperError(policy, err);
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
    revert IPolicyEngine.InvalidConfiguration("Missing policy parameters");
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
