// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IConfigVersionController} from "../interfaces/IConfigVersionController.sol";

/**
 * @title ConfigVersionController
 * @notice Reusable base for data validators that expose version-checked configuration updates.
 * @author Chainlink
 */
abstract contract ConfigVersionController is OwnableUpgradeable, IConfigVersionController {
  error UnexpectedConfigVersion(uint256 expectedVersion, uint256 actualVersion);
  error InvalidConfigCall();
  error UnsupportedConfigSelector(bytes4 selector);
  error ConfigurationError(bytes4 selector, bytes errorReason);
  error OnlyConfigEntry();

  /// @custom:storage-location erc7201:chainlink.ace.ConfigVersionController
  struct ConfigVersionControllerStorage {
    uint256 configVersion;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.ConfigVersionController")) - 1)) & ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant configVersionControllerStorageLocation =
    0x9bfe4fb656749837983e975f9d947672ae0b14ebe74a220348e77701d34a8f00;

  /**
   * @notice Restricts a function so it can only be reached via configure self-calls.
   */
  modifier onlyConfigEntry() {
    if (msg.sender != address(this)) {
      revert OnlyConfigEntry();
    }
    _;
  }

  /**
   * @notice Applies a configuration action after validating the expected version.
   * @param expectedCurrentVersion The version the caller expects before applying the change.
   * @param configCall ABI-encoded call data for a supported configuration action.
   * @return newVersion The updated configuration version.
   */
  function configure(
    uint256 expectedCurrentVersion,
    bytes calldata configCall
  )
    external
    onlyOwner
    returns (uint256 newVersion)
  {
    _assertConfigVersion(expectedCurrentVersion);

    bytes4 selector = _getSelector(configCall);
    if (!_isSupportedConfigSelector(selector)) {
      revert UnsupportedConfigSelector(selector);
    }

    // solhint-disable-next-line avoid-low-level-calls
    (bool ok, bytes memory returndata) = address(this).call(configCall);
    if (!ok) {
      revert ConfigurationError(selector, returndata);
    }

    newVersion = _incrementConfigVersion();
    emit ConfigurationUpdated(expectedCurrentVersion, newVersion, selector, configCall);
  }

  /// @inheritdoc IConfigVersionController
  function getConfigVersion() public view returns (uint256) {
    return _configVersionControllerStorage().configVersion;
  }

  /**
   * @notice Returns the storage pointer for the shared version state.
   * @return $ The shared data validator storage struct.
   */
  function _configVersionControllerStorage() private pure returns (ConfigVersionControllerStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := configVersionControllerStorageLocation
    }
  }

  /**
   * @notice Reverts unless the supplied version matches the current stored version.
   * @param expectedCurrentVersion The caller-provided version.
   */
  function _assertConfigVersion(uint256 expectedCurrentVersion) internal view {
    uint256 currentVersion = _configVersionControllerStorage().configVersion;
    if (currentVersion != expectedCurrentVersion) {
      revert UnexpectedConfigVersion(expectedCurrentVersion, currentVersion);
    }
  }

  /**
   * @notice Sets configuration version to 1 after initializer applies bundled config.
   * @dev Invoked once from `initialize`; not used by `configure`.
   */
  function _bootstrapConfigVersion() internal {
    _configVersionControllerStorage().configVersion = 1;
  }

  /**
   * @notice Increments the stored configuration version after a successful config action.
   * @return newVersion The newly stored version.
   */
  function _incrementConfigVersion() internal returns (uint256 newVersion) {
    ConfigVersionControllerStorage storage $ = _configVersionControllerStorage();
    newVersion = ++$.configVersion;
  }

  /**
   * @notice Extracts the function selector from an encoded config call.
   * @param configCall The encoded call data.
   * @return selector The extracted selector.
   */
  function _getSelector(bytes calldata configCall) internal pure returns (bytes4 selector) {
    if (configCall.length < 4) {
      revert InvalidConfigCall();
    }
    return bytes4(configCall[:4]);
  }

  /**
   * @notice Returns whether a selector is a supported configuration action.
   * @param selector The selector to check.
   * @return True if the selector is supported by configure.
   */
  function _isSupportedConfigSelector(bytes4 selector) internal view virtual returns (bool);
}
