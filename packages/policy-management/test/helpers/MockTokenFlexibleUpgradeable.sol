// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {PolicyProtectedFlexibleUpgradeable} from "../../src/core/PolicyProtectedFlexibleUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract MockTokenFlexibleUpgradeable is UUPSUpgradeable, PolicyProtectedFlexibleUpgradeable, OwnableUpgradeable {
  mapping(address account => uint256 balance) public s_balances;
  uint256 public totalSupply = 0;
  bool public paused;

  error Paused();

  modifier whenNotPaused() {
    if (paused) {
      revert Paused();
    }
    _;
  }

  // disabling initializers on the implementation contract itself
  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  function initialize(address policyEngine) external initializer {
    __Ownable_init(msg.sender);
    __PolicyProtectedFlexible_init(policyEngine);
  }

  // Authorize contract upgrades to only the owner
  // solhint-disable-next-line no-empty-blocks
  function _authorizeUpgrade(address) internal override onlyOwner {}

  function _authorizeAttachPolicyEngine(address) internal override onlyOwner {}

  function transfer(address to, uint256 amount) external whenNotPaused runPolicy {
    s_balances[to] += amount;
  }

  function transferWithContext(
    address to,
    uint256 amount,
    bytes calldata context
  )
    external
    whenNotPaused
    runPolicyWithContext(context)
  {
    s_balances[to] += amount;
  }

  function transferFrom(
    address,
    /*from*/
    address to,
    uint256 amount
  )
    external
    whenNotPaused
    runPolicy
  {
    s_balances[to] += amount;
  }

  function balanceOf(address account) external view returns (uint256) {
    return s_balances[account];
  }

  function mint(address to, uint256 amount) external whenNotPaused runPolicy {
    s_balances[to] += amount;
    totalSupply += amount;
  }

  function burn(address to, uint256 amount) external whenNotPaused runPolicy {
    s_balances[to] -= amount;
    totalSupply -= amount;
  }

  function pause() external runPolicy {
    paused = true;
  }

  function unpause() external runPolicy {
    paused = false;
  }
}
