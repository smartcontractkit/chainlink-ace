// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MockToken is Initializable, PolicyProtected {
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

  function initialize(address policyEngine) external initializer {
    __PolicyProtected_init(msg.sender, policyEngine);
  }

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

  function transferFrom(address, /*from*/ address to, uint256 amount) external whenNotPaused runPolicy {
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
