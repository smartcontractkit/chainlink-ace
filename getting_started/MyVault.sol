// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {PolicyProtected} from "@chainlink/policy-management/core/PolicyProtected.sol";

/**
 * @title MyVault
 * @notice A simple vault contract with policy-protected deposits and withdrawals.
 * @dev This example demonstrates the minimal integration required to make a contract compliant with ACE.
 * Both the `deposit` and `withdraw` functions are protected with the `runPolicy` modifier.
 * This contract is designed to be deployed behind a proxy for upgradeability.
 */
contract MyVault is PolicyProtected {
  mapping(address => uint256) public deposits;

  function initialize(address initialOwner, address policyEngine) public initializer {
    __PolicyProtected_init(initialOwner, policyEngine);
  }

  /**
   * @notice Deposits funds into the vault for the caller.
   * @dev This function is protected by the `runPolicy` modifier, which routes the call
   * through the PolicyEngine for validation before executing the deposit.
   * @param amount The amount to deposit.
   */
  function deposit(uint256 amount) public runPolicy {
    deposits[msg.sender] += amount;
  }

  /**
   * @notice Withdraws funds from the vault for the caller.
   * @dev This function is protected by the `runPolicy` modifier, which routes the call
   * through the PolicyEngine for validation before executing the withdrawal.
   * @param amount The amount to withdraw.
   */
  function withdraw(uint256 amount) public runPolicy {
    require(deposits[msg.sender] >= amount, "Insufficient balance");
    deposits[msg.sender] -= amount;
  }

  /**
   * @notice Returns the total deposits in the vault.
   * @return The sum of all deposits.
   */
  function totalDeposits() public view returns (uint256) {
    return address(this).balance;
  }
}
