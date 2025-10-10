// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// This is a mock contract representing a public sanctions list.
// In a real-world scenario, this would be a highly secure contract managed by a trusted data provider.
contract SanctionsList is Ownable {
  mapping(address => bool) public isSanctioned;

  event AddedToSanctionsList(address indexed account);
  event RemovedFromSanctionsList(address indexed account);

  constructor() Ownable(msg.sender) {}

  function add(address _account) public onlyOwner {
    isSanctioned[_account] = true;
    emit AddedToSanctionsList(_account);
  }

  function remove(address _account) public onlyOwner {
    isSanctioned[_account] = false;
    emit RemovedFromSanctionsList(_account);
  }
}
