// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ICredentialDataValidator} from "../../src/interfaces/ICredentialDataValidator.sol";

contract MockCredentialDataValidator is ICredentialDataValidator {
  bool private s_dataValid;

  function setDataValid(bool dataValid) public {
    s_dataValid = dataValid;
  }

  function validateCredentialData(
    bytes32, /*ccid*/
    address, /*account*/
    bytes32, /*credentialTypeId*/
    bytes calldata, /*credentialData*/
    bytes calldata /*context*/
  )
    external
    view
    returns (bool)
  {
    return s_dataValid;
  }
}
