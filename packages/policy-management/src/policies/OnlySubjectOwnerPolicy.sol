// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {Policy} from "../core/Policy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title OnlySubjectOwnerPolicy
 * @notice A policy that only allows the owner of the subject contract to call the method. Can
 * only be applied to Ownable subjects, otherwise it will reject all transactions.
 */
contract OnlySubjectOwnerPolicy is Policy {
  string public constant override typeAndVersion = "OnlySubjectOwnerPolicy 1.1.1";

  // disabling initializers on the implementation contract itself
  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  function run(
    address caller,
    address subject,
    bytes4, /*selector*/
    bytes[] calldata, /*parameters*/
    bytes calldata /*context*/
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    address subjectOwner;
    try Ownable(subject).owner() returns (address owner) {
      subjectOwner = owner;
    } catch {
      revert IPolicyEngine.PolicyRejected("subject contract is not Ownable");
    }

    if (caller != subjectOwner) {
      revert IPolicyEngine.PolicyRejected("caller is not the subject owner");
    }

    return IPolicyEngine.PolicyResult.Continue;
  }
}
