// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {Policy} from "../../packages/policy-management/src/core/Policy.sol";
import {IPolicyEngine} from "../../packages/policy-management/src/interfaces/IPolicyEngine.sol";
import {SanctionsList} from "./SanctionsList.sol";

contract SanctionsPolicy is Policy {
  address public sanctionsList;

  /**
   * @notice Configures the policy with the sanctions list address.
   * @dev This is called automatically during initialization.
   * @param parameters ABI-encoded address of the SanctionsList contract.
   */
  function configure(bytes calldata parameters) internal override onlyInitializing {
    require(parameters.length > 0, "SanctionsPolicy: configData required");
    address _sanctionsList = abi.decode(parameters, (address));
    _setSanctionsList(_sanctionsList);
  }

  /// @notice Allows updating the sanctions list address after deployment.
  function setSanctionsList(address _listAddress) public onlyOwner {
    _setSanctionsList(_listAddress);
  }

  /// @notice Internal function to validate and set the sanctions list address.
  function _setSanctionsList(address _listAddress) private {
    require(_listAddress != address(0), "SanctionsPolicy: Invalid address");
    sanctionsList = _listAddress;
  }

  function run(
    address, /* caller */
    address, /* subject */
    bytes4, /* selector */
    bytes[] calldata parameters,
    bytes calldata /* context */
  )
    public
    view
    override
    returns (IPolicyEngine.PolicyResult)
  {
    require(parameters.length == 1, "SanctionsPolicy: Expected 1 parameter");
    // This policy expects the "to" address as the first parameter
    address recipient = abi.decode(parameters[0], (address));

    SanctionsList _sl = SanctionsList(sanctionsList);

    // If the recipient is on the list, reject the transaction.
    if (_sl.isSanctioned(recipient)) {
      revert IPolicyEngine.PolicyRejected("account sanctions validation failed");
    }

    return IPolicyEngine.PolicyResult.Continue;
  }
}
