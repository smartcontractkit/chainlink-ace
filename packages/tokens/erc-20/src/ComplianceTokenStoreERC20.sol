// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

contract ComplianceTokenStoreERC20 {
  /// @custom:storage-location erc7201:compliance-token-erc20.ComplianceTokenStoreERC20
  struct ComplianceTokenStorage {
    string name;
    string symbol;
    uint8 decimals;
    uint256 totalSupply;
    mapping(address account => uint256 balance) balances;
    mapping(address account => mapping(address spender => uint256 allowance)) allowances;
    mapping(address account => uint256 amount) frozenBalances;
    mapping(bytes32 key => bytes data) data;
  }

  // keccak256(abi.encode(uint256(keccak256("compliance-token-erc20.ComplianceTokenStoreERC20")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant complianceTokenStorageLocation =
    0xeb7f727e418fdce2e00aa1f4b00053561f65d67239278319bdbcc2711bc43500;

  function getComplianceTokenStorage() internal pure returns (ComplianceTokenStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := complianceTokenStorageLocation
    }
  }
}
