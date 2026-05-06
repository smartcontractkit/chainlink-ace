// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

contract ComplianceTokenStoreERC3643 {
  /// @custom:storage-location erc7201:chainlink.ace.ComplianceTokenStoreERC3643
  struct ComplianceTokenStorage {
    string tokenName;
    string tokenSymbol;
    uint8 tokenDecimals;
    bool tokenPaused;
    uint256 totalSupply;
    mapping(address userAddress => uint256 balance) balances;
    mapping(address userAddress => mapping(address spender => uint256 allowance)) allowances;
    mapping(address userAddress => bool isFrozen) frozen;
    mapping(address userAddress => uint256 amount) frozenTokens;
  }

  // keccak256(abi.encode(uint256(keccak256("chainlink.ace.ComplianceTokenStoreERC3643")) - 1)) &
  // ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 private constant complianceTokenStorageLocation =
    0x3f34113fb156b97e13dc3904401b33793726479947cfe0b61cd6a8cd6d196f00;

  function getComplianceTokenStorage() internal pure returns (ComplianceTokenStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := complianceTokenStorageLocation
    }
  }
}
