// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {IAdvancedPoolHooks} from "@chainlink/contracts-ccip/interfaces/IAdvancedPoolHooks.sol";
import {IBurnMintERC20} from "@chainlink/contracts-ccip/interfaces/IBurnMintERC20.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {Policy} from "../../src/core/Policy.sol";
import {VolumePolicy} from "../../src/policies/VolumePolicy.sol";
import {AdvancedPoolHooksExtractor} from "@chainlink/contracts-ccip/pools/extractors/AdvancedPoolHooksExtractor.sol";
import {AdvancedPoolHooks} from "@chainlink/contracts-ccip/pools/AdvancedPoolHooks.sol";
import {AuthorizedCallers} from "@chainlink/contracts/src/v0.8/shared/access/AuthorizedCallers.sol";
import {BurnMintTokenPool} from "@chainlink/contracts-ccip/pools/BurnMintTokenPool.sol";
import {TokenPool} from "@chainlink/contracts-ccip/pools/TokenPool.sol";
import {OnRampSetup} from "@chainlink/contracts-ccip/test/onRamp/OnRamp/OnRampSetup.t.sol";
import {BurnMintERC20} from "@chainlink/contracts/src/v0.8/shared/token/ERC20/BurnMintERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts@5.3.0/proxy/ERC1967/ERC1967Proxy.sol";

contract AdvancedPoolHooksE2ESetup is OnRampSetup {
  PolicyEngine internal s_policyEngine;
  AdvancedPoolHooksExtractor internal s_extractor;
  VolumePolicy internal s_volumePolicy;

  AdvancedPoolHooks internal s_advancedPoolHooks;
  BurnMintTokenPool internal s_burnMintPool;
  BurnMintERC20 internal s_aceToken;

  address internal s_receiver = makeAddr("receiver");

  string internal constant VOLUME_POLICY_REJECT_REASON = "amount outside allowed volume limits";

  uint256 internal constant VOLUME_MIN = 10e18;
  uint256 internal constant VOLUME_MAX = 1000e18;
  uint256 internal constant VALID_AMOUNT = 100e18;
  uint256 internal constant TOO_HIGH_AMOUNT = 1001e18;
  uint256 internal constant TOO_LOW_AMOUNT = 5e18;

  function setUp() public virtual override {
    super.setUp();

    // Test with an existing token commonly used by customers.
    s_aceToken = new BurnMintERC20("ACE Test Token", "ACET", 18, 0, 0);

    PolicyEngine policyEngineImpl = new PolicyEngine();
    bytes memory policyEngineData = abi.encodeCall(PolicyEngine.initialize, (true, OWNER));
    s_policyEngine = PolicyEngine(address(new ERC1967Proxy(address(policyEngineImpl), policyEngineData)));

    s_extractor = new AdvancedPoolHooksExtractor();

    s_policyEngine.setExtractor(IAdvancedPoolHooks.preflightCheck.selector, address(s_extractor));
    s_policyEngine.setExtractor(IAdvancedPoolHooks.postflightCheck.selector, address(s_extractor));

    VolumePolicy volumePolicyImpl = new VolumePolicy();
    bytes memory policyData =
      abi.encodeCall(Policy.initialize, (address(s_policyEngine), OWNER, abi.encode(VOLUME_MIN, VOLUME_MAX)));
    s_volumePolicy = VolumePolicy(address(new ERC1967Proxy(address(volumePolicyImpl), policyData)));

    s_advancedPoolHooks = new AdvancedPoolHooks(new address[](0), 0, address(s_policyEngine), new address[](0));

    bytes32[] memory volumeParams = new bytes32[](1);
    volumeParams[0] = s_extractor.PARAM_AMOUNT();

    s_policyEngine.addPolicy(
      address(s_advancedPoolHooks), IAdvancedPoolHooks.preflightCheck.selector, address(s_volumePolicy), volumeParams
    );

    s_policyEngine.addPolicy(
      address(s_advancedPoolHooks), IAdvancedPoolHooks.postflightCheck.selector, address(s_volumePolicy), volumeParams
    );

    s_burnMintPool = new BurnMintTokenPool(
      IBurnMintERC20(address(s_aceToken)),
      18,
      address(s_advancedPoolHooks),
      address(s_mockRMNRemote),
      address(s_sourceRouter)
    );

    s_aceToken.grantMintAndBurnRoles(address(s_burnMintPool));

    // Pool must be an authorized caller on hooks to invoke preflight/postflight checks
    address[] memory addedCallers = new address[](1);
    addedCallers[0] = address(s_burnMintPool);
    s_advancedPoolHooks.applyAuthorizedCallerUpdates(
      AuthorizedCallers.AuthorizedCallerArgs({addedCallers: addedCallers, removedCallers: new address[](0)})
    );

    s_tokenAdminRegistry.proposeAdministrator(address(s_aceToken), OWNER);
    s_tokenAdminRegistry.acceptAdminRole(address(s_aceToken));
    s_tokenAdminRegistry.setPool(address(s_aceToken), address(s_burnMintPool));

    bytes[] memory remotePoolAddresses = new bytes[](1);
    remotePoolAddresses[0] = abi.encode(address(s_burnMintPool));
    TokenPool.ChainUpdate[] memory chainUpdate = new TokenPool.ChainUpdate[](1);
    chainUpdate[0] = TokenPool.ChainUpdate({
      remoteChainSelector: DEST_CHAIN_SELECTOR,
      remotePoolAddresses: remotePoolAddresses,
      remoteTokenAddress: abi.encode(address(s_aceToken)),
      outboundRateLimiterConfig: _getOutboundRateLimiterConfig(),
      inboundRateLimiterConfig: _getInboundRateLimiterConfig()
    });
    s_burnMintPool.applyChainUpdates(new uint64[](0), chainUpdate);

    bytes[] memory remotePoolAddressesSrc = new bytes[](1);
    remotePoolAddressesSrc[0] = abi.encode(address(s_burnMintPool));
    TokenPool.ChainUpdate[] memory chainUpdateSrc = new TokenPool.ChainUpdate[](1);
    chainUpdateSrc[0] = TokenPool.ChainUpdate({
      remoteChainSelector: SOURCE_CHAIN_SELECTOR,
      remotePoolAddresses: remotePoolAddressesSrc,
      remoteTokenAddress: abi.encode(address(s_aceToken)),
      outboundRateLimiterConfig: _getOutboundRateLimiterConfig(),
      inboundRateLimiterConfig: _getInboundRateLimiterConfig()
    });
    s_burnMintPool.applyChainUpdates(new uint64[](0), chainUpdateSrc);

    s_feeQuoter.updatePrices(_getSingleTokenPriceUpdateStruct(address(s_aceToken), 1e18));
  }
}
