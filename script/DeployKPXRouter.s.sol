// SPDX-License-Identifier: MIT
// AXIOLEDGER  KINETOPROTOCOL ($KPX)
// DeployKPXRouter.s.sol  Chain-Aware Deployment Script
//
// Usage - Anvil:
//   forge script script/DeployKPXRouter.s.sol:DeployKPXRouter \
//     --rpc-url http://127.0.0.1:8545 \
//     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
//     --broadcast -vvvv
//
// Usage - Sepolia:
//   forge script script/DeployKPXRouter.s.sol:DeployKPXRouter \
//     --rpc-url $SEPOLIA_RPC_URL \
//     --private-key $DEPLOYER_PRIVATE_KEY \
//     --broadcast --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv

pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/KPXRouterGateway.sol";

// ---------------------------------------------------------------------------
// Mock contracts for local devnet
// ---------------------------------------------------------------------------

contract MockVRQVerifier {
    function isFlagged(address)                    external pure returns (bool)    { return false; }
    function verifyProof(bytes calldata, uint256[] calldata) external pure returns (bool) { return true; }
    function verifyCompliance(bytes calldata, bytes32) external pure returns (bool) { return true; }
    function circuitVersion()                      external pure returns (uint256) { return 1; }
    function isTxSafe(bytes32)                     external pure returns (bool)    { return true; }
}

contract MockDarkPool {
    function getInstitutionalThreshold() external pure returns (uint256) { return 1_000_000e18; }
    function executeConfidentialSwap(address, uint256 amountIn, address[] calldata, bytes calldata)
        external pure returns (uint256) { return amountIn * 99 / 100; }
    function placeSealedOrder(bytes32, uint256) external payable returns (bytes32) { return bytes32(0); }
    function isOrderActive(bytes32) external pure returns (bool) { return false; }
}

// ---------------------------------------------------------------------------
// Deploy script
// ---------------------------------------------------------------------------

contract DeployKPXRouter is Script {
    // Canonical chain IDs
    uint256 constant CHAIN_ANVIL   = 31337;
    uint256 constant CHAIN_SEPOLIA = 11155111;
    uint256 constant CHAIN_MAINNET = 1;

    function run() external {
        uint256 deployerKey = vm.envOr(
            "DEPLOYER_PRIVATE_KEY",
            uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
        );
        address deployer = vm.addr(deployerKey);
        bool    isMock   = block.chainid == CHAIN_ANVIL;

        // console.log("=================================================");
        // console.log("  KINETOPROTOCOL ($KPX)  Router Deployment");
        // console.log("=================================================");
        // console.log("Chain ID :", block.chainid);
        // console.log("Deployer :", deployer);
        // console.log("Balance  :", deployer.balance / 1e15, "milliETH");
        // console.log("Mocks    :", isMock ? "YES (devnet)" : "NO (staging)");
        // console.log("");

        // DAO address  deployer on testnet, MUST be replaced with multisig on mainnet
        address daoAddress = vm.envOr("DAO_MULTISIG_ADDRESS", deployer);
        if (block.chainid == CHAIN_MAINNET) {
            require(daoAddress != deployer, "MAINNET: DAO address must be a multisig, not the deployer EOA");
        }

        vm.startBroadcast(deployerKey);

        // Step 1: VRQ Verifier
        address vrqAddr = vm.envOr("VRQ_VERIFIER_ADDRESS", address(0));
        if (vrqAddr == address(0)) {
            MockVRQVerifier mockVrq = new MockVRQVerifier();
            vrqAddr = address(mockVrq);
            // console.log("[1] MockVRQVerifier:", vrqAddr);
            if (!isMock) console.log("    NOTE: Replace with production IVRQVerifier before mainnet");
        } else {
            // console.log("[1] VRQVerifier (from env):", vrqAddr);
        }

        // Step 2: Dark Pool
        address darkPoolAddr = vm.envOr("DARK_POOL_ADDRESS", address(0));
        if (darkPoolAddr == address(0)) {
            MockDarkPool mockDp = new MockDarkPool();
            darkPoolAddr = address(mockDp);
            // console.log("[2] MockDarkPool:", darkPoolAddr);
        } else {
            // console.log("[2] DarkPool (from env):", darkPoolAddr);
        }

        // Step 3: KPXRouterGateway
        KPXRouterGateway router = new KPXRouterGateway(
            vrqAddr,
            darkPoolAddr,
            daoAddress
        );
        // console.log("[3] KPXRouterGateway:", address(router));

        vm.stopBroadcast();

        // console.log("");
        // console.log("=================================================");
        // console.log("  DEPLOYED ADDRESSES");
        // console.log("=================================================");
        // console.log("VRQVerifier      :", vrqAddr);
        // console.log("DarkPool         :", darkPoolAddr);
        // console.log("KPXRouterGateway :", address(router));
        // console.log("TreasuryDAO      :", daoAddress);
        // console.log("=================================================");

        if (block.chainid == CHAIN_SEPOLIA || block.chainid == CHAIN_MAINNET) {
            // console.log("Etherscan verify:");
            // console.log("  forge verify-contract --chain", block.chainid);
            // console.log("  --constructor-args $(cast abi-encode 'constructor(address,address,address)'", vrqAddr, darkPoolAddr, daoAddress, ")");
            // console.log("  <ROUTER_ADDR> KPXRouterGateway");
        }
    }
}
