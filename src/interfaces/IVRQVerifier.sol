// SPDX-License-Identifier: BSL-1.1
// AXIOLEDGER  VERACIPHERS ($VRQ)
// IVRQVerifier.sol  ZK-DID Compliance Verifier Interface
// Ref: Whitepaper 11.11  core/contracts/IKPXRouter.sol

pragma solidity ^0.8.24;

/// @title IVRQVerifier
/// @notice Interface cho VERACIPHERS ZK-DID compliance verification
/// @dev KPXRouterGateway gi interface ny  xc minh ZK-Proof v blacklist check
interface IVRQVerifier {
    /// @notice Kim tra a ch c b Supply Chain Scanner flag khng
    /// @param addr a ch cn kim tra
    /// @return flagged True nu a ch nm trong blacklist
    function isFlagged(address addr) external view returns (bool flagged);

    /// @notice Xc minh ZK-Proof hp l theo circuit VERACIPHERS
    /// @param proof      ZK-SNARKs proof (~284 bytes, Groth16)
    /// @param pubInputs  Public inputs cho circuit
    /// @return valid     True nu proof hp l
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata pubInputs
    ) external view returns (bool valid);

    /// @notice Xc minh tun th php l (ZK-DID + AML/KYC)  dng cho bridge & RWA
    /// @param proof         ZK compliance proof
    /// @param kycCommitment Commitment ca KYC record (khng l d liu th)
    /// @return compliant    True nu a ch pass AML/KYC
    function verifyCompliance(
        bytes calldata proof,
        bytes32 kycCommitment
    ) external view returns (bool compliant);

    /// @notice Ly phin bn circuit ang dng ( check freshness)
    function circuitVersion() external view returns (uint256 version);

    /// @notice Kim tra transaction hash c b detect l tn cng bridge
    function isTxSafe(bytes32 txHash) external view returns (bool safe);
}
