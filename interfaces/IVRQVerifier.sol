// SPDX-License-Identifier: BSL-1.1
// AXIOLEDGER — VERACIPHERS ($VRQ)
// IVRQVerifier.sol — ZK-DID Compliance Verifier Interface
// Ref: Whitepaper §11.11 · core/contracts/IKPXRouter.sol

pragma solidity ^0.8.24;

/// @title IVRQVerifier
/// @notice Interface cho VERACIPHERS ZK-DID compliance verification
/// @dev KPXRouterGateway gọi interface này để xác minh ZK-Proof và blacklist check
interface IVRQVerifier {
    /// @notice Kiểm tra địa chỉ có bị Supply Chain Scanner flag không
    /// @param addr Địa chỉ cần kiểm tra
    /// @return flagged True nếu địa chỉ nằm trong blacklist
    function isFlagged(address addr) external view returns (bool flagged);

    /// @notice Xác minh ZK-Proof hợp lệ theo circuit VERACIPHERS
    /// @param proof      ZK-SNARKs proof (~284 bytes, Groth16)
    /// @param pubInputs  Public inputs cho circuit
    /// @return valid     True nếu proof hợp lệ
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata pubInputs
    ) external view returns (bool valid);

    /// @notice Xác minh tuân thủ pháp lý (ZK-DID + AML/KYC) — dùng cho bridge & RWA
    /// @param proof         ZK compliance proof
    /// @param kycCommitment Commitment của KYC record (không lộ dữ liệu thô)
    /// @return compliant    True nếu địa chỉ pass AML/KYC
    function verifyCompliance(
        bytes calldata proof,
        bytes32 kycCommitment
    ) external view returns (bool compliant);

    /// @notice Lấy phiên bản circuit đang dùng (để check freshness)
    function circuitVersion() external view returns (uint256 version);

    /// @notice Kiểm tra transaction hash có bị detect là tấn công bridge
    function isTxSafe(bytes32 txHash) external view returns (bool safe);
}
