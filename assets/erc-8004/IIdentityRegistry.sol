// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.24;

// Extracted verbatim from the ERC-8004 Interfaces section. Do not hand-edit: this file must
// remain identical to the specification, which is the point of the exercise.

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Metadata} from "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";

interface IIdentityRegistry is IERC721, IERC721Metadata {
    struct MetadataEntry {
        string metadataKey;
        bytes metadataValue;
    }

    event Registered(uint256 indexed agentId, string agentURI, address indexed owner);
    event MetadataSet(uint256 indexed agentId, string indexed indexedMetadataKey, string metadataKey, bytes metadataValue);
    event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy);
    event AgentRevoked(uint256 indexed agentId, address indexed revokedBy);

    function register() external returns (uint256 agentId);
    function register(string calldata agentURI) external returns (uint256 agentId);
    function register(string calldata agentURI, MetadataEntry[] calldata metadata) external returns (uint256 agentId);

    function setAgentURI(uint256 agentId, string calldata newURI) external;

    function getMetadata(uint256 agentId, string calldata metadataKey) external view returns (bytes memory);
    function setMetadata(uint256 agentId, string calldata metadataKey, bytes calldata metadataValue) external;

    function setAgentWallet(uint256 agentId, address newWallet, uint256 nonce, uint256 deadline, bytes calldata signature) external;
    function getAgentWallet(uint256 agentId) external view returns (address);
    function getAgentWalletNonce(uint256 agentId) external view returns (uint256);
    function unsetAgentWallet(uint256 agentId) external;

    function revokeAgent(uint256 agentId) external;
    function isRevoked(uint256 agentId) external view returns (bool);

    /// @dev Used by the Reputation Registry to enforce that a feedback submitter is neither the
    ///      owner of agentId nor an approved operator for it.
    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool);
}
