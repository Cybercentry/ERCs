// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.24;

// Extracted verbatim from the ERC-8004 Interfaces section. Do not hand-edit: this file must
// remain identical to the specification, which is the point of the exercise.

interface IReputationRegistry {
    event NewFeedback(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex, int128 value, uint8 valueDecimals, string indexed indexedTag1, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash);
    event FeedbackRevoked(uint256 indexed agentId, address indexed clientAddress, uint64 indexed feedbackIndex);
    event ResponseAppended(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex, address indexed responder, string responseURI, bytes32 responseHash);

    function getIdentityRegistry() external view returns (address);

    function giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals, string calldata tag1, string calldata tag2, string calldata endpoint, string calldata feedbackURI, bytes32 feedbackHash) external;
    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external;
    function appendResponse(uint256 agentId, address clientAddress, uint64 feedbackIndex, string calldata responseURI, bytes32 responseHash) external;

    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64);
    function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex) external view returns (int128 value, uint8 valueDecimals, string memory tag1, string memory tag2, bool isRevoked);
    function getResponseCount(uint256 agentId, address clientAddress, uint64 feedbackIndex, address[] calldata responders, uint64 fromIndex, uint64 maxEntries) external view returns (uint64 count, uint64 nextIndex);

    function getSummary(uint256 agentId, address clientAddress, string calldata tag1, string calldata tag2, uint64 fromIndex, uint64 maxEntries) external view returns (uint64 count, int256 sumWad, uint64 nextIndex);
    function readFeedbackRange(uint256 agentId, address clientAddress, string calldata tag1, string calldata tag2, bool includeRevoked, uint64 fromIndex, uint64 maxEntries) external view returns (uint64[] memory feedbackIndexes, int128[] memory values, uint8[] memory valueDecimals, string[] memory tag1s, string[] memory tag2s, bool[] memory revokedStatuses, uint64 nextIndex);
    function getClientCount(uint256 agentId) external view returns (uint64);
    function getClients(uint256 agentId, uint64 offset, uint64 limit) external view returns (address[] memory clients);
}
