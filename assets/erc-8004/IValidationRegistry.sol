// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.24;

// Extracted verbatim from the ERC-8004 Interfaces section. Do not hand-edit: this file must
// remain identical to the specification, which is the point of the exercise.

interface IValidationRegistry {
    event ValidationRequest(address indexed validatorAddress, uint256 indexed agentId, string requestURI, bytes32 indexed requestHash);
    event ValidationResponse(address indexed validatorAddress, uint256 indexed agentId, bytes32 indexed requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag);

    function getIdentityRegistry() external view returns (address);

    function validationRequest(address validatorAddress, uint256 agentId, string calldata requestURI, bytes32 requestHash) external;
    function validationResponse(uint256 agentId, bytes32 requestHash, uint8 response, string calldata responseURI, bytes32 responseHash, string calldata tag) external;

    function getValidationStatus(uint256 agentId, bytes32 requestHash) external view returns (address validatorAddress, uint8 response, bytes32 responseHash, string memory tag, uint256 lastUpdate);
    function getSummary(uint256 agentId, address[] calldata validatorAddresses, string calldata tag, uint64 fromIndex, uint64 maxEntries) external view returns (uint64 count, uint256 sumResponse, uint64 nextIndex);
    function getAgentValidations(uint256 agentId, uint64 fromIndex, uint64 maxEntries) external view returns (bytes32[] memory requestHashes, uint64 nextIndex);
    function getValidatorRequests(address validatorAddress, uint64 fromIndex, uint64 maxEntries) external view returns (uint256[] memory agentIds, bytes32[] memory requestHashes, uint64 nextIndex);
}
