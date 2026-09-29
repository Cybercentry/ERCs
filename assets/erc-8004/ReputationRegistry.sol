// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.24;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IReputationRegistry} from "./IReputationRegistry.sol";
import {IIdentityRegistry} from "./IIdentityRegistry.sol";

/// @title ERC-8004 Reputation Registry (reference implementation)
contract ReputationRegistry is ERC165, IReputationRegistry {
    struct Feedback {
        int128 value;
        uint8 valueDecimals;
        bool isRevoked;
        string tag1;
        string tag2;
    }

    IIdentityRegistry private immutable _identity;

    // agentId => client => feedbackIndex (1-based) => feedback
    mapping(uint256 => mapping(address => mapping(uint64 => Feedback))) private _feedback;
    mapping(uint256 => mapping(address => uint64)) private _lastIndex;
    mapping(uint256 => address[]) private _clients;
    // agentId => client => feedbackIndex => responders in first-response order, and responses per responder
    mapping(uint256 => mapping(address => mapping(uint64 => address[]))) private _responders;
    mapping(uint256 => mapping(address => mapping(uint64 => mapping(address => uint64)))) private _responseCount;

    error SelfFeedback();
    error TooManyDecimals();
    error IndexOutOfBounds();
    error AlreadyRevoked();
    error EmptyURI();

    constructor(address identityRegistry) {
        _identity = IIdentityRegistry(identityRegistry);
    }

    function getIdentityRegistry() external view returns (address) {
        return address(_identity);
    }

    // Writes

    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external {
        if (valueDecimals > 18) revert TooManyDecimals();
        // Also reverts for an unregistered agentId, since ownerOf reverts.
        if (_identity.isAuthorizedOrOwner(msg.sender, agentId)) revert SelfFeedback();

        uint64 index = ++_lastIndex[agentId][msg.sender];
        if (index == 1) _clients[agentId].push(msg.sender);
        _feedback[agentId][msg.sender][index] = Feedback(value, valueDecimals, false, tag1, tag2);

        emit NewFeedback(agentId, msg.sender, index, value, valueDecimals, tag1, tag1, tag2, endpoint, feedbackURI, feedbackHash);
    }

    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external {
        Feedback storage f = _get(agentId, msg.sender, feedbackIndex);
        if (f.isRevoked) revert AlreadyRevoked();
        f.isRevoked = true;
        emit FeedbackRevoked(agentId, msg.sender, feedbackIndex);
    }

    function appendResponse(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        string calldata responseURI,
        bytes32 responseHash
    ) external {
        _get(agentId, clientAddress, feedbackIndex);
        if (bytes(responseURI).length == 0) revert EmptyURI();
        if (_responseCount[agentId][clientAddress][feedbackIndex][msg.sender]++ == 0) {
            _responders[agentId][clientAddress][feedbackIndex].push(msg.sender);
        }
        emit ResponseAppended(agentId, clientAddress, feedbackIndex, msg.sender, responseURI, responseHash);
    }

    // Reads

    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64) {
        return _lastIndex[agentId][clientAddress];
    }

    function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external
        view
        returns (int128, uint8, string memory, string memory, bool)
    {
        Feedback storage f = _get(agentId, clientAddress, feedbackIndex);
        return (f.value, f.valueDecimals, f.tag1, f.tag2, f.isRevoked);
    }

    function getSummary(
        uint256 agentId,
        address clientAddress,
        string calldata tag1,
        string calldata tag2,
        uint64 fromIndex,
        uint64 maxEntries
    ) external view returns (uint64 count, int256 sumWad, uint64 nextIndex) {
        uint64 end;
        (fromIndex, end, nextIndex) = _window(_lastIndex[agentId][clientAddress], fromIndex, maxEntries);
        for (uint64 i = fromIndex; i <= end; ++i) {
            Feedback storage f = _feedback[agentId][clientAddress][i];
            if (!_matches(f, tag1, tag2, false)) continue;
            sumWad += int256(f.value) * int256(uint256(10) ** (18 - f.valueDecimals));
            ++count;
        }
    }

    function readFeedbackRange(
        uint256 agentId,
        address clientAddress,
        string calldata tag1,
        string calldata tag2,
        bool includeRevoked,
        uint64 fromIndex,
        uint64 maxEntries
    )
        external
        view
        returns (
            uint64[] memory feedbackIndexes,
            int128[] memory values,
            uint8[] memory valueDecimals,
            string[] memory tag1s,
            string[] memory tag2s,
            bool[] memory revokedStatuses,
            uint64 nextIndex
        )
    {
        uint64 start;
        uint64 end;
        (start, end, nextIndex) = _window(_lastIndex[agentId][clientAddress], fromIndex, maxEntries);
        mapping(uint64 => Feedback) storage list = _feedback[agentId][clientAddress];

        uint256 n;
        for (uint64 i = start; i <= end; ++i) {
            if (_matches(list[i], tag1, tag2, includeRevoked)) ++n;
        }
        feedbackIndexes = new uint64[](n);
        values = new int128[](n);
        valueDecimals = new uint8[](n);
        tag1s = new string[](n);
        tag2s = new string[](n);
        revokedStatuses = new bool[](n);

        uint256 k;
        for (uint64 i = start; i <= end; ++i) {
            Feedback storage f = list[i];
            if (!_matches(f, tag1, tag2, includeRevoked)) continue;
            (feedbackIndexes[k], values[k], valueDecimals[k]) = (i, f.value, f.valueDecimals);
            (tag1s[k], tag2s[k], revokedStatuses[k]) = (f.tag1, f.tag2, f.isRevoked);
            ++k;
        }
    }

    function getResponseCount(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        address[] calldata responders,
        uint64 fromIndex,
        uint64 maxEntries
    ) external view returns (uint64 count, uint64 nextIndex) {
        mapping(address => uint64) storage counts = _responseCount[agentId][clientAddress][feedbackIndex];
        if (responders.length != 0) {
            for (uint256 i; i < responders.length; ++i) count += counts[responders[i]];
            return (count, 0);
        }
        address[] storage all = _responders[agentId][clientAddress][feedbackIndex];
        uint64 end;
        (fromIndex, end, nextIndex) = _window(uint64(all.length), fromIndex, maxEntries);
        for (uint64 i = fromIndex; i <= end; ++i) count += counts[all[i - 1]];
    }

    function getClientCount(uint256 agentId) external view returns (uint64) {
        return uint64(_clients[agentId].length);
    }

    function getClients(uint256 agentId, uint64 offset, uint64 limit) external view returns (address[] memory clients) {
        address[] storage all = _clients[agentId];
        uint256 end = uint256(offset) + limit;
        if (end > all.length) end = all.length;
        if (offset >= end) return new address[](0);
        clients = new address[](end - offset);
        for (uint256 i; i < clients.length; ++i) clients[i] = all[offset + i];
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IReputationRegistry).interfaceId || super.supportsInterface(interfaceId);
    }

    // Helpers

    function _get(uint256 agentId, address clientAddress, uint64 feedbackIndex) private view returns (Feedback storage) {
        if (feedbackIndex == 0 || feedbackIndex > _lastIndex[agentId][clientAddress]) revert IndexOutOfBounds();
        return _feedback[agentId][clientAddress][feedbackIndex];
    }

    function _matches(Feedback storage f, string calldata tag1, string calldata tag2, bool includeRevoked)
        private
        view
        returns (bool)
    {
        if (f.isRevoked && !includeRevoked) return false;
        if (bytes(tag1).length != 0 && keccak256(bytes(tag1)) != keccak256(bytes(f.tag1))) return false;
        if (bytes(tag2).length != 0 && keccak256(bytes(tag2)) != keccak256(bytes(f.tag2))) return false;
        return true;
    }

    /// @dev The 1-based window [start, end] a paged read inspects over a list of `length` entries, and the
    ///      index to resume from (0 once the list is fully traversed). fromIndex 0 reads from 1. An empty
    ///      window (start > end) inspects nothing; with maxEntries 0 it resumes at start.
    function _window(uint64 length, uint64 fromIndex, uint64 maxEntries)
        private
        pure
        returns (uint64 start, uint64 end, uint64 next)
    {
        start = fromIndex == 0 ? 1 : fromIndex;
        if (start > length) return (start, 0, 0);
        if (maxEntries == 0) return (start, 0, start);
        uint256 last = uint256(start) + maxEntries - 1;
        end = last < length ? uint64(last) : length;
        next = end < length ? end + 1 : 0;
    }
}
