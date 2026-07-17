// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.24;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IReputationRegistry} from "./IReputationRegistry.sol";
import {IIdentityRegistry} from "./IIdentityRegistry.sol";

/**
 * @title ReputationRegistry
 * @notice ERC-8004 Reputation Registry.
 *
 * Every read bounds the work it performs, not the rows it returns. A call inspects at most
 * `maxEntries` indices and reports where to resume. Bounding the rows instead would leave the cost
 * linear in an agent's total feedback, which is what these reads exist to avoid: they are declared
 * for on-chain consumption, and anyone may add feedback to an agent they do not own.
 */
contract ReputationRegistry is ERC165, IReputationRegistry {
    struct Feedback {
        int128 value;
        uint8 valueDecimals;
        bool isRevoked;
        string tag1;
        string tag2;
    }

    IIdentityRegistry private immutable _identityRegistry;

    /// @dev agentId => client => feedbackIndex (1-based) => Feedback
    mapping(uint256 => mapping(address => mapping(uint64 => Feedback))) private _feedback;
    /// @dev agentId => client => highest feedbackIndex written
    mapping(uint256 => mapping(address => uint64)) private _lastIndex;
    /// @dev agentId => clients who have given feedback, in first-feedback order
    mapping(uint256 => address[]) private _clients;
    mapping(uint256 => mapping(address => bool)) private _isClient;
    /// @dev agentId => client => feedbackIndex => responder => count
    mapping(uint256 => mapping(address => mapping(uint64 => mapping(address => uint64)))) private _responseCount;
    mapping(uint256 => mapping(address => mapping(uint64 => address[]))) private _responders;
    mapping(uint256 => mapping(address => mapping(uint64 => mapping(address => bool)))) private _isResponder;

    error SelfFeedback();
    error TooManyDecimals();
    error IndexOutOfBounds();
    error AlreadyRevoked();
    error EmptyURI();
    error ZeroIdentityRegistry();

    constructor(address identityRegistry_) {
        if (identityRegistry_ == address(0)) revert ZeroIdentityRegistry();
        _identityRegistry = IIdentityRegistry(identityRegistry_);
    }

    function getIdentityRegistry() external view returns (address) {
        return address(_identityRegistry);
    }

    // ------------------------------------------------------------------ writes

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

        // Reverts for an unregistered agentId, which the specification also requires.
        if (_identityRegistry.isAuthorizedOrOwner(msg.sender, agentId)) revert SelfFeedback();

        uint64 index = ++_lastIndex[agentId][msg.sender];
        _feedback[agentId][msg.sender][index] =
            Feedback({value: value, valueDecimals: valueDecimals, isRevoked: false, tag1: tag1, tag2: tag2});

        if (!_isClient[agentId][msg.sender]) {
            _clients[agentId].push(msg.sender);
            _isClient[agentId][msg.sender] = true;
        }

        emit NewFeedback(
            agentId, msg.sender, index, value, valueDecimals, tag1, tag1, tag2, endpoint, feedbackURI, feedbackHash
        );
    }

    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external {
        if (feedbackIndex == 0 || feedbackIndex > _lastIndex[agentId][msg.sender]) revert IndexOutOfBounds();
        Feedback storage f = _feedback[agentId][msg.sender][feedbackIndex];
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
        if (feedbackIndex == 0 || feedbackIndex > _lastIndex[agentId][clientAddress]) revert IndexOutOfBounds();
        if (bytes(responseURI).length == 0) revert EmptyURI();

        if (!_isResponder[agentId][clientAddress][feedbackIndex][msg.sender]) {
            _responders[agentId][clientAddress][feedbackIndex].push(msg.sender);
            _isResponder[agentId][clientAddress][feedbackIndex][msg.sender] = true;
        }
        ++_responseCount[agentId][clientAddress][feedbackIndex][msg.sender];

        emit ResponseAppended(agentId, clientAddress, feedbackIndex, msg.sender, responseURI, responseHash);
    }

    // ------------------------------------------------------------ single reads

    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64) {
        return _lastIndex[agentId][clientAddress];
    }

    function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external
        view
        returns (int128 value, uint8 valueDecimals, string memory tag1, string memory tag2, bool isRevoked)
    {
        if (feedbackIndex == 0 || feedbackIndex > _lastIndex[agentId][clientAddress]) revert IndexOutOfBounds();
        Feedback storage f = _feedback[agentId][clientAddress][feedbackIndex];
        return (f.value, f.valueDecimals, f.tag1, f.tag2, f.isRevoked);
    }

    // -------------------------------------------------------- bounded-work reads

    function getSummary(
        uint256 agentId,
        address clientAddress,
        string calldata tag1,
        string calldata tag2,
        uint64 fromIndex,
        uint64 maxEntries
    ) external view returns (uint64 count, int256 sumWad, uint64 nextIndex) {
        (uint64 start, uint64 end, uint64 next) = _window(agentId, clientAddress, fromIndex, maxEntries);
        bytes32 t1 = keccak256(bytes(tag1));
        bytes32 t2 = keccak256(bytes(tag2));

        for (uint64 i = start; i <= end && end != 0; ++i) {
            Feedback storage f = _feedback[agentId][clientAddress][i];
            if (!_matches(f, t1, t2, false)) continue;
            // valueDecimals is 0..18 (enforced at write); compute the scale in checked arithmetic so the
            // exponent's non-underflow does not rely on that invariant holding non-locally.
            int256 scale = int256(10 ** uint256(18 - f.valueDecimals));
            unchecked {
                sumWad += int256(f.value) * scale;
                ++count;
            }
        }
        nextIndex = next;
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
        (uint64 start, uint64 end, uint64 next) = _window(agentId, clientAddress, fromIndex, maxEntries);
        bytes32 t1 = keccak256(bytes(tag1));
        bytes32 t2 = keccak256(bytes(tag2));

        uint64 n;
        for (uint64 i = start; i <= end && end != 0; ++i) {
            if (_matches(_feedback[agentId][clientAddress][i], t1, t2, includeRevoked)) ++n;
        }

        feedbackIndexes = new uint64[](n);
        values = new int128[](n);
        valueDecimals = new uint8[](n);
        tag1s = new string[](n);
        tag2s = new string[](n);
        revokedStatuses = new bool[](n);

        uint64 k;
        for (uint64 i = start; i <= end && end != 0; ++i) {
            Feedback storage f = _feedback[agentId][clientAddress][i];
            if (!_matches(f, t1, t2, includeRevoked)) continue;
            feedbackIndexes[k] = i;
            values[k] = f.value;
            valueDecimals[k] = f.valueDecimals;
            tag1s[k] = f.tag1;
            tag2s[k] = f.tag2;
            revokedStatuses[k] = f.isRevoked;
            unchecked {
                ++k;
            }
        }
        nextIndex = next;
    }

    /// @dev The window a call may inspect. `end == 0` means there is nothing to read.
    ///      `next == 0` means the client has been fully traversed.
    function _window(uint256 agentId, address clientAddress, uint64 fromIndex, uint64 maxEntries)
        private
        view
        returns (uint64 start, uint64 end, uint64 next)
    {
        uint64 last = _lastIndex[agentId][clientAddress];
        start = fromIndex == 0 ? 1 : fromIndex;
        if (start > last) return (start, 0, 0);
        // Inspecting nothing is not the same as having traversed everything: resume at start, or the
        // caller reads next == 0 as "fully traversed" and silently stops with every entry unread.
        if (maxEntries == 0) return (start, 0, start);
        // Widened: start + maxEntries overflows uint64 for large maxEntries, so the natural
        // "read everything" call panicked instead of clamping to the last index.
        uint256 limitEnd = uint256(start) + uint256(maxEntries) - 1;
        end = limitEnd < last ? uint64(limitEnd) : last;
        next = end < last ? end + 1 : 0;
    }

    function _matches(Feedback storage f, bytes32 t1, bytes32 t2, bool includeRevoked) private view returns (bool) {
        if (!includeRevoked && f.isRevoked) return false;
        if (t1 != _EMPTY && t1 != keccak256(bytes(f.tag1))) return false;
        if (t2 != _EMPTY && t2 != keccak256(bytes(f.tag2))) return false;
        return true;
    }

    bytes32 private constant _EMPTY = keccak256("");

    // ------------------------------------------------------------------ clients

    function getClientCount(uint256 agentId) external view returns (uint64) {
        return uint64(_clients[agentId].length);
    }

    function getClients(uint256 agentId, uint64 offset, uint64 limit) external view returns (address[] memory clients) {
        address[] storage all = _clients[agentId];
        uint256 total = all.length;
        if (offset >= total || limit == 0) return new address[](0);
        uint256 end = offset + limit;
        if (end > total) end = total;
        clients = new address[](end - offset);
        for (uint256 i; i < clients.length; ++i) {
            clients[i] = all[offset + i];
        }
    }

    // ---------------------------------------------------------------- responses

    function getResponseCount(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        address[] calldata responders,
        uint64 fromIndex,
        uint64 maxEntries
    ) external view returns (uint64 count, uint64 nextIndex) {
        if (responders.length != 0) {
            // Exact lookup, already bounded by the caller-supplied responders array.
            for (uint256 i; i < responders.length; ++i) {
                count += _responseCount[agentId][clientAddress][feedbackIndex][responders[i]];
            }
            return (count, 0);
        }
        // Aggregate over every responder. appendResponse is permissionless, so this list is
        // attacker-growable; bound the work by maxEntries exactly as the other reads do, rather than
        // scanning the whole list and risking an out-of-gas on a view that has no paginated alternative.
        address[] storage all = _responders[agentId][clientAddress][feedbackIndex];
        (uint64 start, uint64 end, uint64 next) = _windowOver(uint64(all.length), fromIndex, maxEntries);
        for (uint64 i = start; i <= end && end != 0; ++i) {
            count += _responseCount[agentId][clientAddress][feedbackIndex][all[i - 1]];
        }
        nextIndex = next;
    }

    /// @dev The inclusive 1-based window [start, end] over a list of `length` entries, and the 1-based
    ///      index to resume from (0 == fully traversed). Same convention as the feedback reads; a window
    ///      that inspects nothing resumes at start rather than reporting completion.
    function _windowOver(uint64 length, uint64 fromIndex, uint64 maxEntries)
        private
        pure
        returns (uint64 start, uint64 end, uint64 next)
    {
        start = fromIndex == 0 ? 1 : fromIndex;
        if (start > length) return (start, 0, 0);
        if (maxEntries == 0) return (start, 0, start);
        uint256 limitEnd = uint256(start) + uint256(maxEntries) - 1;
        end = limitEnd < length ? uint64(limitEnd) : length;
        next = end < length ? end + 1 : 0;
    }

    // ------------------------------------------------------------------ ERC-165

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IReputationRegistry).interfaceId || super.supportsInterface(interfaceId);
    }
}
