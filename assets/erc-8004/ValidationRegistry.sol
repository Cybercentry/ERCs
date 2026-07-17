// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.24;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IValidationRegistry} from "./IValidationRegistry.sol";
import {IIdentityRegistry} from "./IIdentityRegistry.sol";

/**
 * @title ValidationRegistry
 * @notice ERC-8004 Validation Registry.
 */
contract ValidationRegistry is ERC165, IValidationRegistry {
    struct ValidationStatus {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
        bool hasResponse;
    }

    struct Request {
        uint256 agentId;
        bytes32 requestHash;
    }

    IIdentityRegistry private immutable _identityRegistry;

    // Keyed by keccak256(agentId, requestHash), not by requestHash alone. A bare requestHash is a
    // global first-come namespace: an observer can copy a pending request's hash from the mempool and
    // claim it under an agent it controls, permanently blocking the intended request. Binding the key
    // to the requesting agent removes the shared namespace, so the same hash under two agents is two
    // independent requests and cannot be squatted.
    mapping(bytes32 => ValidationStatus) private _validations;
    mapping(uint256 => bytes32[]) private _agentValidations;
    mapping(address => Request[]) private _validatorRequests;

    function _key(uint256 agentId, bytes32 requestHash) private pure returns (bytes32) {
        return keccak256(abi.encode(agentId, requestHash));
    }

    error ZeroIdentityRegistry();
    error ZeroValidator();
    error RequestExists();
    error UnknownRequest();
    error NotAuthorized();
    error NotValidator();
    error ResponseOutOfRange();

    constructor(address identityRegistry_) {
        if (identityRegistry_ == address(0)) revert ZeroIdentityRegistry();
        _identityRegistry = IIdentityRegistry(identityRegistry_);
    }

    function getIdentityRegistry() external view returns (address) {
        return address(_identityRegistry);
    }

    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external {
        if (validatorAddress == address(0)) revert ZeroValidator();
        bytes32 key = _key(agentId, requestHash);
        if (_validations[key].validatorAddress != address(0)) revert RequestExists();

        // Reverts for an unregistered agentId.
        if (!_identityRegistry.isAuthorizedOrOwner(msg.sender, agentId)) revert NotAuthorized();

        _validations[key] = ValidationStatus({
            validatorAddress: validatorAddress,
            agentId: agentId,
            response: 0,
            responseHash: bytes32(0),
            tag: "",
            lastUpdate: block.timestamp,
            hasResponse: false
        });

        _agentValidations[agentId].push(requestHash);
        _validatorRequests[validatorAddress].push(Request({agentId: agentId, requestHash: requestHash}));

        emit ValidationRequest(validatorAddress, agentId, requestURI, requestHash);
    }

    function validationResponse(
        uint256 agentId,
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external {
        ValidationStatus storage s = _validations[_key(agentId, requestHash)];
        if (s.validatorAddress == address(0)) revert UnknownRequest();
        if (msg.sender != s.validatorAddress) revert NotValidator();
        if (response > 100) revert ResponseOutOfRange();

        s.response = response;
        s.responseHash = responseHash;
        s.tag = tag;
        s.lastUpdate = block.timestamp;
        s.hasResponse = true;

        emit ValidationResponse(s.validatorAddress, agentId, requestHash, response, responseURI, responseHash, tag);
    }

    function getValidationStatus(uint256 agentId, bytes32 requestHash)
        external
        view
        returns (
            address validatorAddress,
            uint8 response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        )
    {
        ValidationStatus storage s = _validations[_key(agentId, requestHash)];
        if (s.validatorAddress == address(0)) revert UnknownRequest();
        return (s.validatorAddress, s.response, s.responseHash, s.tag, s.lastUpdate);
    }

    function getSummary(
        uint256 agentId,
        address[] calldata validatorAddresses,
        string calldata tag,
        uint64 fromIndex,
        uint64 maxEntries
    ) external view returns (uint64 count, uint256 sumResponse, uint64 nextIndex) {
        bytes32[] storage hashes = _agentValidations[agentId];
        bytes32 tagHash = keccak256(bytes(tag));
        bool anyTag = bytes(tag).length == 0;

        (uint64 start, uint64 end, uint64 next) = _window(uint64(hashes.length), fromIndex, maxEntries);
        for (uint64 i = start; i <= end; ++i) {
            ValidationStatus storage s = _validations[_key(agentId, hashes[i - 1])];
            if (!s.hasResponse) continue;

            bool matchValidator = validatorAddresses.length == 0;
            for (uint256 j; !matchValidator && j < validatorAddresses.length; ++j) {
                if (s.validatorAddress == validatorAddresses[j]) matchValidator = true;
            }
            if (!matchValidator) continue;
            if (!anyTag && keccak256(bytes(s.tag)) != tagHash) continue;

            // Returns the sum, not the average, for the reasons the Reputation Registry does: a sum has
            // exactly one correct answer and composes across pages, so independent implementations agree.
            sumResponse += s.response;
            ++count;
        }
        nextIndex = next;
    }

    function getAgentValidations(uint256 agentId, uint64 fromIndex, uint64 maxEntries)
        external
        view
        returns (bytes32[] memory requestHashes, uint64 nextIndex)
    {
        return _page(_agentValidations[agentId], fromIndex, maxEntries);
    }

    function getValidatorRequests(address validatorAddress, uint64 fromIndex, uint64 maxEntries)
        external
        view
        returns (uint256[] memory agentIds, bytes32[] memory requestHashes, uint64 nextIndex)
    {
        Request[] storage list = _validatorRequests[validatorAddress];
        (uint64 start, uint64 end, uint64 next) = _window(uint64(list.length), fromIndex, maxEntries);
        uint64 n = end >= start ? end - start + 1 : 0;
        // A validator needs both parts to respond, since requests are keyed by (agentId, requestHash).
        agentIds = new uint256[](n);
        requestHashes = new bytes32[](n);
        for (uint64 i; i < n; ++i) {
            Request storage r = list[start - 1 + i];
            agentIds[i] = r.agentId;
            requestHashes[i] = r.requestHash;
        }
        nextIndex = next;
    }

    /// @dev The inclusive 1-based window [start, end] a call may inspect over a list of `length`
    ///      entries, and the 1-based index to resume from. This mirrors the Reputation Registry so the
    ///      two registries share one convention: indices are 1-based, next == 0 means the list has been
    ///      fully traversed, and a window that inspects nothing resumes at start (never 0) rather than
    ///      falsely reporting traversal complete. When start > end the window is empty.
    function _window(uint64 length, uint64 fromIndex, uint64 maxEntries)
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

    /// @dev A bounded page of a bytes32 list, plus the 1-based index to resume from.
    function _page(bytes32[] storage list, uint64 fromIndex, uint64 maxEntries)
        private
        view
        returns (bytes32[] memory page, uint64 nextIndex)
    {
        (uint64 start, uint64 end, uint64 next) = _window(uint64(list.length), fromIndex, maxEntries);
        uint64 n = end >= start ? end - start + 1 : 0;
        page = new bytes32[](n);
        for (uint64 i; i < n; ++i) {
            page[i] = list[start - 1 + i];
        }
        nextIndex = next;
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IValidationRegistry).interfaceId || super.supportsInterface(interfaceId);
    }
}
