// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.24;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IValidationRegistry} from "./IValidationRegistry.sol";
import {IIdentityRegistry} from "./IIdentityRegistry.sol";

/// @title ERC-8004 Validation Registry (reference implementation)
contract ValidationRegistry is ERC165, IValidationRegistry {
    struct Validation {
        address validatorAddress;
        uint8 response;
        bool hasResponse;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
    }

    struct Request {
        uint256 agentId;
        address requester;
        bytes32 requestHash;
    }

    IIdentityRegistry private immutable _identity;

    // A request is keyed by (agentId, requester, requestHash).
    mapping(uint256 => mapping(address => mapping(bytes32 => Validation))) private _validations;
    mapping(uint256 => Request[]) private _agentRequests;
    mapping(address => Request[]) private _validatorRequests;

    error ZeroValidator();
    error EmptyURI();
    error ZeroHash();
    error SelfValidation();
    error RequestExists();
    error UnknownRequest();
    error NotValidator();
    error ResponseOutOfRange();

    constructor(address identityRegistry) {
        _identity = IIdentityRegistry(identityRegistry);
    }

    function getIdentityRegistry() external view returns (address) {
        return address(_identity);
    }

    // Writes

    /// @dev Anyone may request validation; the caller is the requester.
    function validationRequest(address validatorAddress, uint256 agentId, string calldata requestURI, bytes32 requestHash)
        external
    {
        if (validatorAddress == address(0)) revert ZeroValidator();
        if (bytes(requestURI).length == 0) revert EmptyURI();
        if (requestHash == bytes32(0)) revert ZeroHash();
        // Also reverts for an unregistered agentId. Mirrors the self-feedback rule: the owner and its
        // operators cannot validate the agent.
        if (_identity.isAuthorizedOrOwner(validatorAddress, agentId)) revert SelfValidation();
        Validation storage v = _validations[agentId][msg.sender][requestHash];
        if (v.validatorAddress != address(0)) revert RequestExists();

        v.validatorAddress = validatorAddress;
        v.lastUpdate = block.timestamp;
        Request memory r = Request(agentId, msg.sender, requestHash);
        _agentRequests[agentId].push(r);
        _validatorRequests[validatorAddress].push(r);

        emit ValidationRequest(validatorAddress, agentId, msg.sender, requestURI, requestHash);
    }

    function validationResponse(
        uint256 agentId,
        address requester,
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external {
        Validation storage v = _get(agentId, requester, requestHash);
        if (msg.sender != v.validatorAddress) revert NotValidator();
        if (response > 100) revert ResponseOutOfRange();

        (v.response, v.hasResponse, v.responseHash, v.tag, v.lastUpdate) =
            (response, true, responseHash, tag, block.timestamp);

        emit ValidationResponse(msg.sender, agentId, requestHash, requester, response, responseURI, responseHash, tag);
    }

    // Reads

    function getValidationStatus(uint256 agentId, address requester, bytes32 requestHash)
        external
        view
        returns (address, uint8, bytes32, string memory, uint256)
    {
        Validation storage v = _get(agentId, requester, requestHash);
        return (v.validatorAddress, v.response, v.responseHash, v.tag, v.lastUpdate);
    }

    function getSummary(
        uint256 agentId,
        address[] calldata validatorAddresses,
        address[] calldata requesters,
        string calldata tag,
        uint64 fromIndex,
        uint64 maxEntries
    ) external view returns (uint64 count, uint256 sumResponse, uint64 nextIndex) {
        Request[] storage all = _agentRequests[agentId];
        uint64 end;
        (fromIndex, end, nextIndex) = _window(uint64(all.length), fromIndex, maxEntries);
        for (uint64 i = fromIndex; i <= end; ++i) {
            Request storage r = all[i - 1];
            Validation storage v = _validations[agentId][r.requester][r.requestHash];
            if (!v.hasResponse) continue; // a pending request is not a zero
            if (!_contains(validatorAddresses, v.validatorAddress)) continue;
            if (!_contains(requesters, r.requester)) continue;
            if (bytes(tag).length != 0 && keccak256(bytes(tag)) != keccak256(bytes(v.tag))) continue;
            sumResponse += v.response;
            ++count;
        }
    }

    function getAgentValidations(uint256 agentId, uint64 fromIndex, uint64 maxEntries)
        external
        view
        returns (address[] memory requesters, bytes32[] memory requestHashes, uint64 nextIndex)
    {
        Request[] storage all = _agentRequests[agentId];
        uint64 start;
        uint64 end;
        (start, end, nextIndex) = _window(uint64(all.length), fromIndex, maxEntries);
        uint256 n = end >= start ? end - start + 1 : 0;
        requesters = new address[](n);
        requestHashes = new bytes32[](n);
        for (uint256 k; k < n; ++k) {
            Request storage r = all[start - 1 + k];
            (requesters[k], requestHashes[k]) = (r.requester, r.requestHash);
        }
    }

    function getValidatorRequests(address validatorAddress, uint64 fromIndex, uint64 maxEntries)
        external
        view
        returns (uint256[] memory agentIds, address[] memory requesters, bytes32[] memory requestHashes, uint64 nextIndex)
    {
        Request[] storage all = _validatorRequests[validatorAddress];
        uint64 start;
        uint64 end;
        (start, end, nextIndex) = _window(uint64(all.length), fromIndex, maxEntries);
        uint256 n = end >= start ? end - start + 1 : 0;
        agentIds = new uint256[](n);
        requesters = new address[](n);
        requestHashes = new bytes32[](n);
        for (uint256 k; k < n; ++k) {
            Request storage r = all[start - 1 + k];
            (agentIds[k], requesters[k], requestHashes[k]) = (r.agentId, r.requester, r.requestHash);
        }
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IValidationRegistry).interfaceId || super.supportsInterface(interfaceId);
    }

    // Helpers

    function _get(uint256 agentId, address requester, bytes32 requestHash) private view returns (Validation storage v) {
        v = _validations[agentId][requester][requestHash];
        if (v.validatorAddress == address(0)) revert UnknownRequest();
    }

    /// @dev An empty filter matches anything.
    function _contains(address[] calldata list, address a) private pure returns (bool) {
        if (list.length == 0) return true;
        for (uint256 i; i < list.length; ++i) if (list[i] == a) return true;
        return false;
    }

    /// @dev Same paging convention as the Reputation Registry: the 1-based window [start, end] and the
    ///      index to resume from (0 once fully traversed). fromIndex 0 reads from 1; with maxEntries 0
    ///      nothing is inspected and the call resumes at start.
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
