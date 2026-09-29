// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {ERC721Enumerable} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import {IERC721Metadata} from "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IIdentityRegistry} from "./IIdentityRegistry.sol";

/// @title ERC-8004 Identity Registry (reference implementation)
contract IdentityRegistry is ERC721URIStorage, ERC721Enumerable, EIP712, IIdentityRegistry {
    string private constant WALLET_KEY = "agentWallet";
    bytes32 private constant WALLET_SET_TYPEHASH =
        keccak256("AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 nonce,uint256 deadline)");

    uint256 private _nextId;
    mapping(uint256 => mapping(string => bytes)) private _metadata;
    mapping(uint256 => uint256) private _walletNonce;
    mapping(uint256 => bool) private _revoked;

    error NotAuthorized();
    error ReservedKey();
    error AlreadyRevoked();
    error SignatureExpired();
    error InvalidNonce();
    error InvalidSignature();
    error ZeroWallet();

    constructor() ERC721("AgentIdentity", "AGENT") EIP712("ERC8004IdentityRegistry", "1") {}

    modifier onlyAuthorized(uint256 agentId) {
        if (!isAuthorizedOrOwner(msg.sender, agentId)) revert NotAuthorized();
        _;
    }

    // Registration

    function register() external returns (uint256) {
        return _register("", new MetadataEntry[](0));
    }

    function register(string calldata agentURI) external returns (uint256) {
        return _register(agentURI, new MetadataEntry[](0));
    }

    function register(string calldata agentURI, MetadataEntry[] calldata metadata) external returns (uint256) {
        return _register(agentURI, metadata);
    }

    function _register(string memory agentURI, MetadataEntry[] memory metadata) private returns (uint256 agentId) {
        agentId = _nextId++;
        _mint(msg.sender, agentId);
        if (bytes(agentURI).length != 0) _setTokenURI(agentId, agentURI);
        emit Registered(agentId, agentURI, msg.sender);
        _setWallet(agentId, abi.encodePacked(msg.sender));
        for (uint256 i; i < metadata.length; ++i) {
            _setMetadata(agentId, metadata[i].metadataKey, metadata[i].metadataValue);
        }
    }

    // Agent URI and metadata

    function setAgentURI(uint256 agentId, string calldata newURI) external onlyAuthorized(agentId) {
        _setTokenURI(agentId, newURI);
        emit URIUpdated(agentId, newURI, msg.sender);
    }

    function getMetadata(uint256 agentId, string calldata metadataKey) external view returns (bytes memory) {
        return _metadata[agentId][metadataKey];
    }

    function setMetadata(uint256 agentId, string calldata metadataKey, bytes calldata metadataValue)
        external
        onlyAuthorized(agentId)
    {
        _setMetadata(agentId, metadataKey, metadataValue);
    }

    function _setMetadata(uint256 agentId, string memory key, bytes memory value) private {
        if (keccak256(bytes(key)) == keccak256(bytes(WALLET_KEY))) revert ReservedKey();
        _metadata[agentId][key] = value;
        emit MetadataSet(agentId, key, key, value);
    }

    // Agent wallet

    function getAgentWallet(uint256 agentId) external view returns (address) {
        return address(bytes20(_metadata[agentId][WALLET_KEY]));
    }

    function getAgentWalletNonce(uint256 agentId) external view returns (uint256) {
        return _walletNonce[agentId];
    }

    function setAgentWallet(uint256 agentId, address newWallet, uint256 nonce, uint256 deadline, bytes calldata signature)
        external
        onlyAuthorized(agentId)
    {
        if (newWallet == address(0)) revert ZeroWallet();
        if (block.timestamp > deadline) revert SignatureExpired();
        if (nonce != _walletNonce[agentId]) revert InvalidNonce();

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(WALLET_SET_TYPEHASH, agentId, newWallet, ownerOf(agentId), nonce, deadline))
        );
        if (!_isValidSignature(newWallet, digest, signature)) revert InvalidSignature();

        _walletNonce[agentId] = nonce + 1;
        _setWallet(agentId, abi.encodePacked(newWallet));
    }

    function unsetAgentWallet(uint256 agentId) external onlyAuthorized(agentId) {
        _setWallet(agentId, "");
    }

    function _setWallet(uint256 agentId, bytes memory wallet) private {
        _metadata[agentId][WALLET_KEY] = wallet;
        emit MetadataSet(agentId, WALLET_KEY, WALLET_KEY, wallet);
    }

    /// @dev An ECDSA signature from the wallet itself (an EOA), else an ERC-1271 approval (a contract).
    function _isValidSignature(address wallet, bytes32 digest, bytes calldata signature) private view returns (bool) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == wallet) return true;
        (bool ok, bytes memory result) =
            wallet.staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, signature)));
        return ok && result.length >= 32 && abi.decode(result, (bytes4)) == IERC1271.isValidSignature.selector;
    }

    // Revocation

    function revokeAgent(uint256 agentId) external onlyAuthorized(agentId) {
        if (_revoked[agentId]) revert AlreadyRevoked();
        _revoked[agentId] = true;
        emit AgentRevoked(agentId, msg.sender);
    }

    function isRevoked(uint256 agentId) external view returns (bool) {
        return _revoked[agentId];
    }

    // Authorization: the owner, or an operator approved for all of the owner's tokens.

    function isAuthorizedOrOwner(address spender, uint256 agentId) public view returns (bool) {
        address owner = ownerOf(agentId);
        return spender == owner || isApprovedForAll(owner, spender);
    }

    // ERC-721 overrides

    /// @dev Clears agentWallet when the agent changes owner.
    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721, ERC721Enumerable)
        returns (address)
    {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) _setWallet(tokenId, "");
        return super._update(to, tokenId, auth);
    }

    function _increaseBalance(address account, uint128 value) internal override(ERC721, ERC721Enumerable) {
        super._increaseBalance(account, value);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage, IERC721Metadata)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721URIStorage, ERC721Enumerable, IERC165)
        returns (bool)
    {
        return interfaceId == type(IIdentityRegistry).interfaceId || super.supportsInterface(interfaceId);
    }
}
