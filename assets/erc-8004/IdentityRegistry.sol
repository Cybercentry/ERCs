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

/**
 * @title IdentityRegistry
 * @notice ERC-8004 Identity Registry.
 *
 * Implemented from the specification text. agentId is the ERC-721 tokenId; agentURI is the
 * ERC-721 tokenURI.
 */
contract IdentityRegistry is ERC721URIStorage, ERC721Enumerable, EIP712, IIdentityRegistry {
    /// @dev agentIds are assigned incrementally by the registry, starting at 0.
    uint256 private _lastId;

    /// @dev agentId => metadataKey => metadataValue. Includes the reserved key `agentWallet`.
    mapping(uint256 => mapping(string => bytes)) private _metadata;

    /// @dev agentId => the next valid nonce for setAgentWallet.
    mapping(uint256 => uint256) private _walletNonce;

    /// @dev agentId => whether the agent has been revoked. Set-once, and preserved across transfer.
    mapping(uint256 => bool) private _revoked;

    string private constant AGENT_WALLET_KEY = "agentWallet";
    bytes32 private constant AGENT_WALLET_KEY_HASH = keccak256(bytes("agentWallet"));

    bytes32 private constant AGENT_WALLET_SET_TYPEHASH =
        keccak256("AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 nonce,uint256 deadline)");

    bytes4 private constant ERC1271_MAGICVALUE = 0x1626ba7e;

    error NotAuthorized();
    error ReservedKey();
    error AlreadyRevoked();
    error SignatureExpired();
    error InvalidNonce();
    error InvalidWalletSignature();
    error ZeroWallet();

    constructor() ERC721("AgentIdentity", "AGENT") EIP712("ERC8004IdentityRegistry", "1") {}

    // ------------------------------------------------------------- registration

    function register() external returns (uint256 agentId) {
        return _register("", new MetadataEntry[](0), false);
    }

    function register(string calldata agentURI) external returns (uint256 agentId) {
        return _register(agentURI, new MetadataEntry[](0), true);
    }

    function register(string calldata agentURI, MetadataEntry[] calldata metadata)
        external
        returns (uint256 agentId)
    {
        return _register(agentURI, metadata, true);
    }

    function _register(string memory agentURI, MetadataEntry[] memory metadata, bool setURI)
        private
        returns (uint256 agentId)
    {
        agentId = _lastId++;

        // The reserved agentWallet is set on registration, initially to the registrant.
        _metadata[agentId][AGENT_WALLET_KEY] = abi.encodePacked(msg.sender);

        _safeMint(msg.sender, agentId);
        if (setURI) _setTokenURI(agentId, agentURI);

        emit Registered(agentId, agentURI, msg.sender);
        emit MetadataSet(agentId, AGENT_WALLET_KEY, AGENT_WALLET_KEY, abi.encodePacked(msg.sender));

        for (uint256 i; i < metadata.length; ++i) {
            if (keccak256(bytes(metadata[i].metadataKey)) == AGENT_WALLET_KEY_HASH) revert ReservedKey();
            _metadata[agentId][metadata[i].metadataKey] = metadata[i].metadataValue;
            emit MetadataSet(agentId, metadata[i].metadataKey, metadata[i].metadataKey, metadata[i].metadataValue);
        }
    }

    // --------------------------------------------------------------- agent URI

    function setAgentURI(uint256 agentId, string calldata newURI) external {
        _requireAuthorized(agentId);
        _setTokenURI(agentId, newURI);
        emit URIUpdated(agentId, newURI, msg.sender);
    }

    // --------------------------------------------------------------- metadata

    function getMetadata(uint256 agentId, string calldata metadataKey) external view returns (bytes memory) {
        return _metadata[agentId][metadataKey];
    }

    function setMetadata(uint256 agentId, string calldata metadataKey, bytes calldata metadataValue) external {
        _requireAuthorized(agentId);
        if (keccak256(bytes(metadataKey)) == AGENT_WALLET_KEY_HASH) revert ReservedKey();
        _metadata[agentId][metadataKey] = metadataValue;
        emit MetadataSet(agentId, metadataKey, metadataKey, metadataValue);
    }

    // ------------------------------------------------------------ agent wallet

    function getAgentWallet(uint256 agentId) external view returns (address) {
        return address(bytes20(_metadata[agentId][AGENT_WALLET_KEY]));
    }

    function getAgentWalletNonce(uint256 agentId) external view returns (uint256) {
        return _walletNonce[agentId];
    }

    function setAgentWallet(
        uint256 agentId,
        address newWallet,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external {
        address agentOwner = ownerOf(agentId);
        if (!_isAuthorized(agentOwner, msg.sender, agentId)) revert NotAuthorized();
        if (newWallet == address(0)) revert ZeroWallet();
        if (block.timestamp > deadline) revert SignatureExpired();
        if (nonce != _walletNonce[agentId]) revert InvalidNonce();

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(AGENT_WALLET_SET_TYPEHASH, agentId, newWallet, agentOwner, nonce, deadline))
        );

        // EOAs and EIP-7702 delegated EOAs first, then ERC-1271 contract wallets.
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, signature);
        if (err != ECDSA.RecoverError.NoError || recovered != newWallet) {
            (bool ok, bytes memory res) =
                newWallet.staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, signature)));
            if (!(ok && res.length >= 32 && abi.decode(res, (bytes4)) == ERC1271_MAGICVALUE)) {
                revert InvalidWalletSignature();
            }
        }

        // Consume the nonce so this signature cannot be replayed to revert a later change.
        unchecked {
            _walletNonce[agentId] = nonce + 1;
        }

        _metadata[agentId][AGENT_WALLET_KEY] = abi.encodePacked(newWallet);
        emit MetadataSet(agentId, AGENT_WALLET_KEY, AGENT_WALLET_KEY, abi.encodePacked(newWallet));
    }

    function unsetAgentWallet(uint256 agentId) external {
        _requireAuthorized(agentId);
        _metadata[agentId][AGENT_WALLET_KEY] = "";
        emit MetadataSet(agentId, AGENT_WALLET_KEY, AGENT_WALLET_KEY, "");
    }

    // --------------------------------------------------------------- revocation

    /// @notice Irreversibly mark an agent revoked. A trustless registry has no authority that can revoke
    ///         on a user's behalf, so this is the owner's own declaration that the agent is retired or
    ///         compromised; being set-once and preserved across transfer, it cannot be undone by rotating
    ///         the wallet or transferring the token. It is a signal, not an enforcement: the registry does
    ///         not block a revoked agent's operations, and consumers decide what a revoked status means.
    function revokeAgent(uint256 agentId) external {
        _requireAuthorized(agentId);
        if (_revoked[agentId]) revert AlreadyRevoked();
        _revoked[agentId] = true;
        emit AgentRevoked(agentId, msg.sender);
    }

    function isRevoked(uint256 agentId) external view returns (bool) {
        return _revoked[agentId];
    }

    // ----------------------------------------------------------- authorisation

    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool) {
        return _isAuthorized(ownerOf(agentId), spender, agentId);
    }

    function _requireAuthorized(uint256 agentId) private view {
        if (!_isAuthorized(ownerOf(agentId), msg.sender, agentId)) revert NotAuthorized();
    }

    // --------------------------------------------------------------- transfers

    /// @dev The verified agentWallet does not survive a change of owner. Cleared before the
    ///      super call, which may hand control to the recipient.
    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721, ERC721Enumerable)
        returns (address)
    {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) {
            _metadata[tokenId][AGENT_WALLET_KEY] = "";
            emit MetadataSet(tokenId, AGENT_WALLET_KEY, AGENT_WALLET_KEY, "");
        }
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

    // ----------------------------------------------------------------- ERC-165

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721URIStorage, ERC721Enumerable, IERC165)
        returns (bool)
    {
        return interfaceId == type(IIdentityRegistry).interfaceId || super.supportsInterface(interfaceId);
    }
}
