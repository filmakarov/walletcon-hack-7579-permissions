// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IModule } from "contracts/interfaces/modules/IModule.sol";
import { IValidator, VALIDATION_SUCCESS, VALIDATION_FAILED } from "contracts/interfaces/modules/IERC7579Modules.sol";
import { EncodedModuleTypes } from "erc7579-ref/ModuleTypeLib.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

type ValidAfter is uint48;
type ValidUntil is uint48;

struct SingleSignerPermission {
    ValidUntil validUntil;
    ValidAfter validAfter;
    address signatureValidationAlgorithm;
    bytes signer;
    address[] policies;
    bytes[] policyDatas;
}

contract PermissionsValidator is IValidator {

    mapping(bytes32 singleSignerPermissionId => mapping (address smartAccount => SingleSignerPermission)) public smartAccountOwners;

    /// @inheritdoc IValidator
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        returns (uint256 validationData)
    {
        if (_isBatchExecuteCall(userOp)) {
            rv = _validateUserOpBatchExecute(userOp, userOpHash);
        } else {
            rv = _validateUserOpSingleExecute(userOp, userOpHash);
        }
    }

    /// @inheritdoc IValidator
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        returns (bytes4)
    {
        sender;
        hash;
        data;
        return 0xffffffff;
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external {
        smartAccountOwners[msg.sender] = address(bytes20(data));
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external {
        delete smartAccountOwners[msg.sender];
    }

    /// @inheritdoc IModule
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 1;
    }

    function isOwner(address account, address owner) external view returns (bool) {
        return smartAccountOwners[account] == owner;
    }

    /// @inheritdoc IModule
    function getModuleTypes() external view returns (EncodedModuleTypes) {
        // solhint-disable-previous-line no-empty-blocks
    }

    // Review
    function test(uint256 a) public {
        a;
    }

    function getSingleSignerPermissionId(
        ValidUntil validUntil,
        ValidAfter validAfter,
        address signatureValidationAlgorithm,
        bytes signer,
        address[] policies,
        bytes[] policyDatas
    )
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                flag,
                signer,
                ValidAfter.unwrap(validAfter),
                ValidUntil.unwrap(validUntil),
                _policyConfig,
                signerData,
                policyData
            )
        );
    }
}



/**

TODO:

[ ] add simple ecdsa algorithm contract
[ ] add erc721 token policy contract (whatever is required for demo dapp)

 */