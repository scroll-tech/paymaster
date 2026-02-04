// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";
import {VerifyingPaymaster} from "@verifying-paymaster/VerifyingPaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";

/// @title DeployPaymaster
/// @notice Deploy script for VerifyingPaymaster contract
/// @dev Uses CREATE2 via Safe Singleton Factory for deterministic addresses
contract DeployPaymaster is Script {
    // Safe Singleton Factory - deployed on all major networks
    address constant SAFE_SINGLETON_FACTORY = 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7;

    // EntryPoint v0.7 - same address on all networks
    address constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() public {
        // Load environment variables
        address verifyingSigner = vm.envAddress("VERIFYING_SIGNER");
        address owner = vm.envAddress("OWNER");
        bytes32 salt = vm.envOr("DEPLOY_SALT", bytes32(0));

        console2.log("Deploying VerifyingPaymaster...");
        console2.log("  EntryPoint:", ENTRYPOINT_V07);
        console2.log("  Verifying Signer:", verifyingSigner);
        console2.log("  Owner:", owner);
        console2.log("  Salt:", vm.toString(salt));

        // Compute expected address
        address expectedAddress = computeAddress(verifyingSigner, owner, salt);
        console2.log("  Expected Address:", expectedAddress);

        // Check if already deployed
        if (expectedAddress.code.length > 0) {
            console2.log("Contract already deployed at expected address");
            return;
        }

        // vm.startBroadcast() without args uses the wallet provided via CLI flags
        // (--private-key, --trezor, --ledger, etc.)
        vm.startBroadcast();

        address deployed = deploy(verifyingSigner, owner, salt);

        vm.stopBroadcast();

        console2.log("Deployed VerifyingPaymaster at:", deployed);

        // Verify deployment
        require(deployed == expectedAddress, "Deployed address mismatch");
        require(deployed.code.length > 0, "Deployment failed");

        // Log contract state
        VerifyingPaymaster paymaster = VerifyingPaymaster(payable(deployed));
        console2.log("  verifyingSigner:", paymaster.verifyingSigner());
        console2.log("  owner:", paymaster.owner());
    }

    function deploy(address verifyingSigner, address owner, bytes32 salt) internal returns (address) {
        bytes memory creationCode = type(VerifyingPaymaster).creationCode;
        bytes memory args = abi.encode(IEntryPoint(ENTRYPOINT_V07), verifyingSigner, owner);
        bytes memory callData = abi.encodePacked(salt, creationCode, args);

        (bool success, bytes memory result) = SAFE_SINGLETON_FACTORY.call(callData);
        require(success, "Deploy failed");

        return address(bytes20(result));
    }

    function computeAddress(address verifyingSigner, address owner, bytes32 salt) public pure returns (address) {
        bytes memory creationCode = type(VerifyingPaymaster).creationCode;
        bytes memory args = abi.encode(IEntryPoint(ENTRYPOINT_V07), verifyingSigner, owner);
        bytes32 initCodeHash = keccak256(abi.encodePacked(creationCode, args));

        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), SAFE_SINGLETON_FACTORY, salt, initCodeHash))))
        );
    }
}
