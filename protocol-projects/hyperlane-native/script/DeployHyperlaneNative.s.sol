// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Mailbox} from "lib/hyperlane/solidity/contracts/Mailbox.sol";
import {MerkleTreeHook} from "lib/hyperlane/solidity/contracts/hooks/MerkleTreeHook.sol";
import {ProtocolFee} from "lib/hyperlane/solidity/contracts/hooks/ProtocolFee.sol";
import {
    StaticMessageIdMultisigIsmFactory
} from "lib/hyperlane/solidity/contracts/isms/multisig/StaticMultisigIsm.sol";
import {
    ValidatorAnnounce
} from "lib/hyperlane/solidity/contracts/isms/multisig/ValidatorAnnounce.sol";

interface Vm {
    function envUint(string calldata name) external view returns (uint256);
    function envAddress(string calldata name) external view returns (address);
    function envString(string calldata name) external view returns (string memory);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
    function writeJson(string calldata json, string calldata path) external;
    function toString(address value) external pure returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
}

contract DeployHyperlaneNative {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 deployerKey = vm.envUint("HYP_DEPLOYER_KEY");
        address owner = vm.envAddress("HYP_OWNER_ADDRESS");
        address validator = vm.envAddress("HYP_VALIDATOR_ADDRESS");
        uint32 localDomain = uint32(vm.envUint("HYP_LOCAL_DOMAIN"));

        vm.startBroadcast(deployerKey);
        Mailbox mailbox = new Mailbox(localDomain);
        StaticMessageIdMultisigIsmFactory factory =
            new StaticMessageIdMultisigIsmFactory();
        address[] memory validators = new address[](1);
        validators[0] = validator;
        address ism = factory.deploy(validators, 1);
        MerkleTreeHook merkleTreeHook = new MerkleTreeHook(address(mailbox));
        ProtocolFee protocolFee = new ProtocolFee(0, 0, owner, owner);
        ValidatorAnnounce validatorAnnounce =
            new ValidatorAnnounce(address(mailbox));
        mailbox.initialize(
            owner,
            ism,
            address(protocolFee),
            address(merkleTreeHook)
        );
        vm.stopBroadcast();

        vm.writeJson(
            string.concat(
                '{"schema_version":"xir-lab-hyperlane-native-deployment-v1",',
                '"local_domain":',
                vm.toString(localDomain),
                ',"contracts":{',
                _entry("mailbox", address(mailbox)),
                ",",
                _entry("merkleTreeHook", address(merkleTreeHook)),
                ",",
                _entry("validatorAnnounce", address(validatorAnnounce)),
                ",",
                _entry("defaultIsm", ism),
                ",",
                _entry(
                    "staticMessageIdMultisigIsmFactory",
                    address(factory)
                ),
                ",",
                _entry("protocolFee", address(protocolFee)),
                "}}"
            ),
            vm.envString("HYP_DEPLOYMENT_OUTPUT")
        );
    }

    function _entry(
        string memory name,
        address value
    ) private view returns (string memory) {
        return
            string.concat(
                '"',
                name,
                '":"',
                vm.toString(value),
                '"'
            );
    }
}
