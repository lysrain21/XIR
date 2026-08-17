// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EndpointV2} from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import {SendUln302} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/uln302/SendUln302.sol";
import {ReceiveUln302} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/uln302/ReceiveUln302.sol";
import {UlnConfig, SetDefaultUlnConfigParam} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import {
    ExecutorConfig,
    SetDefaultExecutorConfigParam
} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/SendLibBase.sol";
import {DVN} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/dvn/DVN.sol";
import {DVNFeeLib} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/dvn/DVNFeeLib.sol";
import {IDVN} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/interfaces/IDVN.sol";
import {Executor} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/Executor.sol";
import {ExecutorFeeLib} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/ExecutorFeeLib.sol";
import {IExecutor} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/interfaces/IExecutor.sol";
import {PriceFeed} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/PriceFeed.sol";
import {ILayerZeroPriceFeed} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/interfaces/ILayerZeroPriceFeed.sol";
import {Treasury} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/Treasury.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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

contract DeployLayerZeroNative {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 deployerKey = vm.envUint("LZ_DEPLOYER_KEY");
        address deployer = vm.envAddress("LZ_DEPLOYER_ADDRESS");
        address dvnSigner = vm.envAddress("LZ_DVN_SIGNER_ADDRESS");
        uint32 localEid = uint32(vm.envUint("LZ_LOCAL_EID"));
        uint32[5] memory allEids = [
            uint32(vm.envUint("LZ_EID_A")),
            uint32(vm.envUint("LZ_EID_B")),
            uint32(vm.envUint("LZ_EID_C")),
            uint32(vm.envUint("LZ_EID_D")),
            uint32(vm.envUint("LZ_EID_E"))
        ];
        uint32[] memory remoteEids = remoteEidsFor(localEid, allEids);

        vm.startBroadcast(deployerKey);
        EndpointV2 endpoint = new EndpointV2(localEid, deployer);
        SendUln302 sendUln = new SendUln302(address(endpoint), 100000, 100000);
        ReceiveUln302 receiveUln = new ReceiveUln302(address(endpoint));
        Treasury treasury = new Treasury();
        sendUln.setTreasury(address(treasury));

        PriceFeed priceFeedImplementation = new PriceFeed();
        PriceFeed priceFeed = PriceFeed(
            address(
                new ERC1967Proxy(address(priceFeedImplementation), abi.encodeCall(PriceFeed.initialize, (deployer)))
            )
        );
        priceFeed.setNativeTokenPriceUSD(1e20);
        ILayerZeroPriceFeed.UpdatePrice[] memory prices = new ILayerZeroPriceFeed.UpdatePrice[](remoteEids.length);
        for (uint256 i = 0; i < remoteEids.length; i++) {
            prices[i] = ILayerZeroPriceFeed.UpdatePrice(remoteEids[i], ILayerZeroPriceFeed.Price(1e20, 1, 1));
        }
        priceFeed.setPrice(prices);

        address[] memory messageLibs = new address[](2);
        messageLibs[0] = address(sendUln);
        messageLibs[1] = address(receiveUln);
        address[] memory signers = new address[](1);
        signers[0] = dvnSigner;
        address[] memory admins = new address[](2);
        admins[0] = deployer;
        admins[1] = dvnSigner;
        DVN dvn = new DVN(localEid, localEid, messageLibs, address(priceFeed), signers, 1, admins);
        DVNFeeLib dvnFeeLib = new DVNFeeLib(localEid, 1e18);
        dvn.setWorkerFeeLib(address(dvnFeeLib));

        Executor executorImplementation = new Executor();
        Executor executor = Executor(
            payable(address(
                    new ERC1967Proxy(
                        address(executorImplementation),
                        abi.encodeCall(
                            Executor.initialize,
                            (address(endpoint), address(0), messageLibs, address(priceFeed), deployer, admins)
                        )
                    )
                ))
        );
        ExecutorFeeLib executorFeeLib = new ExecutorFeeLib(localEid, 1e18);
        executor.setWorkerFeeLib(address(executorFeeLib));

        IDVN.DstConfigParam[] memory dvnConfigs = new IDVN.DstConfigParam[](remoteEids.length);
        IExecutor.DstConfigParam[] memory executorConfigs = new IExecutor.DstConfigParam[](remoteEids.length);
        SetDefaultUlnConfigParam[] memory ulnConfigs = new SetDefaultUlnConfigParam[](remoteEids.length);
        SetDefaultExecutorConfigParam[] memory sendExecutorConfigs =
            new SetDefaultExecutorConfigParam[](remoteEids.length);
        address[] memory requiredDvns = new address[](1);
        requiredDvns[0] = address(dvn);
        for (uint256 i = 0; i < remoteEids.length; i++) {
            dvnConfigs[i] = IDVN.DstConfigParam(remoteEids[i], 5000, 10000, 0);
            executorConfigs[i] = IExecutor.DstConfigParam({
                dstEid: remoteEids[i],
                lzReceiveBaseGas: 5000,
                lzComposeBaseGas: 0,
                multiplierBps: 10000,
                floorMarginUSD: 0,
                nativeCap: 1 ether
            });
            ulnConfigs[i] =
                SetDefaultUlnConfigParam(remoteEids[i], UlnConfig(1, 1, 0, 0, requiredDvns, new address[](0)));
            sendExecutorConfigs[i] =
                SetDefaultExecutorConfigParam(remoteEids[i], ExecutorConfig(1000, address(executor)));
        }
        dvn.setDstConfig(dvnConfigs);
        executor.setDstConfig(executorConfigs);
        sendUln.setDefaultUlnConfigs(ulnConfigs);
        sendUln.setDefaultExecutorConfigs(sendExecutorConfigs);
        receiveUln.setDefaultUlnConfigs(ulnConfigs);
        endpoint.registerLibrary(address(sendUln));
        endpoint.registerLibrary(address(receiveUln));
        for (uint256 i = 0; i < remoteEids.length; i++) {
            endpoint.setDefaultSendLibrary(remoteEids[i], address(sendUln));
            endpoint.setDefaultReceiveLibrary(remoteEids[i], address(receiveUln), 0);
        }
        vm.stopBroadcast();

        vm.writeJson(
            _manifest(
                localEid,
                endpoint,
                sendUln,
                receiveUln,
                dvn,
                executor,
                priceFeed,
                treasury,
                dvnFeeLib,
                executorFeeLib,
                priceFeedImplementation,
                executorImplementation
            ),
            vm.envString("LZ_DEPLOYMENT_OUTPUT")
        );
    }

    function remoteEidsFor(uint32 localEid, uint32[5] memory allEids) public pure returns (uint32[] memory result) {
        result = new uint32[](4);
        uint256 cursor;
        uint256 localMatches;
        for (uint256 i = 0; i < allEids.length; i++) {
            for (uint256 j = 0; j < i; j++) {
                require(allEids[i] != allEids[j], "duplicate eid");
            }
            if (allEids[i] == localEid) {
                localMatches++;
            } else {
                result[cursor++] = allEids[i];
            }
        }
        require(localMatches == 1 && cursor == 4, "unsupported local eid");
    }

    function _entry(string memory name, address value) private view returns (string memory) {
        return string.concat('"', name, '":"', vm.toString(value), '"');
    }

    function _manifest(
        uint32 localEid,
        EndpointV2 endpoint,
        SendUln302 sendUln,
        ReceiveUln302 receiveUln,
        DVN dvn,
        Executor executor,
        PriceFeed priceFeed,
        Treasury treasury,
        DVNFeeLib dvnFeeLib,
        ExecutorFeeLib executorFeeLib,
        PriceFeed priceFeedImplementation,
        Executor executorImplementation
    ) private view returns (string memory) {
        return string.concat(
            '{"schema_version":"xir-lab-layerzero-deployment-v1","local_eid":',
            vm.toString(localEid),
            ',"contracts":{',
            _entry("endpoint_v2", address(endpoint)),
            ",",
            _entry("send_uln_302", address(sendUln)),
            ",",
            _entry("receive_uln_302", address(receiveUln)),
            ",",
            _entry("dvn", address(dvn)),
            ",",
            _entry("executor", address(executor)),
            ",",
            _entry("price_feed", address(priceFeed)),
            ",",
            _entry("treasury", address(treasury)),
            ",",
            _entry("dvn_fee_lib", address(dvnFeeLib)),
            ",",
            _entry("executor_fee_lib", address(executorFeeLib)),
            ",",
            _entry("price_feed_implementation", address(priceFeedImplementation)),
            ",",
            _entry("executor_implementation", address(executorImplementation)),
            "}}"
        );
    }
}
