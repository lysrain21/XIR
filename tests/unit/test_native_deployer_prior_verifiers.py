from __future__ import annotations

from typing import Any

from xir_lab.native.deployer import PROFILE_HASHES, NativeApplicationDeployer


def test_deployer_binds_each_prior_profile_to_its_intermediate_ingress() -> None:
    deployer = object.__new__(NativeApplicationDeployer)
    deployer.manifest = {
        "source": {
            "h_source": "0x0000000000000000000000000000000000000101",
            "l_source": "0x0000000000000000000000000000000000000102",
        },
        "intermediate": {
            "h_in": "0x0000000000000000000000000000000000000201",
            "l_in": "0x0000000000000000000000000000000000000202",
            "h_hom_out": "0x0000000000000000000000000000000000000203",
            "l_hom_out": "0x0000000000000000000000000000000000000204",
            "h_xir_out": "0x0000000000000000000000000000000000000205",
            "l_xir_out": "0x0000000000000000000000000000000000000206",
            "homogeneous_forwarder": "0x0000000000000000000000000000000000000207",
        },
        "destination": {
            "h_hom_in": "0x0000000000000000000000000000000000000301",
            "l_hom_in": "0x0000000000000000000000000000000000000302",
            "h_xir_in": "0x0000000000000000000000000000000000000303",
            "l_xir_in": "0x0000000000000000000000000000000000000304",
            "receiver": "0x0000000000000000000000000000000000000305",
        },
    }
    calls: list[tuple[str, str, str, tuple[Any, ...]]] = []

    def record_call(
        role: str,
        manifest_role: str,
        _source: str,
        _contract: str,
        function_name: str,
        arguments: list[Any],
        *,
        value: int = 0,
    ) -> None:
        del value
        calls.append((role, manifest_role, function_name, tuple(arguments)))

    deployer.call = record_call  # type: ignore[assignment,method-assign]
    deployer._set_peer = lambda *args, **kwargs: None  # type: ignore[method-assign]

    deployer._configure_peers_and_routes()

    binding_calls = [call for call in calls if call[2] == "setPriorVerifier"]
    bindings = {
        (role, outbound, bytes(arguments[0]), str(arguments[1]).lower())
        for role, outbound, _function, arguments in binding_calls
    }
    expected = {
        (
            "intermediate",
            outbound,
            PROFILE_HASHES[profile],
            deployer.manifest["intermediate"][inbound].lower(),
        )
        for outbound in ("h_xir_out", "l_xir_out")
        for profile, inbound in (("H_AB", "h_in"), ("L_AB", "l_in"))
    }
    assert bindings == expected
