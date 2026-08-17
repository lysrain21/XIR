from __future__ import annotations

from pathlib import Path

import pytest

from xir_lab.localnet.toolchain_preflight import discover_libclang
from xir_lab.localnet.topology import LocalTopologyError


def test_versioned_libclang_soname_is_admitted_and_cpp_is_excluded(
    tmp_path: Path,
) -> None:
    library = tmp_path / "libclang-18.so.18"
    library.write_bytes(b"fixture")
    cpp = tmp_path / "libclang-cpp.so.18"
    cpp.write_bytes(b"fixture")
    loaded: list[str] = []

    def loader(path: str) -> object:
        loaded.append(path)
        return object()

    selected = discover_libclang(
        "\n".join(
            (
                f"libclang-cpp.so.18 (libc6,x86-64) => {cpp}",
                f"libclang-18.so.18 (libc6,x86-64) => {library}",
            )
        ),
        loader=loader,
    )
    assert selected == library.resolve()
    assert loaded == [str(library)]


@pytest.mark.parametrize(
    "output",
    (
        "",
        "libclang-cpp.so.18 (libc6,x86-64) => /lib/libclang-cpp.so.18",
    ),
)
def test_absent_or_cpp_only_libclang_fails_before_build(output: str) -> None:
    with pytest.raises(LocalTopologyError, match="loadable libclang"):
        discover_libclang(output, loader=lambda _path: object())
