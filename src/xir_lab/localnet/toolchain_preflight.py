"""Fail-closed native protocol toolchain admission."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import secrets
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast

import rfc8785

from xir_lab.localnet.topology import LocalTopologyError

TOOLCHAIN_PREFLIGHT_SCHEMA = "xir-lab-native-multihop-toolchain-preflight-v1"
_LIBCLANG_PATTERN = re.compile(
    r"=>\s+(?P<path>/\S*/libclang(?:-[0-9]+)?\.so(?:\.[0-9]+)*)\s*$"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _semantic(document: dict[str, Any]) -> str:
    payload = dict(document)
    payload.pop("semantic_sha256", None)
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def discover_libclang(
    ldconfig_output: str,
    *,
    loader: Callable[[str], object] = ctypes.CDLL,
) -> Path:
    """Select the first deterministic, loadable libclang C API library."""

    candidates = sorted(
        {
            match.group("path")
            for line in ldconfig_output.splitlines()
            if (match := _LIBCLANG_PATTERN.search(line)) is not None
        }
    )
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_absolute() or not path.is_file():
            continue
        try:
            loader(str(path))
        except OSError:
            continue
        return path.resolve(strict=True)
    raise LocalTopologyError(
        "loadable libclang shared library is required before protocol build"
    )


def write_toolchain_preflight(
    *,
    output_path: Path,
    command: Sequence[str] = ("ldconfig", "-p"),
) -> dict[str, Any]:
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise LocalTopologyError("ldconfig failed while resolving libclang")
    library = discover_libclang(result.stdout)
    document: dict[str, Any] = {
        "schema_version": TOOLCHAIN_PREFLIGHT_SCHEMA,
        "valid": True,
        "libclang_path": str(library),
        "libclang_directory": str(library.parent),
        "libclang_sha256": _sha256(library),
    }
    document["semantic_sha256"] = _semantic(document)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(
        f".{output_path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, output_path)
    directory = os.open(output_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return document


def verify_toolchain_preflight(
    path: Path, *, require_library: bool = False
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalTopologyError("toolchain preflight is unavailable") from exc
    if not isinstance(value, dict):
        raise LocalTopologyError("toolchain preflight root must be an object")
    document = cast(dict[str, Any], value)
    library_value = document.get("libclang_path")
    library = Path(library_value) if isinstance(library_value, str) else Path()
    checks = {
        "schema": document.get("schema_version") == TOOLCHAIN_PREFLIGHT_SCHEMA,
        "valid": document.get("valid") is True,
        "semantic": document.get("semantic_sha256") == _semantic(document),
        "absolute": library.is_absolute(),
        "path_shape": library.is_absolute() and library.name.startswith("libclang"),
        "directory": document.get("libclang_directory") == str(library.parent),
        "digest_shape": isinstance(document.get("libclang_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", cast(str, document["libclang_sha256"]))
        is not None,
    }
    failed = sorted(name for name, valid in checks.items() if not valid)
    if failed:
        raise LocalTopologyError("toolchain preflight is invalid: " + ", ".join(failed))
    if require_library:
        if (
            not library.is_file()
            or str(library.resolve(strict=True)) != str(library)
            or document.get("libclang_sha256") != _sha256(library)
        ):
            raise LocalTopologyError("toolchain preflight libclang file identity drift")
        try:
            ctypes.CDLL(str(library))
        except OSError as exc:
            raise LocalTopologyError("toolchain preflight libclang is not loadable") from exc
    return document
