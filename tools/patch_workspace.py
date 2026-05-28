#!/usr/bin/env python3

"""Patch a YACL WORKSPACE with the local repositories required by linerpsu."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


SECURE_JOIN_BUILD = r'''
cc_library(
    name = "headers",
    hdrs = glob([
        "secure-join/**/*.h",
        "secure-join/**/*.hpp",
        "secure-join/**/*.hh",
        "out/**/*.h",
        "out/**/*.hpp",
    ]),
    includes = [
        ".",
        "out/build/linux",
    ],
    visibility = ["//visibility:public"],
)

cc_import(
    name = "securejoin_static",
    static_library = "out/build/linux/secure-join/libsecureJoin.a",
    alwayslink = True,
)

cc_library(
    name = "securejoin",
    deps = [
        ":headers",
        ":securejoin_static",
    ],
    visibility = ["//visibility:public"],
)

cc_import(
    name = "libote_static",
    static_library = "out/build/linux/libOTe/libOTe/liblibOTe.a",
    alwayslink = True,
)

cc_import(
    name = "cryptotools_static",
    static_library = "out/build/linux/libOTe/cryptoTools/cryptoTools/libcryptoTools.a",
    alwayslink = True,
)

cc_import(
    name = "macoro_static",
    static_library = "out/build/linux/macoro/macoro/libmacoro.a",
    alwayslink = True,
)

cc_import(
    name = "coproto_static",
    static_library = "out/build/linux/coproto/coproto/libcoproto.a",
    alwayslink = True,
)

cc_library(
    name = "securejoin_libs",
    deps = [
        ":securejoin_static",
        ":libote_static",
        ":cryptotools_static",
        ":macoro_static",
        ":coproto_static",
        ":headers",
    ],
    visibility = ["//visibility:public"],
)
'''


LIBOTE_BUILD = r'''
STATIONARY_HEADERS = glob([
    "libOTe/**/*.h",
    "libOTe/**/*.hpp",
    "libOTe/**/*.ipp",
    "cryptoTools/**/*.h",
    "cryptoTools/**/*.hpp",
    "cryptoTools/**/*.ipp",
    "out/coproto/**/*.h",
    "out/coproto/**/*.hpp",
    "out/coproto/**/*.ipp",
    "out/macoro/**/*.h",
    "out/macoro/**/*.hpp",
    "out/macoro/**/*.ipp",
    "thirdparty/**/*.h",
    "thirdparty/**/*.hpp",
    "thirdparty/**/*.ipp",
    "out/build/linux/**/*.h",
    "out/build/linux/**/*.hpp",
    "out/build/linux/**/*.ipp",
    "out/install/linux/include/**/*.h",
    "out/install/linux/include/**/*.hpp",
    "out/install/linux/include/**/*.ipp",
])

filegroup(
    name = "header_files",
    srcs = STATIONARY_HEADERS,
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = STATIONARY_HEADERS,
    includes = [
        ".",
        "out/build/linux",
        "cryptoTools",
        "out/build/linux/cryptoTools",
        "out/coproto",
        "out/build/linux/coproto",
        "out/macoro",
        "out/build/linux/macoro",
        "thirdparty",
        "out/build/linux/thirdparty",
        "out/install/linux/include",
    ],
    visibility = ["//visibility:public"],
)

cc_import(
    name = "libote_static",
    static_library = "out/build/linux/libOTe/liblibOTe.a",
    alwayslink = True,
)

cc_import(
    name = "simplestot_static",
    static_library = "out/build/linux/thirdparty/SimplestOT/libSimplestOT.a",
    alwayslink = True,
)

cc_import(
    name = "kyberot_static",
    static_library = "out/build/linux/thirdparty/KyberOT/libKyberOT.a",
    alwayslink = True,
)

cc_import(
    name = "cryptotools_static",
    static_library = "out/build/linux/cryptoTools/cryptoTools/libcryptoTools.a",
    alwayslink = True,
)

cc_import(
    name = "coproto_static",
    static_library = "out/build/linux/coproto/coproto/libcoproto.a",
    alwayslink = True,
)

cc_import(
    name = "macoro_static",
    static_library = "out/build/linux/macoro/macoro/libmacoro.a",
    alwayslink = True,
)

cc_import(
    name = "sodium_static",
    static_library = "out/install/linux/lib/libsodium.a",
    alwayslink = True,
)

cc_import(
    name = "boost_system_static",
    static_library = "out/install/linux/lib/libboost_system.a",
    alwayslink = True,
)

cc_import(
    name = "boost_thread_static",
    static_library = "out/install/linux/lib/libboost_thread.a",
    alwayslink = True,
)

cc_library(
    name = "libs",
    deps = [
        ":boost_system_static",
        ":boost_thread_static",
        ":coproto_static",
        ":cryptotools_static",
        ":kyberot_static",
        ":libote_static",
        ":macoro_static",
        ":simplestot_static",
        ":sodium_static",
    ],
    visibility = ["//visibility:public"],
)
'''


PIC_LIBOTE_BUILD = r'''
filegroup(
    name = "headers",
    srcs = glob([
        "rebuild/**/*.h",
        "rebuild/**/*.hpp",
        "rebuild/**/*.ipp",
        "deps/coproto/**/*.h",
        "deps/coproto/**/*.hpp",
        "deps/coproto/**/*.ipp",
        "deps/macoro/**/*.h",
        "deps/macoro/**/*.hpp",
        "deps/macoro/**/*.ipp",
        "install/include/**/*.h",
        "install/include/**/*.hpp",
        "install/include/**/*.ipp",
    ]),
    visibility = ["//visibility:public"],
)

filegroup(
    name = "libs",
    srcs = [
        "rebuild/libOTe/liblibOTe.a",
        "rebuild/cryptoTools/cryptoTools/libcryptoTools.a",
        "rebuild/coproto/coproto/libcoproto.a",
        "rebuild/macoro/macoro/libmacoro.a",
        "install/lib/libsodium.a",
    ],
    visibility = ["//visibility:public"],
)
'''


def workspace_repo_block(repo: str, root: str, build_file_content: str) -> str:
    return f'''
new_local_repository(
    name = "{repo}",
    path = "{root}",
    build_file_content = """{build_file_content}""",
)
'''


def replace_or_add_repo(
    text: str, repo: str, root: str, build_file_content: str
) -> tuple[str, str]:
    pattern = re.compile(
        r'(new_local_repository\(\s*name\s*=\s*"'
        + re.escape(repo)
        + r'"[\s\S]*?path\s*=\s*")[^"]+(")',
        re.MULTILINE,
    )
    out, count = pattern.subn(lambda m: m.group(1) + root + m.group(2), text, count=1)
    if count == 1:
        return out, "updated"
    out = text.rstrip()
    out += "\n\n# Added by examples/linerpsu/tools/patch_workspace.py.\n"
    out += workspace_repo_block(repo, root, build_file_content)
    return out, "added"


def absolute_env_path(name: str, default: Path) -> str:
    raw = os.environ.get(name, str(default))
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return str(path.resolve())


def main() -> int:
    workspace = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("WORKSPACE")
    workspace = workspace.resolve()
    if not workspace.exists():
        print(f"missing WORKSPACE file: {workspace}", file=sys.stderr)
        return 1

    yacl_root = workspace.parent
    deps_root = Path(os.environ.get("LINERPSU_DEPS", yacl_root / ".linerpsu-deps"))
    if not deps_root.is_absolute():
        deps_root = yacl_root / deps_root

    repos = [
        (
            "local_secure_join_usr",
            absolute_env_path("SECURE_JOIN_ROOT", deps_root / "secure-join"),
            SECURE_JOIN_BUILD,
        ),
        (
            "local_libote_stationary",
            absolute_env_path("LIBOTE_ROOT", deps_root / "libOTe"),
            LIBOTE_BUILD,
        ),
        (
            "local_otmpsi_libote_stationary_pic",
            absolute_env_path("LIBOTE_PIC_ROOT", deps_root / "libOTe-pic"),
            PIC_LIBOTE_BUILD,
        ),
    ]

    text = workspace.read_text()
    actions = []
    for repo, root, build_content in repos:
        text, action = replace_or_add_repo(text, repo, root, build_content)
        actions.append(f"{action} {repo} -> {root}")

    workspace.write_text(text)
    for action in actions:
        print(action)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
