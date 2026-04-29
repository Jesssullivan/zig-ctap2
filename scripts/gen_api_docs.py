#!/usr/bin/env python3
"""Compatibility wrapper for API reference generation.

The main documentation generator owns the C FFI and Zig API parsers. Keep this
entry point for older local workflows, but route it through the same functions
used by `scripts/gen_docs.py`.
"""

from gen_docs import REPO_ROOT, generate_c_ffi_doc, generate_zig_api_doc, write_file


def main() -> None:
    c_ffi = generate_c_ffi_doc()
    if c_ffi:
        write_file(REPO_ROOT / "docs" / "api" / "c-ffi.md", c_ffi)

    zig_api = generate_zig_api_doc()
    if zig_api:
        write_file(REPO_ROOT / "docs" / "api" / "zig-api.md", zig_api)


if __name__ == "__main__":
    main()
