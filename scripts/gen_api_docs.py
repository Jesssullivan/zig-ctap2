#!/usr/bin/env python3
"""Generate API reference docs from C headers and Zig sources."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs" / "api"


def extract_c_api(header: Path) -> str:
    """Extract function signatures and doc comments from a C header."""
    text = header.read_text()
    lines = text.splitlines()

    sections: list[str] = []
    current_comment: list[str] = []
    current_section = ""
    in_function = False
    func_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Section headers
        if stripped.startswith("// ---") or (
            stripped.startswith("//") and "---" in stripped and len(stripped) > 10
        ):
            heading = re.sub(r"^//\s*[-─]+\s*", "", stripped).strip()
            heading = re.sub(r"\s*[-─]+$", "", heading).strip()
            if heading:
                current_section = heading
                sections.append(f"\n### {current_section}\n")
            continue

        # Doc comments
        if stripped.startswith("//") or stripped.startswith("/**") or stripped.startswith("*"):
            comment = stripped
            comment = re.sub(r"^/\*\*\s?", "", comment)
            comment = re.sub(r"\*/\s*$", "", comment)
            comment = re.sub(r"^\*\s?", "", comment)
            comment = re.sub(r"^//\s?", "", comment)
            if comment or current_comment:
                current_comment.append(comment)
            continue

        # #define constants
        if stripped.startswith("#define") and not stripped.startswith("#define CTAP2_H"):
            sections.append(f"```c\n{stripped}\n```\n")
            current_comment = []
            continue

        # typedef
        if stripped.startswith("typedef"):
            if current_comment:
                sections.append("\n".join(current_comment) + "\n")
                current_comment = []
            sections.append(f"```c\n{stripped}\n```\n")
            continue

        # Function declarations
        if (
            not stripped.startswith("#")
            and not stripped.startswith("typedef")
            and ("(" in stripped or in_function)
            and not stripped.startswith("{")
            and not stripped.startswith("}")
        ):
            if not in_function and "(" in stripped:
                in_function = True
                func_lines = [line]
            elif in_function:
                func_lines.append(line)

            if in_function and ");" in stripped:
                in_function = False
                func_text = "\n".join(func_lines)
                if current_comment:
                    sections.append("\n".join(current_comment) + "\n")
                    current_comment = []
                sections.append(f"```c\n{func_text}\n```\n")
                func_lines = []
            continue

        if current_comment and stripped == "":
            current_comment = []

    return "\n".join(sections)


def extract_zig_api(src_dir: Path) -> str:
    """Extract pub fn signatures and doc comments from Zig sources."""
    sections: list[str] = []

    for zig_file in sorted(src_dir.glob("*.zig")):
        if zig_file.name == "ffi.zig":
            continue  # FFI covered by C header

        text = zig_file.read_text()
        lines = text.splitlines()
        module_fns: list[str] = []
        current_comment: list[str] = []

        for line in lines:
            stripped = line.strip()

            # Doc comments (///)
            if stripped.startswith("///"):
                current_comment.append(stripped[3:].strip())
                continue

            # Public function or type
            if stripped.startswith("pub fn ") or (
                stripped.startswith("pub const ") and ("= enum" in stripped or "= struct" in stripped or "= union" in stripped)
            ):
                if current_comment:
                    module_fns.append("\n".join(current_comment))
                    current_comment = []
                module_fns.append(f"```zig\n{stripped}\n```\n")
                continue

            if not stripped.startswith("///"):
                current_comment = []

        if module_fns:
            sections.append(f"\n### `{zig_file.name}`\n")
            sections.extend(module_fns)

    return "\n".join(sections)


def main():
    DOCS.mkdir(parents=True, exist_ok=True)

    # C FFI reference
    header = ROOT / "include" / "ctap2.h"
    c_content = extract_c_api(header)
    (DOCS / "c-ffi.md").write_text(
        f"# C FFI Reference\n\n"
        f"Auto-generated from [`include/ctap2.h`](https://github.com/Jesssullivan/zig-ctap2/blob/main/include/ctap2.h).\n\n"
        f"All functions are blocking (with timeouts) and thread-safe. "
        f"Result data is written to caller-provided buffers.\n"
        f"{c_content}\n"
    )

    # Zig API reference
    zig_content = extract_zig_api(ROOT / "src")
    (DOCS / "zig-api.md").write_text(
        f"# Zig API Reference\n\n"
        f"Auto-generated from Zig source files in [`src/`](https://github.com/Jesssullivan/zig-ctap2/tree/main/src).\n\n"
        f"These are the internal Zig modules. For C/Swift interop, see the [C FFI Reference](c-ffi.md).\n"
        f"{zig_content}\n"
    )

    print(f"Generated {DOCS / 'c-ffi.md'}")
    print(f"Generated {DOCS / 'zig-api.md'}")


if __name__ == "__main__":
    main()
