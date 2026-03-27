#!/usr/bin/env python3
"""Generate structured documentation from Zig library source code.

Produces:
  docs/source-tree.md   -- annotated file tree
  docs/api/c-ffi.md     -- C header API reference
  docs/api/zig-api.md   -- Zig public API reference
  LLMS.txt              -- llmstxt.org machine-readable summary
  AGENTS.md             -- agent-oriented interface spec

Usage:
  python scripts/gen_docs.py        # run from repo root
"""

import os
import re
import sys
import textwrap
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SKIP_DIRS = {".git", ".zig-cache", "zig-out", ".direnv", "__pycache__", "node_modules"}

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_NAME = REPO_ROOT.name


# ---------------------------------------------------------------------------
# 1. Source Tree Generator
# ---------------------------------------------------------------------------

def walk_tree(root: Path, prefix: str = "") -> list[str]:
    """Walk directory tree, returning formatted lines with annotations."""
    entries = sorted(
        [e for e in root.iterdir() if e.name not in SKIP_DIRS],
        key=lambda e: (not e.is_dir(), e.name),
    )
    lines = []
    for i, entry in enumerate(entries):
        is_last = i == len(entries) - 1
        connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
        extension = "    " if is_last else "\u2502   "

        if entry.is_dir():
            lines.append(f"{prefix}{connector}{entry.name}/")
            lines.extend(walk_tree(entry, prefix + extension))
        else:
            annotation = get_file_annotation(entry)
            ann_str = f"  ({annotation})" if annotation else ""
            lines.append(f"{prefix}{connector}{entry.name}{ann_str}")
    return lines


def get_file_annotation(path: Path) -> str:
    """Extract a one-line description from file content or infer from name."""
    suffix = path.suffix

    if suffix == ".zig":
        return _annotation_from_zig(path)
    elif suffix == ".h":
        return _annotation_from_c_header(path)
    elif path.name == "build.zig":
        return "Zig build configuration"
    elif path.name == "flake.nix":
        return "Nix flake"
    elif path.name == "flake.lock":
        return "Nix flake lockfile"
    elif path.name == "justfile":
        return "Just task runner recipes"
    elif path.name == "LICENSE":
        return "License"
    elif path.name.endswith(".md"):
        return _annotation_from_first_heading(path)
    elif path.name == "mkdocs.yml":
        return "MkDocs configuration"
    return ""


def _annotation_from_zig(path: Path) -> str:
    """Extract first /// doc comment from a .zig file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("///"):
                    comment = stripped[3:].strip()
                    if len(comment) > 60:
                        comment = comment[:57] + "..."
                    return comment
                elif stripped and not stripped.startswith("//"):
                    break
    except (OSError, UnicodeDecodeError):
        pass
    # Infer from filename
    stem = path.stem
    inferred = {
        "ffi": "C FFI exports",
        "cbor": "CBOR encoder/decoder",
        "ctap2": "CTAP2 command encoding/parsing",
        "ctaphid": "CTAPHID transport framing",
        "hid": "Platform USB HID transport",
        "hid_macos": "macOS IOKit HID",
        "hid_linux": "Linux hidraw HID",
        "pin": "CTAP2 Client PIN protocol",
    }
    return inferred.get(stem, "")


def _annotation_from_c_header(path: Path) -> str:
    """Count exported functions in a C header."""
    try:
        text = path.read_text(encoding="utf-8")
        funcs = re.findall(r"^\w[^;]*\([^)]*\)\s*;", text, re.MULTILINE)
        count = len(funcs)
        if count:
            return f"C header -- {count} functions"
    except (OSError, UnicodeDecodeError):
        pass
    return "C header"


def _annotation_from_first_heading(path: Path) -> str:
    """Extract first markdown heading."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("# "):
                    return line[2:].strip()[:60]
    except (OSError, UnicodeDecodeError):
        pass
    return ""


def generate_source_tree() -> str:
    """Generate the full source tree markdown."""
    lines = [f"# Source Tree: {REPO_NAME}", "", "```"]
    lines.append(f"{REPO_NAME}/")
    lines.extend(walk_tree(REPO_ROOT))
    lines.append("```")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 2. C FFI API Extractor
# ---------------------------------------------------------------------------

def parse_c_header(header_path: Path) -> list[dict]:
    """Parse a C header file and extract function declarations with docs."""
    try:
        text = header_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    lines = text.split("\n")
    functions = []

    func_decls = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()

        if (not stripped or stripped.startswith("#") or stripped.startswith("//")
                or stripped.startswith("/*") or stripped.startswith("*")
                or stripped.startswith("typedef") or stripped.startswith("}")
                or stripped.startswith("{") or stripped.startswith("extern")
                or stripped.startswith("#ifdef") or stripped.startswith("#endif")
                or stripped.startswith("#ifndef") or stripped.startswith("#define")
                or stripped.startswith("#include")):
            i += 1
            continue

        func_text = stripped
        start_line = i

        if ";" not in func_text:
            i += 1
            while i < len(lines) and ";" not in lines[i]:
                func_text += " " + lines[i].strip()
                i += 1
            if i < len(lines):
                func_text += " " + lines[i].strip()

        func = _parse_function_decl(func_text)
        if func:
            func_decls.append((func, start_line))

        i += 1

    for func, start_line in func_decls:
        doc_lines = _collect_doc_comment_above(lines, start_line)
        func["doc"] = doc_lines
        func["params_doc"] = _extract_param_docs(doc_lines)
        func["return_doc"] = _extract_return_doc(doc_lines)
        func["description"] = _extract_description(doc_lines)
        functions.append(func)

    return functions


def _collect_doc_comment_above(lines: list[str], func_start: int) -> list[str]:
    """Look backwards from a function to collect its doc comment."""
    doc_lines = []
    i = func_start - 1

    while i >= 0 and lines[i].strip() == "":
        i -= 1

    if i < 0:
        return []

    if lines[i].strip().endswith("*/"):
        block_end = i
        while i >= 0 and "/**" not in lines[i]:
            i -= 1
        if i >= 0:
            block_text = "\n".join(lines[i:block_end + 1])
            return _parse_doc_block(block_text)
        return []

    if lines[i].strip().startswith("//"):
        raw_comments = []
        while i >= 0 and lines[i].strip().startswith("//"):
            raw_comments.append(lines[i].strip())
            i -= 1
        raw_comments.reverse()

        for line in raw_comments:
            cleaned = line.lstrip("/").strip()
            stripped_of_box = re.sub(r"[\u2500-\u257f\-=]", "", cleaned).strip()
            if not stripped_of_box:
                continue
            label_match = re.match(r"^[\u2500-\u257f\-=]+\s*(.+?)\s*[\u2500-\u257f\-=]*$", cleaned)
            if label_match:
                continue
            if cleaned:
                doc_lines.append(cleaned)

    return doc_lines


def _parse_doc_block(text: str) -> list[str]:
    """Parse a /** ... */ doc comment block into lines."""
    lines = []
    for line in text.split("\n"):
        cleaned = line.strip()
        cleaned = re.sub(r"^/\*\*\s?", "", cleaned)
        cleaned = re.sub(r"\s?\*/$", "", cleaned)
        cleaned = re.sub(r"^\*\s?", "", cleaned)
        cleaned = cleaned.strip()
        if cleaned:
            lines.append(cleaned)
    return lines


def _parse_function_decl(text: str) -> dict | None:
    """Parse a C function declaration."""
    text = re.sub(r"\s+", " ", text).strip()
    match = re.match(r"^(.+?)\s+(\w+)\s*\(([^)]*)\)\s*;", text)
    if not match:
        return None
    return {
        "return_type": match.group(1).strip(),
        "name": match.group(2),
        "params_raw": match.group(3).strip(),
        "signature": text.rstrip(";").strip(),
    }


def _extract_param_docs(doc_lines: list[str]) -> dict[str, str]:
    """Extract @param descriptions from doc lines."""
    params = {}
    for line in doc_lines:
        m = re.match(r"@param\s+(\w+)\s+(.*)", line)
        if m:
            params[m.group(1)] = m.group(2).strip()
    return params


def _extract_return_doc(doc_lines: list[str]) -> str:
    """Extract @return description from doc lines."""
    for line in doc_lines:
        m = re.match(r"@return\s+(.*)", line)
        if m:
            return m.group(1).strip()
    return ""


def _extract_description(doc_lines: list[str]) -> str:
    """Extract description (non-@tag lines) from doc lines."""
    desc_lines = [l for l in doc_lines if not l.startswith("@")]
    return " ".join(desc_lines).strip()


def generate_c_ffi_doc() -> str:
    """Generate C FFI API markdown from all header files."""
    include_dir = REPO_ROOT / "include"
    if not include_dir.exists():
        return ""

    headers = sorted(include_dir.glob("*.h"))
    if not headers:
        return ""

    sections = [f"# C FFI API Reference: {REPO_NAME}", ""]

    for header in headers:
        functions = parse_c_header(header)
        if not functions:
            continue

        sections.append(f"## `{header.name}`")
        sections.append("")

        sections.append("| Function | Description |")
        sections.append("|----------|-------------|")
        for func in functions:
            desc = func["description"] or func["name"]
            sections.append(f"| `{func['name']}` | {desc} |")
        sections.append("")

        sections.append("---")
        sections.append("")
        for func in functions:
            sections.append(f"### `{func['name']}`")
            sections.append("")
            if func["description"]:
                sections.append(func["description"])
                sections.append("")
            sections.append("```c")
            sections.append(func["signature"] + ";")
            sections.append("```")
            sections.append("")

            if func["params_doc"]:
                sections.append("**Parameters:**")
                sections.append("")
                for pname, pdesc in func["params_doc"].items():
                    sections.append(f"- `{pname}`: {pdesc}")
                sections.append("")

            if func["return_doc"]:
                sections.append(f"**Returns:** {func['return_doc']}")
                sections.append("")

    return "\n".join(sections) + "\n"


# ---------------------------------------------------------------------------
# 3. Zig API Extractor
# ---------------------------------------------------------------------------

def parse_zig_file(path: Path) -> list[dict]:
    """Parse a .zig file and extract pub fn / pub const declarations."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    items = []
    lines = text.split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        doc_lines = []
        while stripped.startswith("///"):
            doc_lines.append(stripped[3:].strip())
            i += 1
            if i < len(lines):
                stripped = lines[i].strip()
            else:
                break

        if i >= len(lines):
            break

        line = lines[i]
        stripped = line.strip()

        fn_match = re.match(r"^pub fn (\w+)\s*\(", stripped)
        if fn_match:
            name = fn_match.group(1)
            sig_text = stripped
            while i < len(lines) and "{" not in lines[i] and "!" not in sig_text.split(")")[-1] if ")" in sig_text else True:
                i += 1
                if i < len(lines):
                    sig_text += " " + lines[i].strip()
                    if "{" in lines[i] or (")" in sig_text and i > 0):
                        break
            sig_clean = re.sub(r"\s*\{.*$", "", sig_text).strip()
            items.append({
                "kind": "fn",
                "name": name,
                "signature": sig_clean,
                "doc": " ".join(doc_lines) if doc_lines else "",
            })
            i += 1
            continue

        const_match = re.match(r"^pub const (\w+)\s*=\s*(.*)", stripped)
        if const_match:
            name = const_match.group(1)
            value_start = const_match.group(2).strip()
            kind_detail = "const"
            if value_start.startswith("enum"):
                kind_detail = "enum"
            elif value_start.startswith("struct"):
                kind_detail = "struct"
            elif value_start.startswith("union"):
                kind_detail = "union"

            items.append({
                "kind": kind_detail,
                "name": name,
                "signature": f"pub const {name}",
                "doc": " ".join(doc_lines) if doc_lines else "",
            })
            i += 1
            continue

        i += 1

    return items


def generate_zig_api_doc() -> str:
    """Generate Zig API markdown from all src/*.zig files."""
    src_dir = REPO_ROOT / "src"
    if not src_dir.exists():
        return ""

    zig_files = sorted(src_dir.glob("*.zig"))
    if not zig_files:
        return ""

    sections = [f"# Zig API Reference: {REPO_NAME}", ""]

    for zig_file in zig_files:
        items = parse_zig_file(zig_file)
        if not items:
            continue

        file_desc = _annotation_from_zig(zig_file)
        sections.append(f"## `{zig_file.name}`")
        if file_desc:
            sections.append(f"*{file_desc}*")
        sections.append("")

        fns = [it for it in items if it["kind"] == "fn"]
        types = [it for it in items if it["kind"] in ("enum", "struct", "union")]
        consts = [it for it in items if it["kind"] == "const"]

        if types:
            sections.append("### Types")
            sections.append("")
            for item in types:
                sections.append(f"#### `{item['name']}` ({item['kind']})")
                if item["doc"]:
                    sections.append(f"{item['doc']}")
                sections.append("")

        if fns:
            sections.append("### Functions")
            sections.append("")
            for item in fns:
                sections.append(f"#### `{item['name']}`")
                if item["doc"]:
                    sections.append(f"{item['doc']}")
                sections.append("")
                sections.append("```zig")
                sections.append(item["signature"])
                sections.append("```")
                sections.append("")

        if consts:
            sections.append("### Constants")
            sections.append("")
            for item in consts:
                doc_str = f" -- {item['doc']}" if item['doc'] else ""
                sections.append(f"- `{item['name']}`{doc_str}")
            sections.append("")

    return "\n".join(sections) + "\n"


# ---------------------------------------------------------------------------
# 4. LLMS.txt Generator
# ---------------------------------------------------------------------------

def generate_llms_txt() -> str:
    """Generate LLMS.txt following https://llmstxt.org/ format."""
    lines = [f"# {REPO_NAME}", ""]

    readme = REPO_ROOT / "README.md"
    if readme.exists():
        try:
            text = readme.read_text(encoding="utf-8")
            for line in text.split("\n"):
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and not stripped.startswith("["):
                    lines.append(f"> {stripped}")
                    lines.append("")
                    break
        except (OSError, UnicodeDecodeError):
            pass

    lines.append("## Source Structure")
    lines.append("")
    src_dir = REPO_ROOT / "src"
    if src_dir.exists():
        for f in sorted(src_dir.glob("*.zig")):
            ann = _annotation_from_zig(f)
            ann_str = f" - {ann}" if ann else ""
            lines.append(f"- `src/{f.name}`{ann_str}")
    include_dir = REPO_ROOT / "include"
    if include_dir.exists():
        for f in sorted(include_dir.glob("*.h")):
            ann = _annotation_from_c_header(f)
            ann_str = f" - {ann}" if ann else ""
            lines.append(f"- `include/{f.name}`{ann_str}")
    lines.append("")

    if include_dir.exists():
        headers = sorted(include_dir.glob("*.h"))
        for header in headers:
            functions = parse_c_header(header)
            if functions:
                lines.append(f"## C API ({header.name})")
                lines.append("")
                for func in functions:
                    desc = func["description"]
                    desc_str = f": {desc}" if desc else ""
                    lines.append(f"- `{func['name']}`{desc_str}")
                lines.append("")

    if src_dir.exists():
        lines.append("## Zig API")
        lines.append("")
        for zig_file in sorted(src_dir.glob("*.zig")):
            items = parse_zig_file(zig_file)
            pub_fns = [it for it in items if it["kind"] == "fn"]
            pub_types = [it for it in items if it["kind"] in ("enum", "struct", "union")]
            if pub_fns or pub_types:
                lines.append(f"### {zig_file.name}")
                for item in pub_types:
                    lines.append(f"- `{item['name']}` ({item['kind']})")
                for item in pub_fns:
                    doc_str = f": {item['doc']}" if item["doc"] else ""
                    lines.append(f"- `{item['name']}`{doc_str}")
                lines.append("")

    lines.append("## Build")
    lines.append("")
    lines.append("```")
    lines.append("zig build                    # build static library")
    lines.append("zig build test               # run unit tests")
    lines.append("zig build test-pbt           # property-based tests")
    lines.append("```")
    lines.append("")

    lines.append("## Platform Support")
    lines.append("")
    _add_platform_info(lines)

    return "\n".join(lines) + "\n"


def _add_platform_info(lines: list[str]) -> None:
    """Add platform support info based on repo content."""
    src_dir = REPO_ROOT / "src"
    has_macos = any(src_dir.glob("*_macos.zig")) if src_dir.exists() else False
    has_linux = any(src_dir.glob("*_linux.zig")) if src_dir.exists() else False

    if has_macos and has_linux:
        lines.append("- macOS (arm64, x86_64)")
        lines.append("- Linux (arm64, x86_64)")
    elif has_macos:
        lines.append("- macOS (arm64, x86_64)")
    elif has_linux:
        lines.append("- Linux (arm64, x86_64)")
    else:
        lines.append("- Cross-platform (Zig standard library only)")
    lines.append("")


# ---------------------------------------------------------------------------
# 5. AGENTS.md Generator
# ---------------------------------------------------------------------------

def generate_agents_md() -> str:
    """Generate an agent-oriented interface specification."""
    lines = [f"# AGENTS.md -- {REPO_NAME}", ""]

    lines.append("## Capabilities")
    lines.append("")
    _add_capabilities(lines)

    include_dir = REPO_ROOT / "include"
    if include_dir.exists():
        headers = sorted(include_dir.glob("*.h"))
        for header in headers:
            functions = parse_c_header(header)
            if functions:
                lines.append(f"## C FFI Exports ({header.name})")
                lines.append("")
                lines.append("| Function | Return | Description |")
                lines.append("|----------|--------|-------------|")
                for func in functions:
                    desc = func["description"] or ""
                    ret = func.get("return_type", "")
                    lines.append(f"| `{func['name']}` | `{ret}` | {desc} |")
                lines.append("")

    lines.append("## Error Conventions")
    lines.append("")
    _add_error_conventions(lines)

    lines.append("## Platform Requirements")
    lines.append("")
    _add_platform_requirements(lines)

    lines.append("## Build")
    lines.append("")
    lines.append("```bash")
    lines.append("zig build                              # static library -> zig-out/lib/")
    lines.append("zig build -Doptimize=ReleaseFast       # optimized build")
    lines.append("zig build test                         # unit tests")
    lines.append("zig build test-pbt                     # property-based tests")
    lines.append("```")
    lines.append("")

    lines.append("## Linking")
    lines.append("")
    lines.append("The library builds as a static archive. Include the header")
    lines.append(f"from `include/` and link `zig-out/lib/lib{_lib_name()}.a`.")
    lines.append("")
    _add_link_frameworks(lines)

    return "\n".join(lines) + "\n"


def _lib_name() -> str:
    """Infer library name from build.zig."""
    build_zig = REPO_ROOT / "build.zig"
    if build_zig.exists():
        try:
            text = build_zig.read_text(encoding="utf-8")
            m = re.search(r'\.name\s*=\s*"([^"]+)"', text)
            if m:
                return m.group(1)
        except (OSError, UnicodeDecodeError):
            pass
    return REPO_NAME


def _add_capabilities(lines: list[str]) -> None:
    """Add capability list based on repo analysis."""
    src_dir = REPO_ROOT / "src"
    if not src_dir.exists():
        return

    zig_files = {f.stem for f in src_dir.glob("*.zig")}

    cap_map = {
        "cbor": "CBOR encoding/decoding (CTAP2 subset)",
        "ctap2": "CTAP2 command encoding and response parsing",
        "ctaphid": "CTAPHID USB HID transport framing",
        "hid": "Platform USB HID device enumeration and I/O",
        "pin": "CTAP2 Client PIN protocol v2 (ECDH + AES + HMAC)",
    }

    for stem in sorted(zig_files):
        if stem in cap_map:
            lines.append(f"- {cap_map[stem]}")
        elif stem == "ffi":
            continue
        elif not stem.endswith("_macos") and not stem.endswith("_linux"):
            lines.append(f"- {stem}")

    lines.append("")


def _add_error_conventions(lines: list[str]) -> None:
    """Add error code conventions based on C headers."""
    include_dir = REPO_ROOT / "include"
    if not include_dir.exists():
        lines.append("- Return `0` on success")
        lines.append("- Return `-1` on failure")
        lines.append("- Functions returning data length return byte count on success, negative on error")
        lines.append("")
        return

    found_error_codes = False
    for header in sorted(include_dir.glob("*.h")):
        try:
            text = header.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        defines = re.findall(r"^#define\s+(\w+)\s+(-?\d+)[^\S\n]*(?://[^\S\n]*(.*))?$", text, re.MULTILINE)
        error_defines = [
            (name, value, comment) for name, value, comment in defines
            if int(value) < 0 or re.search(r"(_OK|_ERR|_STATUS)", name)
        ]
        if error_defines:
            found_error_codes = True
            lines.append(f"Defined in `{header.name}`:")
            lines.append("")
            lines.append("| Code | Value | Meaning |")
            lines.append("|------|-------|---------|")
            for name, value, comment in error_defines:
                comment = comment.strip() if comment else ""
                lines.append(f"| `{name}` | {value} | {comment} |")
            lines.append("")

        size_defines = [
            (name, value, comment) for name, value, comment in defines
            if int(value) >= 0 and not re.search(r"(_OK|_ERR|_STATUS)", name)
        ]
        if size_defines:
            lines.append("**Size constants:**")
            lines.append("")
            for name, value, comment in size_defines:
                comment_str = f" -- {comment.strip()}" if comment and comment.strip() else ""
                lines.append(f"- `{name}` = {value}{comment_str}")
            lines.append("")

    if not found_error_codes:
        lines.append("- Return `0` on success")
        lines.append("- Return `-1` on failure")
        lines.append("- Functions returning data length return byte count on success, negative on error")
        lines.append("")


def _add_platform_requirements(lines: list[str]) -> None:
    """Add platform-specific requirements."""
    src_dir = REPO_ROOT / "src"
    if not src_dir.exists():
        return

    has_macos = any(src_dir.glob("*_macos.zig"))
    has_linux = any(src_dir.glob("*_linux.zig"))

    if has_macos:
        lines.append("**macOS:**")
        frameworks = set()
        for f in src_dir.glob("*_macos.zig"):
            try:
                text = f.read_text(encoding="utf-8")
                if "IOKit" in text or "IOHIDManager" in text:
                    frameworks.add("IOKit")
                if "CoreFoundation" in text:
                    frameworks.add("CoreFoundation")
                if "Security" in text or "SecItem" in text:
                    frameworks.add("Security")
                if "UserNotifications" in text or "UNUserNotification" in text:
                    frameworks.add("UserNotifications")
            except (OSError, UnicodeDecodeError):
                pass
        if frameworks:
            lines.append(f"- Frameworks: {', '.join(sorted(frameworks))}")
        lines.append("- Targets: arm64, x86_64")
        lines.append("")

    if has_linux:
        lines.append("**Linux:**")
        libs = set()
        for f in src_dir.glob("*_linux.zig"):
            try:
                text = f.read_text(encoding="utf-8")
                if "hidraw" in text or "/dev/hidraw" in text:
                    libs.add("hidraw (kernel)")
                if "libsecret" in text or "secret_service" in text:
                    libs.add("libsecret-1")
                if "libnotify" in text or "notify_notification" in text:
                    libs.add("libnotify")
            except (OSError, UnicodeDecodeError):
                pass
        if libs:
            lines.append(f"- Libraries: {', '.join(sorted(libs))}")
        lines.append("- Targets: arm64, x86_64")
        lines.append("")

    if not has_macos and not has_linux:
        lines.append("- Cross-platform (Zig standard library only)")
        lines.append("- No external dependencies")
        lines.append("")


def _add_link_frameworks(lines: list[str]) -> None:
    """Add framework/library linking instructions."""
    src_dir = REPO_ROOT / "src"
    if not src_dir.exists():
        return

    has_macos = any(src_dir.glob("*_macos.zig"))
    has_linux = any(src_dir.glob("*_linux.zig"))

    if has_macos or has_linux:
        lines.append("At final link time, the consuming application must link platform frameworks/libraries.")
        lines.append("The static library intentionally does not link them to support cross-compilation.")
        lines.append("")


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------

def write_file(path: Path, content: str) -> None:
    """Write content to file, creating parent directories."""
    if not content.strip():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  wrote {path.relative_to(REPO_ROOT)}")


def main() -> None:
    print(f"Generating docs for {REPO_NAME}...")

    # 1. Source tree
    write_file(REPO_ROOT / "docs" / "source-tree.md", generate_source_tree())

    # 2. C FFI API
    c_ffi = generate_c_ffi_doc()
    if c_ffi:
        write_file(REPO_ROOT / "docs" / "api" / "c-ffi.md", c_ffi)

    # 3. Zig API
    zig_api = generate_zig_api_doc()
    if zig_api:
        write_file(REPO_ROOT / "docs" / "api" / "zig-api.md", zig_api)

    # 4. LLMS.txt
    write_file(REPO_ROOT / "LLMS.txt", generate_llms_txt())

    # 5. AGENTS.md
    write_file(REPO_ROOT / "AGENTS.md", generate_agents_md())

    print("Done.")


if __name__ == "__main__":
    main()
