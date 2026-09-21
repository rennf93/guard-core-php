#!/usr/bin/env python3
"""Generate PHP data tables for guard-core-php from the reference implementation.

Run from the guard-core-php repo root with the reference repo available:

    GUARD_CORE_REF=/path/to/guard-core python3 tools/gen_tables.py

Writes:
    src/Support/Generated/PatternData.php
    src/Support/Generated/UnicodeData.php
    src/Support/Generated/HtmlEntities.php

Committed outputs are normative for conformance; regenerate only when
re-pinning a new spec version.
"""

import html.entities
import json
import os
import sys
import unicodedata

REF = os.environ.get(
    "GUARD_CORE_REF", os.path.join(os.pardir, os.pardir, "guard-core")
)
REF = os.path.abspath(REF)
sys.path.insert(0, REF)

import types
import typing

sys.modules.setdefault(
    "typing_extensions",
    types.ModuleType("typing_extensions") or typing,
)
sys.modules["typing_extensions"].__dict__.update(
    {n: getattr(typing, n, object) for n in ("AsyncContextManager",)}
)

from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS  # noqa: E402
from guard_core.handlers._suspatterns_shell_sources import (  # noqa: E402
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _GLOB_WILDCARD_ATOM_RE,
    _GLUED_BACKTICK_CANDIDATE_RE,
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
    _QUOTE_SPLICE_CANDIDATE_RE,
)
from guard_core.handlers._suspatterns_regex import (  # noqa: E402
    _SCAN_WINDOW_BOUND_SOURCES,
    _CANDIDATE_REJECTION_VALIDATORS,
    DETECTION_PATTERN_WEIGHT_OVERRIDES,
)
from guard_core.handlers._suspatterns_ldap_ipv4 import (  # noqa: E402
    _LEGACY_IPV4_HOST_RE,
)
from guard_core.handlers._suspatterns_shell_sources import (  # noqa: E402
    _BRACE_EXPANSION_COMMAND_RE,
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _GLOB_WILDCARD_ATOM_RE,
    _GLUED_BACKTICK_CANDIDATE_RE,
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
    _QUOTE_SPLICE_CANDIDATE_RE,
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
)
from guard_core.handlers._suspatterns_regex import (  # noqa: E402
    _SCAN_WINDOW_BOUND_SOURCES,
    _CANDIDATE_REJECTION_VALIDATORS,
    DETECTION_PATTERN_WEIGHT_OVERRIDES,
)
from guard_core.handlers._suspatterns_sources import (  # noqa: E402
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
    _LDAP_WILDCARD_CHAIN_RE,
    _LDAP_WILDCARD_EQUALS_RE,
    _LDAP_PAREN_BREAKOUT_RE,
    _LDAP_PAREN_CONJUNCTION_RE,
    _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE,
)
from guard_core.handlers._suspatterns_matchers import (  # noqa: E402
    _SQLI_LOAD_FILE_RE,
    _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
    _FILE_UPLOAD_DANGEROUS_EXTENSION_RE,
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    _FILE_UPLOAD_TRUNCATION_RE,
    _FILE_UPLOAD_DECODED_TRUNCATION_RE,
    _TEMPLATE_CURLY_KEYWORD_RE,
    _TEMPLATE_DOLLAR_BRACE_CALL_RE,
    _TEMPLATE_CURLY_CALL_RE,
    _TEMPLATE_PERCENT_KEYWORD_RE,
    _TEMPLATE_ASP_KEYWORD_RE,
)
from guard_core.handlers._suspatterns_sources import (  # noqa: E402
    _SSTI_HASH_BRACE_SHAPE_RE,
)
from guard_core.handlers._suspatterns_views import (  # noqa: E402
    _PATH_TRAVERSAL_DECODED_SHAPE_RE,
)

OUT = os.path.join(os.path.dirname(__file__), os.pardir, "src", "Support", "Generated")
os.makedirs(OUT, exist_ok=True)


def php_str(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "$":
            out.append("\\$")
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        elif o < 0x100:
            out.append("\\x%02x" % o)
        elif o < 0x10000:
            out.append("\\u{%04x}" % o)
        else:
            out.append("\\u{%x}" % o)
    return '"' + "".join(out) + '"'


MATCHER_NAMES = {
    _SQLI_LOAD_FILE_RE: "load_file",
    _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE: "cmd_dollar",
    _FILE_UPLOAD_DANGEROUS_EXTENSION_RE: "file_upload",
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE: "file_upload",
    _FILE_UPLOAD_TRUNCATION_RE: "file_upload",
    _FILE_UPLOAD_DECODED_TRUNCATION_RE: "file_upload",
    _TEMPLATE_CURLY_KEYWORD_RE: "template_curly_keyword",
    _TEMPLATE_DOLLAR_BRACE_CALL_RE: "template_dollar",
    _TEMPLATE_CURLY_CALL_RE: "template_curly_call",
    _TEMPLATE_PERCENT_KEYWORD_RE: "template_percent",
    _TEMPLATE_ASP_KEYWORD_RE: "template_asp",
    _SSTI_HASH_BRACE_SHAPE_RE: "template_hash",
    _GLOB_WILDCARD_ATOM_RE: "glob",
}

FINDER_NAMES = {
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE: "shell_dash_c",
    _LDAP_NULL_BYTE_ATTR_RE: "ldap_null_attr_raw",
    _LDAP_NULL_BYTE_DECODED_ATTR_RE: "ldap_null_attr_decoded",
    _QUOTE_SPLICE_CANDIDATE_RE: "quote_splice",
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE: "pickle_generic",
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE: "xml_public_dtd",
}

VALIDATOR_NAMES = {
    _LEGACY_IPV4_HOST_RE: "legacy_ipv4",
    _LDAP_WILDCARD_CHAIN_RE: "ldap_wildcard_chain",
    _LDAP_WILDCARD_EQUALS_RE: "ldap_wildcard_chain",
    _LDAP_PAREN_BREAKOUT_RE: "ldap_wildcard_chain",
    _LDAP_PAREN_CONJUNCTION_RE: "ldap_paren_conjunction",
    _GLUED_BACKTICK_CANDIDATE_RE: "glued_backtick",
    _SENSITIVE_SOURCE_EXTENSION_PATH_RE: "source_extension_path",
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE: "dollar_substitution",
    _BRACE_EXPANSION_COMMAND_RE: "brace_expansion",
    _QUOTE_SPLICE_CANDIDATE_RE: "quote_splice",
    _GLOB_WILDCARD_ATOM_RE: "glob",
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE: "pickle_generic",
}

# Indices into _PATTERN_DEFINITIONS of the size-gated pattern family. These are
# the \A-anchored single-line patterns whose PCRE2 walk consumes JIT stack
# proportional to the walked line, exhausting the stack on benign single-line
# subjects (measured on php:8.3-cli, stock ini, pcre.jit=1):
#   - line-walk shapes \A(?:(?!\n).)*<target>... and the keyword-lookahead
#     double-walk variant \A(?=(?:(?!\n).)*<keyword>)\A... fail from ~24.5KB
#     subjects (PREG_JIT_STACKLIMIT_ERROR);
#   - \A-anchored path-walk segment loops \A[/\\]?(?:(?!<target>)[\w.\-~%]+[/\\])*
#     (tempered or not) fail from ~16.4KB subjects: a trailing target after
#     ~16KB of "a/" segments drives the loop to full walk depth. 2 bytes per
#     walked segment is the stack-densest input, so ~16392 bytes is the family
#     floor cliff.
# Anchored siblings 41, 108, 118 and 129 were verified not to exhaust even at
# the 262144-byte view cap with trailing targets and are not gated.
# Under pcre.jit=0 the same shapes fail from ~100KB (PREG_RECURSION_LIMIT_ERROR).
# The PHP runtime skips these preg calls once the view subject's first line
# reaches SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES (threshold below the
# ~16.4KB segment-loop cliff), which makes the mitigation ini-independent.
# Verified below against the expected shape so a future table re-pin cannot
# silently re-point the indices.
SIZE_GATED_PATTERN_INDICES = [
    # line-walk family, ~24.5KB cliff
    32, 33, 34, 35, 36, 102, 107, 110, 112, 115,
    # \A-anchored path-walk segment loops, ~16.4KB cliff with trailing targets
    101, 103, 104, 105, 106, 109, 111, 113, 114, 116, 117, 119, 121,
    122, 123, 124, 125, 126, 128, 130, 131, 132, 133, 134, 135, 136,
]
SIZE_GATED_CATEGORIES = {"dir_traversal", "sensitive_file", "cms_probing", "recon"}


def _verify_size_gated_indices() -> None:
    line_walk_prefixes = (
        "\\A(?:(?!\\n).)*",
        "\\A(?=(?:(?!\\n).)*",
    )
    for i in SIZE_GATED_PATTERN_INDICES:
        src, _contexts, category = _PATTERN_DEFINITIONS[i]
        assert category in SIZE_GATED_CATEGORIES, (
            f"size-gated pattern {i}: unexpected category {category!r}"
        )
        is_line_walk = src.startswith(line_walk_prefixes)
        is_segment_loop = src.startswith("\\A[/")
        assert is_line_walk or is_segment_loop, (
            f"size-gated pattern {i}: unexpected shape {src[:80]!r}"
        )


def gen_patterns() -> None:
    _verify_size_gated_indices()
    lines = ["<?php", "", "declare(strict_types=1);", "", "namespace RenzoFranceschini\\GuardCore\\Support\\Generated;", "", "final class PatternData", "{", "    public const PATTERNS = ["]
    for pattern, contexts, category in _PATTERN_DEFINITIONS:
        ctx = ", ".join(php_str(c) for c in sorted(contexts))
        lines.append(f"        [{php_str(pattern)}, [{ctx}], {php_str(category)}],")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const SIZE_GATED_PATTERN_INDICES = [")
    for i in SIZE_GATED_PATTERN_INDICES:
        lines.append(f"        {i},")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const RAW_VIEW_SOURCES = [")
    for s in sorted(DETECTION_RAW_VIEW_PATTERN_SOURCES):
        lines.append(f"        {php_str(s)},")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const URL_DECODED_VIEW_SOURCES = [")
    for s in sorted(DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES):
        lines.append(f"        {php_str(s)},")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const SCAN_WINDOW_BOUNDS = [")
    for source, pairs in _SCAN_WINDOW_BOUND_SOURCES.items():
        rendered = ", ".join(f"[{php_str(p)}, {php_str(t)}]" for p, t in pairs)
        lines.append(f"        {php_str(source)} => [{rendered}],")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const MATCHER_KINDS = [")
    for source, name in MATCHER_NAMES.items():
        lines.append(f"        {php_str(source)} => {php_str(name)},")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const FINDER_KINDS = [")
    for source, name in FINDER_NAMES.items():
        lines.append(f"        {php_str(source)} => {php_str(name)},")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const VALIDATOR_KINDS = [")
    for source, name in VALIDATOR_NAMES.items():
        lines.append(f"        {php_str(source)} => {php_str(name)},")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const WEIGHT_OVERRIDES = [")
    for source, weight in DETECTION_PATTERN_WEIGHT_OVERRIDES.items():
        lines.append(f"        {php_str(source)} => {weight},")
    lines.append("    ];")
    lines.append("")
    lines.append(f"    public const DECODED_PATH_TRAVERSAL_RE = {php_str(_PATH_TRAVERSAL_DECODED_SHAPE_RE.pattern)};")
    lines.append("}")
    with open(os.path.join(OUT, "PatternData.php"), "w") as f:
        f.write("\n".join(lines) + "\n")


def gen_unicode() -> None:
    """Emit the normalization tables consumed by Support\\Unicode.

    NFKC_DECOMP holds the *full* compatibility decomposition (NFKD) of every
    codepoint whose NFKD differs from itself, so the runtime only needs one
    table lookup per codepoint before canonical reordering and composition.
    Hangul syllables (U+AC00..U+D7A3) are excluded because their decomposition
    (and recomposition) is algorithmic.

    COMP is the canonical composition pair table, keyed starter -> combining
    character -> composite.  Pairs are derived the same way the previous
    canonical-only generator did: take every two-way canonical decomposition
    and keep it only when NFC of the decomposition round-trips back to the
    original codepoint, which filters the composition exclusions implicitly.

    WORK_RE covers every codepoint that can change an NFKC result: anything
    with a decomposition, anything with a non-zero canonical combining class,
    every second element of a composition pair, and the conjoining Hangul
    V/T jamo (algorithmic composition seconds).  If a UTF-8 string matches
    none of them it is already in NFKC form and the runtime can return it
    byte-for-byte; the character class is emitted as merged ranges so the
    runtime check is a single PCRE scan.

    Generated with the CPython that carries the pinned UCD version:
    Python 3.14.1 / unicodedata 16.0.0.
    """
    nfkc_decomp: dict[int, list[int]] = {}
    cclass: dict[int, int] = {}
    comp: dict[int, dict[int, int]] = {}
    work: set[int] = set()
    last = 0x110000
    for cp in range(last):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        ch = chr(cp)
        k = unicodedata.combining(ch)
        if k:
            cclass[cp] = k
            work.add(cp)
        if 0xAC00 <= cp <= 0xD7A3:
            continue
        nfkd = unicodedata.normalize("NFKD", ch)
        if nfkd != ch:
            nfkc_decomp[cp] = [ord(c) for c in nfkd]
            work.add(cp)
        d = unicodedata.decomposition(ch)
        if d and not d.startswith("<"):
            parts = d.split()
            # Canonical two-way decomposition: the pair composes back to ch
            # unless it is a composition exclusion, which the NFC round-trip
            # on the pair itself filters out. (Checking NFC of the recursive
            # NFD form instead would drop every two-level decomposition such
            # as U+1E14, whose NFD is E, U+0304, U+0300.)
            if len(parts) == 2:
                a, b = (int(p, 16) for p in parts)
                if unicodedata.normalize("NFC", chr(a) + chr(b)) == ch:
                    comp.setdefault(a, {})[b] = cp
                    work.add(b)
    # Conjoining Hangul V (U+1160..U+11A7) and T (U+11A8..U+11FF) jamo can be
    # absorbed by the algorithmic composition step.
    work.update(range(0x1160, 0x1200))

    def cclass_ranges() -> list[tuple[int, int, int]]:
        keys = sorted(cclass)
        ranges = []
        start = prev = keys[0]
        val = cclass[start]
        for k in keys[1:]:
            if k == prev + 1 and cclass[k] == val:
                prev = k
                continue
            ranges.append((start, prev, val))
            start = prev = k
            val = cclass[k]
        ranges.append((start, prev, val))
        return ranges

    def work_ranges() -> list[tuple[int, int]]:
        keys = sorted(work)
        ranges = []
        start = prev = keys[0]
        for k in keys[1:]:
            if k == prev + 1:
                prev = k
                continue
            ranges.append((start, prev))
            start = prev = k
        ranges.append((start, prev))
        return ranges

    pattern_body = "".join(
        f"\\x{{{a:x}}}" if a == b else f"\\x{{{a:x}}}-\\x{{{b:x}}}"
        for a, b in work_ranges()
    )

    lines = [
        "<?php",
        "",
        "declare(strict_types=1);",
        "",
        "namespace RenzoFranceschini\\GuardCore\\Support\\Generated;",
        "",
        "final class UnicodeData",
        "{",
        "    public const NFKC_DECOMP = [",
    ]
    for cp in sorted(nfkc_decomp):
        seq = ", ".join("0x%x" % c for c in nfkc_decomp[cp])
        lines.append(f"        0x{cp:x} => [{seq}],")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const CCC = [")
    for a, b, v in cclass_ranges():
        lines.append(f"        [0x{a:x}, 0x{b:x}, {v}],")
    lines.append("    ];")
    lines.append("")
    lines.append("    public const COMP = [")
    for a in sorted(comp):
        pairs = ", ".join(f"0x{b:x} => 0x{comp[a][b]:x}" for b in sorted(comp[a]))
        lines.append(f"        0x{a:x} => [{pairs}],")
    lines.append("    ];")
    lines.append("")
    lines.append(f"    public const WORK_RE = '/[{pattern_body}]/u';")
    lines.append("}")
    with open(os.path.join(OUT, "UnicodeData.php"), "w") as f:
        f.write("\n".join(lines) + "\n")


def gen_html() -> None:
    lines = ["<?php", "", "declare(strict_types=1);", "", "namespace RenzoFranceschini\\GuardCore\\Support\\Generated;", "", "final class HtmlEntities", "{", "    public const HTML5 = ["]
    for name in sorted(html.entities.html5):
        lines.append(f"        {php_str(name)} => {php_str(html.entities.html5[name])},")
    lines.append("    ];")
    lines.append("}")
    with open(os.path.join(OUT, "HtmlEntities.php"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    gen_patterns()
    gen_unicode()
    gen_html()
    print("generated:", sorted(os.listdir(OUT)))
