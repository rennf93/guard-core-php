#!/usr/bin/env python3
"""Generate NFKC parity fixtures for bin/test_nfkc.php.

Outputs (all committed):
    tests/Nfkc/nfkc_conformance.txt  - NFKC columns of the Unicode
                                       NormalizationTest.txt (16.0.0)
    tests/Nfkc/nfkc_random.txt       - exhaustive "interesting" codepoints plus
                                       seeded random codepoints and sequences
    tests/Nfkc/nfkc_payloads.json    - realistic payload fixtures

Fixture text format: one case per line, "<input>;<expected>" where both sides
are space-separated hex codepoints. Lines starting with '#' are comments.

Regenerate from the repo root with the pinned interpreter (the same one that
generated src/Support/Generated/UnicodeData.php):

    python3.14 tools/gen_nfkc_fixtures.py [path-to-NormalizationTest.txt]

Without a path argument the script downloads NormalizationTest.txt for
unicodedata.unidata_version from unicode.org into a temporary directory.

Determinism: the only entropy source is random.Random(20260920), seeded
explicitly, so regenerating with the same interpreter version reproduces the
fixtures byte-for-byte. Parity target: unicodedata.normalize("NFKC", ...) of
that same interpreter (3.14.x => Unicode 16.0.0).
"""

import json
import random
import sys
import tempfile
import unicodedata
import urllib.request
from pathlib import Path

SEED = 20260920
RANDOM_CPS = 100_000
RANDOM_SEQUENCES = 4_000

NORMALIZATION_TEST_URL = (
    "https://www.unicode.org/Public/{v}/ucd/NormalizationTest.txt"
)

OUT = Path(__file__).resolve().parent.parent / "tests" / "Nfkc"


def is_surrogate(cp: int) -> bool:
    return 0xD800 <= cp <= 0xDFFF


def cps_hex(s: str) -> str:
    return " ".join(f"{ord(c):x}" for c in s)


def case_line(source: str, expected: str) -> str:
    return f"{cps_hex(source)};{cps_hex(expected)}"


def write_lines(path: Path, header: list[str], lines: list[str]) -> None:
    with open(path, "w") as f:
        f.write("\n".join(header + lines) + "\n")
    print(f"wrote {path} ({len(lines)} cases)")


def gen_conformance(test_file: Path) -> None:
    lines = []
    skipped = 0
    for raw in test_file.read_text(encoding="utf-8").splitlines():
        line = raw.split("#")[0].strip()
        if not line or line.startswith("@"):
            continue
        fields = line.split(";")
        source = "".join(chr(int(cp, 16)) for cp in fields[0].split())
        nfkc = "".join(chr(int(cp, 16)) for cp in fields[3].split())
        if any(is_surrogate(ord(c)) for c in source + nfkc):
            # Lone surrogates have no UTF-8 byte form and cannot cross the
            # PHP byte boundary; the runtime maps such bytes to the mbstring
            # substitute character instead (pinned separately in the runner).
            skipped += 1
            continue
        lines.append(case_line(source, nfkc))
    header = [
        "# NFKC parity: Unicode NormalizationTest.txt (Unicode "
        f"{unicodedata.unidata_version}), NFKC column.",
        f"# Source: {NORMALIZATION_TEST_URL.format(v=unicodedata.unidata_version)}",
        f"# Cases: {len(lines)}; skipped {skipped} containing lone surrogates",
        "# (no UTF-8 byte form). Format: '<input cps>;<expected cps>' in hex.",
    ]
    write_lines(OUT / "nfkc_conformance.txt", header, lines)


def interesting_codepoints() -> list[int]:
    cps: set[int] = set()
    for cp in range(0x110000):
        if is_surrogate(cp):
            continue
        ch = chr(cp)
        if unicodedata.normalize("NFKD", ch) != ch:
            cps.add(cp)
        if unicodedata.combining(ch):
            cps.add(cp)
    cps.update(range(0x1100, 0x1200))  # all conjoining jamo
    return sorted(cps)


def gen_random() -> None:
    rng = random.Random(SEED)
    exhaustive = interesting_codepoints()
    lines = [case_line(chr(cp), unicodedata.normalize("NFKC", chr(cp))) for cp in exhaustive]

    random_header = [
        f"# section: random codepoints, seed={SEED}, count={RANDOM_CPS}, "
        "uniform over U+0000..U+10FFFF excluding surrogates",
    ]
    max_cp = 0x110000
    for _ in range(RANDOM_CPS):
        cp = rng.randrange(max_cp)
        while is_surrogate(cp):
            cp = rng.randrange(max_cp)
        lines.append(case_line(chr(cp), unicodedata.normalize("NFKC", chr(cp))))

    seq_header = [
        f"# section: random sequences, seed={SEED} (same rng instance, "
        f"continues after the codepoints section), count={RANDOM_SEQUENCES}, "
        "length 2..10, alphabet: exhaustive pool plus uniform random cps",
    ]
    pool = exhaustive + [rng.randrange(max_cp) for _ in range(2000)]
    for _ in range(RANDOM_SEQUENCES):
        n = rng.randint(2, 10)
        seq = []
        while len(seq) < n:
            cp = rng.choice(pool)
            if not is_surrogate(cp):
                seq.append(cp)
        source = "".join(chr(cp) for cp in seq)
        lines.append(case_line(source, unicodedata.normalize("NFKC", source)))

    header = [
        "# NFKC parity: seeded random corpus.",
        f"# Generator: tools/gen_nfkc_fixtures.py, python {sys.version.split()[0]},"
        f" unicodedata {unicodedata.unidata_version}.",
        f"# section: exhaustive ({len(exhaustive)} codepoints): every cp with a"
        " compatibility/canonical decomposition, every combining mark, every"
        " Hangul conjoining jamo, normalized individually.",
        *random_header,
        *seq_header,
    ]
    write_lines(OUT / "nfkc_random.txt", header, lines)


def gen_payloads() -> None:
    payloads = [
        "na\u00efve caf\u00e9 r\u00e9sum\u00e9 \u2014 \u0438\u0442\u043e\u0433",
        "ＳＥＬＥＣＴ ＊ ＦＲＯＭ ｕｓｅｒｓ ＷＨＥＲＥ ｎａｍｅ＝＇ａｄｍｉｎ＇",
        "\uff34\uff49\uff54\uff4c\uff45 \uff21\uff50\uff49",
        "\uFB01lter://\uFB02ower.shop/\uFB03?x=\uFB04",
        "\u212B ngstr\u00F6m \u2126 ohm \u212A Kelvin",
        "\u2460\u2465\u2469 \u2163 \u00BD \u00B2 \u339C \u33A0 \u3314\u30E6\u30FC\u30B6\u30FC",
        "\uFDFA basmala",
        "\U0001D446\U0001D450\U0001D452\U0001D451\U0001D462\U0001D451\U0001D456\U0001D453 \U0001D437\U0001D442\U0001D446",
        "e\u0301gal \u00E9gal \u0301 combining-first A\u030A\u0328",
        "\uAC00\u11A8\uAC01 \uD55C\uAD6D\uC5B4 \u1112\u1161\u11AB\u1103\u1161\u11BC\u110B\u1161\u11C2",
        "\u30D5\u30A9\u30EB\u30C0 \uFF8C\uFF9E\uFF70\uFF99\uFF84\uFF9E",
        "width\u3000full space\u00A0nbsp\u200Bzwsp\u200Dzwj\uFEFFbom\u00ADshy",
        "\U0001F469\u200D\U0001F4BB emoji-zwj \U0001F680\U0001F44D",
        "<scr\u0130pt>alert(1)</scr\u0130pt>",
        "\uFF1C\uFF53\uFF43\uFF52\uFF49\uFF50\uFF54\uFF3E\uFF1E\uFF06\uFF4F\uFF4E",
        "\u2014 \u2013 \u2215 \u2216 \u2044 \u29F8 \uFF0F \u01C0 \u037E",
        "SELECT \u25CB FROM t\u2081 WHERE x \u2260 \u0037\u0662",
        "\u09AC\u09BE\u0982\u09B2\u09BE \u0C15\u0C4B\u0C1F\u0C4A\u0C32\u0C41 \u0D15\u0D4B\u0D1F\u0D4D\u0D1F\u0D4D",
        "\u0F56\u0F7C\u0F51\u0F0B\u0F40\u0F66\u0F60\u0F72\u0F0D",
        "\u2028\u2029 line separators \u001C\u001D\u001E\u001F group separators",
        "\u0000\u0001\u0002\u007F\u0080\u009F controls",
        "\U0001D400\U0001D7D8\U0001D7E1 plane1 math \U00020000 plane2 CJK-B \U0001F977",
        "\u2FFC\u2FFD\u2FFE\u2FFF ideographic description",
        "\u10FFFF \u10FFFE \u07FF \u0870 last-first-sentinel",
    ]
    cases = [[f"payload_{i:02d}", p, unicodedata.normalize("NFKC", p)] for i, p in enumerate(payloads)]
    meta = {
        "description": "NFKC parity: realistic payloads (deterministic list, no RNG).",
        "generator": "tools/gen_nfkc_fixtures.py",
        "python": sys.version.split()[0],
        "unicodedata": unicodedata.unidata_version,
        "cases": cases,
    }
    path = OUT / "nfkc_payloads.json"
    with open(path, "w") as f:
        json.dump(meta, f, ensure_ascii=True, indent=1)
        f.write("\n")
    print(f"wrote {path} ({len(cases)} cases)")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    if len(sys.argv) > 1:
        test_file = Path(sys.argv[1])
    else:
        url = NORMALIZATION_TEST_URL.format(v=unicodedata.unidata_version)
        print(f"downloading {url}")
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp.write(urllib.request.urlopen(url, timeout=60).read())
            test_file = Path(tmp.name)
    print(
        f"generator: python {sys.version.split()[0]},"
        f" unicodedata {unicodedata.unidata_version}"
    )
    gen_conformance(test_file)
    gen_random()
    gen_payloads()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
