<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\Preprocessor;
use RenzoFranceschini\GuardCore\Support\Text;
use RenzoFranceschini\GuardCore\Support\Unicode;

require __DIR__ . '/../vendor/autoload.php';

final class T
{
    public int $passed = 0;
    public int $failed = 0;

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === $actual) {
            $this->passed++;
            echo "ok - {$label}\n";
        } else {
            $this->failed++;
            echo "FAIL - {$label}\n";
            echo '  expected: ' . var_export($expected, true) . "\n";
            echo '  actual:   ' . var_export($actual, true) . "\n";
        }
    }

    public function truthy(mixed $actual, string $label): void
    {
        $this->same(true, (bool) $actual, $label);
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

$t = new T();

/** Build the UTF-8 byte string for a space-separated hex codepoint list. */
function nfkcCpsToBytes(string $hexCps): string
{
    $out = '';
    foreach (explode(' ', $hexCps) as $cp) {
        if ($cp !== '') {
            $out .= Text::cpBytes((int) hexdec($cp));
        }
    }

    return $out;
}

/** Run every "<input>;<expected>" hex-codepoint case in a fixture file. */
function nfkcRunHexFixture(string $path, string $section): void
{
    global $t;
    $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
    $cases = 0;
    foreach ($lines as $n => $line) {
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        $pos = strpos($line, ';');
        if ($pos === false) {
            continue;
        }
        $input = nfkcCpsToBytes(substr($line, 0, $pos));
        $expected = nfkcCpsToBytes(substr($line, $pos + 1));
        $actual = Unicode::nfkc($input);
        if ($actual === $expected) {
            $t->passed++;
            $cases++;
        } else {
            $t->failed++;
            echo 'FAIL - ' . basename($path) . ' line ' . ($n + 1) . "\n";
            echo '  input:    ' . strtoupper(bin2hex($input)) . "\n";
            echo '  expected: ' . strtoupper(bin2hex($expected)) . "\n";
            echo '  actual:   ' . strtoupper(bin2hex($actual)) . "\n";
        }
    }
    echo "ok - {$section}: {$cases} cases\n";
}

$t->section('NFKC parity: Unicode NormalizationTest (conformance corpus)');
nfkcRunHexFixture(__DIR__ . '/../tests/Nfkc/nfkc_conformance.txt', 'NormalizationTest 16.0.0 NFKC column');

$t->section('NFKC parity: seeded random corpus (seed 20260920)');
nfkcRunHexFixture(__DIR__ . '/../tests/Nfkc/nfkc_random.txt', 'exhaustive + random codepoints + random sequences');

$t->section('NFKC parity: realistic payloads');
$payloads = json_decode((string) file_get_contents(__DIR__ . '/../tests/Nfkc/nfkc_payloads.json'), true, 512, JSON_THROW_ON_ERROR);
foreach ($payloads['cases'] as $case) {
    $t->same($case[2], Unicode::nfkc($case[1]), "nfkc payload {$case[0]}");
}

/** Decode a compact hex byte string like 'e4b8ff' into raw bytes. */
function nfkcHexBytes(string $hex): string
{
    $out = '';
    foreach (str_split($hex, 2) as $byte) {
        $out .= chr((int) hexdec($byte));
    }

    return $out;
}

$t->section('Legacy lenient decode pins (invalid UTF-8, mb_* substitute semantics)');
// The pre-4.0.3 implementation iterated with mb_strlen/mb_substr and
// Text::ord, which surface each invalid UTF-8 sequence prefix as mbstring's
// substitute character ('?' with the default mbstring.substitute_character).
// Unicode::nfkc must keep mapping such inputs to the same bytes so stored
// baselines and cross-impl expectations stay stable.
$legacyPins = [
    // [input hex, expected hex] (captured from the 89e8bd5 implementation)
    ['80', '3f'],
    ['bf', '3f'],
    ['c080', '3f3f'],
    ['c1bf', '3f3f'],
    ['e08080', '3f3f3f'],
    ['e09fbf', '3f3f3f'],
    ['eda080', '3f3f3f'],
    ['edbfbf', '3f3f3f'],
    ['f08282ac', '3f3f3f3f'],
    ['f08fbfbf', '3f3f3f3f'],
    ['f4908080', '3f3f3f3f'],
    ['f5808080', '3f3f3f3f'],
    ['f888808080', '3f3f3f3f3f'],
    ['fefe', '3f3f'],
    ['ff', '3f'],
    ['e080', '3f3f'],
    ['f08080', '3f3f3f'],
    ['e4b8ff', '3f3f'],
    ['e180e180', '3f3f'],
    ['c328', '3f28'],
    ['f09f98', '3f'],
    ['f09f9880c3', 'f09f98803f'],
    ['e0a080', 'e0a080'],
    ['ed9fbf', 'ed9fbf'],
    ['f48fbfbf', 'f48fbfbf'],
    ['f0908080', 'f0908080'],
    ['c2a9', 'c2a9'],
    ['61e4b8ad8062', '61e4b8ad3f62'],
    ['808080', '3f3f3f'],
    ['e080a0', '3f3f3f'],
    ['61c3a9ff6280', '61c3a93f623f'],
];
/**
 * The lenient mb_* decoder surfaces each invalid UTF-8 sequence as
 * mbstring's substitute character, which is environment-dependent
 * (historically '?' on common mbstring builds, U+FFFD on others). The
 * implementation resolves it at runtime through mb_substr; the pins do
 * the same, so the expected bytes track the environment exactly.
 */
function nfkcSubstituteByte(): string
{
    static $sub = null;
    if ($sub === null) {
        // Mirror Unicode::substituteCp() exactly: mb_substr's lenient view
        // of an invalid byte, mapped through the same Text::ord fallback.
        $sub = mb_chr(Text::ord(mb_substr("\x80", 0, 1, 'UTF-8')), 'UTF-8');
    }

    return $sub;
}

foreach ($legacyPins as [$inHex, $wantHex]) {
    $sub = nfkcSubstituteByte();
    $want = '';
    foreach (str_split($wantHex, 2) as $byte) {
        $want .= ($byte === '3f') ? $sub : nfkcHexBytes($byte);
    }
    $t->same($want, Unicode::nfkc(nfkcHexBytes($inHex)), "legacy decode pin {$inHex}");
}

$t->section('256KB benign body preprocessing timing (bound 15s)');

/**
 * Deterministic benign body; keep in sync with the timings in the PR notes.
 */
function nfkcBuildBody(int $kb): string
{
    $para = "The quick brown fox jumps over the lazy dog. "
        . "User report #4711: na\u{ef}ve caf\u{e9} r\u{e9}sum\u{e9} submitted via the API gateway. "
        . '{"action":"update","name":"sensor/alpha-01","value":12.5,"tags":["telemetry","beta"]}'
        . " Metrics: p50=3ms p99=41ms uptime=99.98%. All systems nominal, awaiting operator input.\n";
    $out = '';
    while (strlen($out) < $kb * 1024) {
        $out .= $para;
    }

    return substr($out, 0, $kb * 1024);
}

foreach ([64, 256] as $kb) {
    $body = nfkcBuildBody($kb);
    $t0 = hrtime(true);
    $normalized = Unicode::nfkc($body);
    $nfkcSeconds = (hrtime(true) - $t0) / 1e9;
    $t->truthy($nfkcSeconds < 15.0, "Unicode::nfkc {$kb}KB under 15s (" . number_format($nfkcSeconds, 3) . "s)");

    $pre = new Preprocessor();
    $exhausted = [];
    $t0 = hrtime(true);
    [$processed, $decoded] = $pre->preprocessWithDecoded($body, $exhausted);
    $preSeconds = (hrtime(true) - $t0) / 1e9;
    $t->truthy($preSeconds < 15.0, "preprocessWithDecoded {$kb}KB under 15s (" . number_format($preSeconds, 3) . "s)");

    // Regression pins: the benign body contains no compatibility codepoints,
    // so the rewrite must produce byte-identical output to the 89e8bd5
    // implementation (hashes captured before the rewrite).
    $pins = [
        64 => ['nfkc' => 'c4a32f424107963aa8da2927baf6275aad957b0da39f3ca0029f1342cb77a13d', 'preprocess' => 'f02cb59f4255311f142996ece57b6f06118a462f4a3649ec3e856dd23586fd74'],
        256 => ['nfkc' => '6ed447da844afbbbbe7a5a35446672f9078cf07e5f02ec47d6acb0bf36027710', 'preprocess' => 'e0b7e52a1cb786cd800980453c9838f76958dd1cb6dc93fcd9baf7ec1120000c'],
    ];
    $t->same($pins[$kb]['nfkc'], hash('sha256', $normalized), "nfkc {$kb}KB output hash pinned");
    $t->same($pins[$kb]['preprocess'], hash('sha256', $processed), "preprocess {$kb}KB output hash pinned");
    $t->same([], $exhausted, "decode budget not exhausted ({$kb}KB)");
}

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);
