<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Support\Generated\PatternData;

require __DIR__ . '/../vendor/autoload.php';

/**
 * Honesty tests for the recon leading-separator gate (port of
 * tests/test_sus_patterns/test_recon_bare_word_context.py, upstream commit
 * 79818055): whole-value recon rows whose leading path separator is optional
 * must not match bare field values ("default", "SAP", "README.md", ...) in
 * query_param and request_body contexts, while probe paths ("/default.asp",
 * "\default") stay recon threats and url_path/unknown behavior is unchanged.
 *
 * Context-shape note: this engine scans each query value alone and the request
 * body as one raw value, so the Python test's JSON-leaf request shapes
 * collapse to the embedded_json context-level assertions below; the gate is
 * keyed on the normalized context of the value actually being scanned, like
 * the Python gate in _build_regex_threat.
 */

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

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

/**
 * Ordinary field values that the whole-value recon rows match when the
 * leading "/" is optional: product names, enum values, file names.
 */
const BARE_WORDS = [
    'default',
    'SAP',
    'ise',
    'language',
    'autodiscover',
    'confluence',
    'actuator',
    'cgi-bin',
    'lms/db',
    'README.md',
    'CHANGELOG',
    'Makefile',
    'credentials.json',
    'report.asp',
];

const PROBE_PATHS = [
    '/default.asp',
    '/sap',
    '\\README.md',
    '/actuator/health',
    '/cgi-bin/test.cgi',
    '/README.md',
];

/**
 * Pre-existing divergence, pinned to keep it visible: "\default" does not
 * detect on master either. The processed view decodes the "\de" byte-run of
 * "\default" into a single Latin-1 character before the recon rows scan, and
 * recon rows are excluded from the raw view, so the match never forms. The
 * Python engine detects this probe; fixing the escape pass would move
 * detection verdicts and belongs with the corpus regen follow-up, not with
 * this gate.
 */
const KNOWN_DIVERGENCE_PROBES = [
    '\\default',
];

function detect(SusPatterns $sus, string $value, string $context): array
{
    return $sus->detect($value, '127.0.0.1', $context);
}

function assertNoThreat(T $t, array $result, string $desc): void
{
    $t->same(false, $result['is_threat'], "{$desc}: no threat");
    $t->same([], $result['threats'], "{$desc}: zero threats");
}

function assertReconThreat(T $t, array $result, string $desc): void
{
    $t->same(true, $result['is_threat'], "{$desc}: threat detected");
    $recon = array_filter($result['threats'], static fn (array $th): bool => ($th['category'] ?? '') === 'recon');
    $t->same(false, $recon === [], "{$desc}: recon category present");
}

$t = new T();
$sus = new SusPatterns();

$t->section('gate registry is derived and non-empty');
$t->same(true, PatternData::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES !== [], 'derived recon optional-separator registry is non-empty');
$t->same(true, count(PatternData::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES) < count(array_filter(
    PatternData::PATTERNS,
    static fn (array $row): bool => $row[2] === 'recon'
)), 'registry excludes recon rows without the optional-separator anchor');
foreach (PatternData::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES as $source) {
    $t->same(true, str_starts_with($source, '\\A[/\\\\]?'), 'source starts with the optional-separator anchor: ' . $source);
}

$t->section('bare query_param values are not recon probes');
foreach (BARE_WORDS as $value) {
    assertNoThreat($t, detect($sus, $value, 'query_param'), "query_param value={$value}");
}

$t->section('bare request_body values are not recon probes');
foreach (BARE_WORDS as $value) {
    assertNoThreat($t, detect($sus, $value, 'request_body'), "request_body value={$value}");
}

$t->section('probe paths as query_param or request_body values are still recon');
foreach (PROBE_PATHS as $probe) {
    foreach (['query_param', 'request_body'] as $context) {
        assertReconThreat($t, detect($sus, $probe, $context), "{$context} value={$probe}");
    }
}

$t->section('url_path context unchanged: probes and bare words both detect');
foreach (PROBE_PATHS as $probe) {
    assertReconThreat($t, detect($sus, $probe, 'url_path'), "url_path probe={$probe}");
}
foreach (KNOWN_DIVERGENCE_PROBES as $probe) {
    $t->same(false, detect($sus, $probe, 'url_path')['is_threat'], "url_path known-divergence probe={$probe} stays undetected (pre-existing)");
}
foreach (['/default', '/sap', '/README.md'] as $path) {
    assertReconThreat($t, detect($sus, $path, 'url_path'), "url_path path={$path}");
}

$t->section('embedded_json context follows the Python leaf rules');
assertNoThreat($t, detect($sus, 'SAP', 'request_body:embedded_json'), 'embedded_json bare word');
assertNoThreat($t, detect($sus, 'README.md', 'request_body:embedded_json'), 'embedded_json bare file name');
assertReconThreat($t, detect($sus, '/default.asp', 'request_body:embedded_json'), 'embedded_json probe path');

$t->section('unchanged contexts: unknown stays path-like, header keeps the context filter');
assertReconThreat($t, detect($sus, 'SAP', 'unknown'), 'unknown bare word still detects');
assertNoThreat($t, detect($sus, 'SAP', 'header'), 'header bare word not scanned by recon rows');

$t->section('real probes still detected');
$etcPasswd = detect($sus, '/etc/passwd', 'url_path');
$t->same(true, $etcPasswd['is_threat'], 'sensitive file probe still detected');
$attack = detect($sus, "'; DROP TABLE users;--", 'query_param');
$t->same(true, $attack['is_threat'], 'sqli probe still detected');

echo "\npassed={$t->passed} failed={$t->failed}\n";
exit($t->failed === 0 ? 0 : 1);
