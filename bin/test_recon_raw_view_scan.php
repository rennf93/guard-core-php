<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;
use RenzoFranceschini\GuardCore\Support\Generated\PatternData;

require __DIR__ . '/../vendor/autoload.php';

/**
 * Honesty tests for the recon raw-view scan (port of
 * tests/test_sus_patterns/test_recon_raw_view_scan.py and the Rust engine's
 * tests/recon_raw_view_scan.rs): recon-category rows also scan the
 * signal-preserving raw view, because the configured preprocessor folds LDAP
 * hex escapes ("\de" -> "Þ") before the pattern tables run, so a probe such
 * as "\default" arrives mangled on the processed views and was previously
 * unreachable in every configured pipeline.
 *
 * The #116 leading-separator gate applies to raw-view matches unchanged (bare
 * words stay innocent outside url_path/unknown), and the raw-view merge drops
 * (pattern, match) pairs the processed views already reported so a row
 * matching both views counts once.
 *
 * Level note: the engine-level assertions run the full SusPatterns::detect()
 * pipeline (preprocessor + all views), because the whole point is that the
 * pipeline's own preprocessor mangles backslash probes on the processed
 * views and only the signal-preserving raw view still carries them.
 * Context-shape note: this engine scans each query value alone and the
 * request body as one raw value, so the Python test's JSON-leaf and
 * urlencoded-form request shapes collapse to the query_param and
 * request_body engine-level assertions plus the :embedded_json context
 * assertions below.
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
 * Separator-prefixed probes the processed views mangle or gate away: the
 * LDAP hex decoder folds "\de" into "Þ", so "\default" arrives as "Þfault"
 * and only the raw view still sees the original value.
 */
const BACKSLASH_PROBES = ['\\default', '\\report.asp', '\\README.md'];

/** Ordinary field values: the gate must keep them innocent on the raw view. */
const BARE_WORDS = ['default', 'SAP', 'actuator', 'README.md'];

function reconThreats(array $result): array
{
    return array_values(array_filter(
        $result['threats'],
        static fn (array $th): bool => ($th['category'] ?? '') === 'recon'
    ));
}

function detect(SusPatterns $sus, string $value, string $context): array
{
    return $sus->detect($value, '127.0.0.1', $context);
}

function assertReconThreat(T $t, array $result, string $desc): void
{
    $t->same(true, $result['is_threat'], "{$desc}: threat detected");
    $t->same(false, reconThreats($result) === [], "{$desc}: recon category present");
}

function assertNoThreat(T $t, array $result, string $desc): void
{
    $t->same(false, $result['is_threat'], "{$desc}: no threat");
    $t->same([], $result['threats'], "{$desc}: zero threats");
}

$t = new T();
$sus = new SusPatterns();

$t->section('raw-view recon registry is derived and non-empty');
$t->same(true, PatternData::RECON_RAW_VIEW_PATTERN_SOURCES !== [], 'derived recon raw-view registry is non-empty');
$allReconSources = array_map(
    static fn (array $row): string => $row[0],
    array_filter(PatternData::PATTERNS, static fn (array $row): bool => $row[2] === 'recon')
);
$t->same(count(array_unique($allReconSources)), count(PatternData::RECON_RAW_VIEW_PATTERN_SOURCES), 'registry holds every recon row');
foreach ($allReconSources as $source) {
    $t->same(true, in_array($source, PatternData::RECON_RAW_VIEW_PATTERN_SOURCES, true), 'recon row is a raw-view member');
}

$t->section('backslash probes detect in query_param and request_body through the pipeline');
foreach (BACKSLASH_PROBES as $probe) {
    assertReconThreat($t, detect($sus, $probe, 'query_param'), "query_param probe={$probe}");
    assertReconThreat($t, detect($sus, $probe, 'request_body'), "request_body probe={$probe}");
}

$t->section('bare words stay innocent on the raw view');
foreach (BARE_WORDS as $word) {
    assertNoThreat($t, detect($sus, $word, 'query_param'), "query_param word={$word}");
    assertNoThreat($t, detect($sus, $word, 'request_body'), "request_body word={$word}");
}

$t->section('backslash probe as the url_path value detects');
assertReconThreat($t, detect($sus, '\\default', 'url_path'), 'url_path probe=\\default');

$t->section('case folding still applies on raw-view matches');
assertReconThreat($t, detect($sus, '\\SAP', 'query_param'), 'query_param probe=\\SAP');

$t->section('embedded_json context follows the probe gate');
assertReconThreat($t, detect($sus, '\\default', 'request_body:embedded_json'), 'embedded_json probe (request_body)');
assertNoThreat($t, detect($sus, 'default', 'request_body:embedded_json'), 'embedded_json bare word (request_body)');
assertReconThreat($t, detect($sus, '\\default', 'query_param:embedded_json'), 'embedded_json probe (query_param)');
assertNoThreat($t, detect($sus, 'default', 'query_param:embedded_json'), 'embedded_json bare word (query_param)');

$t->section('row matching both views is counted once');
$result = detect($sus, '\\report.asp', 'query_param');
$recon = reconThreats($result);
$t->same(1, count($recon), '\\report.asp survives preprocessing: processed and raw sightings collapse to one');
$t->same('\\report.asp', $recon[0]['match'] ?? null, 'match text preserved');
$t->same(true, $result['is_threat'], 'verdict still a threat');

$t->section('hex-decoded separator probe still detects once');
$result = detect($sus, '\\2fdefault', 'query_param');
$recon = reconThreats($result);
$t->same(1, count($recon), '\\2fdefault decodes on the processed views: single recon hit');
$t->same('/default', $recon[0]['match'] ?? null, 'decoded match text preserved');

$t->section('slash-backslash url path stays clean on both views');
assertNoThreat($t, detect($sus, '/\\default', 'url_path'), 'url_path=/\\default');

$t->section('hex-folded run stays clean');
assertNoThreat($t, detect($sus, '\\de\\ad\\be\\ef', 'query_param'), 'query_param=\\de\\ad\\be\\ef');

$t->section('configured pipeline: SuspiciousActivityCheck blocks probe query and body values');
$config = new SecurityConfig();
$check = new SuspiciousActivityCheck(
    $config,
    new GuardResponseFactory(),
    new SusPatterns($config->detectionSemanticThreshold),
    null,
    new RouteResolver()
);
$probeRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['system' => '\\default']);
$probeRequest->state()->clientIp = '9.9.9.9';
$response = $check->check($probeRequest);
$t->same(true, $response instanceof GuardResponse, '\\default query value blocks through the pipeline');
$t->same(400, $response?->statusCode(), 'block status is 400');
$cleanRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['system' => 'default']);
$cleanRequest->state()->clientIp = '9.9.9.9';
$t->same(null, $check->check($cleanRequest), 'bare default query value passes through the pipeline');
$cleanBody = new SimpleGuardRequest(urlPath: '/items', method: 'POST', body: 'default');
$cleanBody->state()->clientIp = '9.9.9.9';
$t->same(null, $check->check($cleanBody), 'bare default body passes through the pipeline');
$probeBody = new SimpleGuardRequest(urlPath: '/items', method: 'POST', body: '\\default');
$probeBody->state()->clientIp = '9.9.9.9';
$t->same(true, $check->check($probeBody) instanceof GuardResponse, '\\default body blocks through the pipeline');

echo "\npassed={$t->passed} failed={$t->failed}\n";
exit($t->failed === 0 ? 0 : 1);
