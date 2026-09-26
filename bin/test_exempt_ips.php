<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Cloud\InMemoryCloudIpStore;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

require __DIR__ . '/../vendor/autoload.php';

// Acceptance checklist port for the exempt_ips feature (spec
// specs/exempt-ips.md sections 2-4 and 7; reference implementation
// guard-core PR #118, tests/test_core/test_exempt_ips.py). Runs fully
// in-memory (enable_redis false, seeded cloud ranges): no Redis, no
// network. Checklist item 7 (per-route require_ip/block_ip) is not
// applicable at engine level and is documented inline below.

const EXEMPT_IP = '198.51.100.7';
const CIDR_SIBLING_IP = '198.51.100.9';
const OTHER_IP = '203.0.113.9';

final class T
{
    public int $passed = 0;

    public int $failed = 0;

    private string $section = '';

    public function section(string $name): void
    {
        $this->section = $name;
        echo "=== {$name} ===\n";
    }

    public function ok(bool $condition, string $label): void
    {
        if ($condition) {
            $this->passed++;
            echo "  PASS {$label}\n";
        } else {
            $this->failed++;
            echo "  FAIL {$this->section} :: {$label}\n";
        }
    }

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        $ok = $expected === $actual;
        if (!$ok) {
            echo '    expected: ' . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
        }
        $this->ok($ok, $label);
    }

    public function throws(callable $fn, string $class, ?string $contains, string $label): void
    {
        try {
            $fn();
            $this->ok(false, "{$label} (no exception)");
        } catch (\Throwable $e) {
            $ok = $e instanceof $class && ($contains === null || str_contains($e->getMessage(), $contains));
            if (!$ok) {
                echo '    got: ' . get_class($e) . ': ' . $e->getMessage() . "\n";
            }
            $this->ok($ok, $label);
        }
    }

    public function done(string $name): int
    {
        echo "\n{$name}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed;
    }
}

$t = new T();

/** @param array<string, mixed> $configArgs */
function makeEngine(...$configArgs): GuardEngine
{
    $cloud = ($configArgs['seedCloud'] ?? false)
        ? new CloudManager(null, new InMemoryCloudIpStore())
        : null;
    unset($configArgs['seedCloud']);
    $configArgs['enableRedis'] = $configArgs['enableRedis'] ?? false;
    $engine = new GuardEngine(new SecurityConfig(...$configArgs), cloudManager: $cloud);
    if ($cloud !== null) {
        // Keep the cloud_ip_refresh gate closed for the whole run: no
        // network fetch, the seeded /24 below is the only range known.
        $cloud->lastCloudIpRefresh = time();
        $cloud->ipRanges['AWS']['198.51.100.0/24'] = true;
    }

    return $engine;
}

function fire(GuardEngine $engine, string $ip, array $queryParams = [], array $headers = []): ?GuardResponse
{
    $request = new SimpleGuardRequest(urlPath: '/', clientHost: $ip, headers: $headers, queryParams: $queryParams);
    $response = $engine->execute($request);

    return $response;
}

$t->section('config: exempt_ips defaults, validation, immutability');
$t->same([], (new SecurityConfig())->exemptIps, 'exempt_ips defaults to empty (fail-open surface is none)');
$t->same(['198.51.100.7', '198.51.100.0/28'], (new SecurityConfig(exemptIps: ['198.51.100.7', '198.51.100.0/28']))->exemptIps, 'entries kept, CIDR canonical');
$t->same(['198.51.100.7'], (new SecurityConfig(exemptIps: ['::ffff:198.51.100.7']))->exemptIps, 'IPv4-mapped entry canonicalized like the whitelist');
$t->throws(static fn (): SecurityConfig => new SecurityConfig(exemptIps: ['not-an-ip']), InvalidArgumentException::class, 'exempt_ips', 'checklist 9: invalid entry fails closed at construction');
$t->throws(static fn (): SecurityConfig => new SecurityConfig(exemptIps: ['198.51.100.0/33']), InvalidArgumentException::class, 'exempt_ips', 'checklist 9: out-of-range CIDR prefix fails closed');
$t->throws(static fn (): SecurityConfig => new SecurityConfig(exemptIps: [123]), InvalidArgumentException::class, 'exempt_ips', 'checklist 9: non-string entry fails closed');
$base = new SecurityConfig(enableRedis: false);
$copy = $base->with(['exempt_ips' => ['10.0.0.1']]);
$t->same(['10.0.0.1'], $copy->exemptIps, 'with() sets exempt_ips on the copy');
$t->same([], $base->exemptIps, 'with() leaves the original untouched');
$t->same($base->revision() + 1, $copy->revision(), 'with() bumps the revision like sibling fields');

$t->section('checklist 1: exempt exact IP exceeds the rate limit');
$engine = makeEngine(rateLimit: 3, rateLimitWindow: 60, exemptIps: [EXEMPT_IP]);
$response = null;
foreach ([1, 2, 3, 4, 5] as $hit) {
    $response = fire($engine, EXEMPT_IP);
    $t->same(null, $response, "exempt exact IP hit {$hit} past the limit still passes");
}

$t->section('checklist 2: exempt CIDR exceeds the rate limit');
$engine = makeEngine(rateLimit: 3, rateLimitWindow: 60, exemptIps: ['198.51.100.0/28']);
foreach ([1, 2, 3, 4, 5] as $hit) {
    $response = fire($engine, CIDR_SIBLING_IP);
    $t->same(null, $response, "exempt CIDR member hit {$hit} past the limit still passes");
}

$t->section('exempt match sets the skip flag without whitelisting (reference flag pins)');
$request = new SimpleGuardRequest(urlPath: '/', clientHost: EXEMPT_IP);
$engine->execute($request);
$t->same(true, $request->state()->isExempt, 'CIDR member sets is_exempt');
$t->same(false, $request->state()->isWhitelisted, 'exempt match does not set is_whitelisted');
$request = new SimpleGuardRequest(urlPath: '/', clientHost: OTHER_IP);
$engine->execute($request);
$t->same(false, $request->state()->isExempt, 'non-member does not set is_exempt');

$t->section('checklist 3: a non-exempt client is still throttled');
$engine = makeEngine(rateLimit: 3, rateLimitWindow: 60, exemptIps: [EXEMPT_IP]);
$t->same(null, fire($engine, OTHER_IP), 'non-exempt hit 1 allowed');
$t->same(null, fire($engine, OTHER_IP), 'non-exempt hit 2 allowed');
$t->same(null, fire($engine, OTHER_IP), 'non-exempt hit 3 allowed');
$response = fire($engine, OTHER_IP);
$t->same(429, $response?->statusCode(), 'non-exempt hit 4 gets 429 at the limit');

$t->section('checklist 4: empty whitelist leaks no deny path');
$engine = makeEngine(rateLimit: 100, exemptIps: [EXEMPT_IP]);
$t->same(null, fire($engine, EXEMPT_IP), 'exempt IP passes');
$t->same(null, fire($engine, OTHER_IP), 'unlisted IP passes as before (no deny-path leak)');
$t->same(null, fire($engine, '192.0.2.77'), 'any other IP passes as before');

$t->section('checklist 4b: the whitelist deny path is unchanged');
$engine = makeEngine(rateLimit: 100, whitelist: [OTHER_IP], exemptIps: [EXEMPT_IP]);
$t->same(403, fire($engine, EXEMPT_IP)?->statusCode(), 'exempt IP does not pass a restrictive whitelist');
$request = new SimpleGuardRequest(urlPath: '/', clientHost: OTHER_IP);
$engine->execute($request);
$t->same(true, $request->state()->isWhitelisted, 'whitelisted IP still sets is_whitelisted');
$engine = makeEngine(rateLimit: 100, whitelist: [EXEMPT_IP], exemptIps: [EXEMPT_IP]);
$request = new SimpleGuardRequest(urlPath: '/', clientHost: EXEMPT_IP);
$engine->execute($request);
$t->same(true, $request->state()->isWhitelisted, 'IP in both lists is simply a whitelist match');

$t->section('checklist 5: an exempt IP on the blacklist is still denied');
$engine = makeEngine(rateLimit: 100, exemptIps: [EXEMPT_IP], blacklist: [EXEMPT_IP]);
$t->same(403, fire($engine, EXEMPT_IP)?->statusCode(), 'blacklist wins over exemption');
$request = new SimpleGuardRequest(urlPath: '/', clientHost: EXEMPT_IP);
$engine->execute($request);
$t->same(false, $request->state()->isExempt, 'no exempt flag past the deny');

$t->section('checklist 6: an exempt IP with an active ban is still denied');
$engine = makeEngine(rateLimit: 100, exemptIps: [EXEMPT_IP]);
$engine->banManager()->ban(EXEMPT_IP, 3600, 'test-ban');
$t->same(403, fire($engine, EXEMPT_IP)?->statusCode(), 'dynamic ban wins over exemption');

$t->section('checklist 7: per-route IP rules (engine-level note)');
echo "  NOTE: per-route require_ip/block_ip decorators do not exist in the\n";
echo "  PHP engine surface (RouteConfig carries bypassedChecks and decorator\n";
echo "  options only), so spec checklist item 7 is not applicable at engine\n";
echo "  level; the adapter repos own the decorator mapping. The engine-level\n";
echo "  analog that DOES exist is pinned below: a route that bypasses the\n";
echo "  global IP stage leaves the skip flags unset, so exemption does not\n";
echo "  leak into it and rate limiting still applies there.\n";
$engine = makeEngine(rateLimit: 1, rateLimitWindow: 60, exemptIps: [EXEMPT_IP]);
$request = new SimpleGuardRequest(urlPath: '/bypassed', clientHost: EXEMPT_IP);
$request->state()->routeConfig = new RouteConfig(bypassedChecks: ['ip']);
$t->same(null, $engine->execute($request), 'ip-bypassed route: exempt IP hit 1 allowed (flags short-circuit)');
$request = new SimpleGuardRequest(urlPath: '/bypassed', clientHost: EXEMPT_IP);
$request->state()->routeConfig = new RouteConfig(bypassedChecks: ['ip']);
$response = $engine->execute($request);
$t->same(429, $response?->statusCode(), 'ip-bypassed route: exemption does not leak in, rate limit still applies');
$t->same(false, $request->state()->isExempt, 'ip-bypassed route: no exempt flag past the short-circuit');

$t->section('checklist 8: penetration detection still scans exempt IPs');
$engine = makeEngine(rateLimit: 100, exemptIps: [EXEMPT_IP]);
$request = new SimpleGuardRequest(urlPath: '/', clientHost: EXEMPT_IP, queryParams: ['q' => '<script>alert(1)</script>']);
$response = $engine->execute($request);
$t->same(400, $response?->statusCode(), 'attack payload from an exempt IP still gets 400');
$t->same(true, $request->state()->isExempt, 'the exempt flag was set; detection ignores it');
$response = fire($engine, OTHER_IP, ['q' => '<script>alert(1)</script>']);
$t->same(400, $response?->statusCode(), 'attack payload from a non-exempt IP still gets 400');

$t->section('skip consumers: user agent check skips for exempt IPs');
$engine = makeEngine(rateLimit: 100, exemptIps: [EXEMPT_IP], blockedUserAgents: ['badbot.*']);
$t->same(null, fire($engine, EXEMPT_IP, [], ['User-Agent' => 'badbot/1.0']), 'exempt IP with blocked UA passes');
$t->same(403, fire($engine, OTHER_IP, [], ['User-Agent' => 'badbot/1.0'])?->statusCode(), 'non-exempt IP with blocked UA still 403');

$t->section('skip consumers: global cloud block still applies to exempt IPs');
$engine = makeEngine(rateLimit: 100, exemptIps: [EXEMPT_IP], blockCloudProviders: ['AWS'], seedCloud: true);
$t->same(403, fire($engine, EXEMPT_IP)?->statusCode(), 'global block_cloud_providers denies an exempt AWS IP');
$engine = makeEngine(rateLimit: 100, whitelist: [EXEMPT_IP], blockCloudProviders: ['AWS'], seedCloud: true);
$t->same(null, fire($engine, EXEMPT_IP), 'pin: the whitelist branch is untouched by this port (pre-existing whitelist semantics: the check skips for whitelisted IPs)');

$t->section('skip consumers: per-route cloud blocks skip for exempt IPs');
$engine = makeEngine(rateLimit: 100, exemptIps: [EXEMPT_IP], seedCloud: true);
$request = new SimpleGuardRequest(urlPath: '/route', clientHost: EXEMPT_IP);
$request->state()->routeConfig = new RouteConfig(blockCloudProviders: ['AWS']);
$t->same(null, $engine->execute($request), 'exempt IP skips the route cloud block');
$request = new SimpleGuardRequest(urlPath: '/route', clientHost: CIDR_SIBLING_IP);
$request->state()->routeConfig = new RouteConfig(blockCloudProviders: ['AWS']);
$t->same(403, $engine->execute($request)?->statusCode(), 'non-exempt AWS IP still blocked by the route cloud block');

$t->section('checklist 10: IPv4-mapped and IPv6 forms match like the whitelist');
$engine = makeEngine(rateLimit: 1, rateLimitWindow: 60, exemptIps: ['::ffff:198.51.100.7']);
$t->same(null, fire($engine, EXEMPT_IP), 'mapped entry matches the plain IPv4 client (past-limit hit still passes)');
$t->same(null, fire($engine, '::ffff:198.51.100.7'), 'mapped entry matches the mapped IPv4-mapped client form');
$engine = makeEngine(rateLimit: 1, rateLimitWindow: 60, exemptIps: ['2001:db8::/32']);
$t->same(null, fire($engine, '2001:db8::1'), 'IPv6 CIDR entry matches the IPv6 client');
$engine = makeEngine(rateLimit: 1, rateLimitWindow: 60, whitelist: ['::ffff:198.51.100.7']);
$t->same(null, fire($engine, EXEMPT_IP), 'whitelist matcher parity: mapped entry allows the plain IPv4 client');
$engine = makeEngine(rateLimit: 100, whitelist: ['::ffff:198.51.100.7']);
$t->same(403, fire($engine, OTHER_IP)?->statusCode(), 'whitelist matcher parity: the restrictive path still denies the unlisted');

exit($t->done('EXEMPT IPS'));
