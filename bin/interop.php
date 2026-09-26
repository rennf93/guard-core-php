<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Cloud\RedisCloudIpStore;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitRequest;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;

require __DIR__ . '/../vendor/autoload.php';

final class InteropRunner
{
    public int $passed = 0;
    public int $failed = 0;

    /** @var list<array{scenario: string, direction: string, name: string, passed: bool, detail: string}> */
    public array $checks = [];

    /** @var array<string, string> */
    public array $artifacts = [];

    public function check(string $scenario, string $direction, string $name, bool $ok, string $detail = ''): void
    {
        $verdict = $ok ? 'ok' : 'FAIL';
        echo "{$verdict} - [{$scenario}] {$name}" . ($detail !== '' ? " ({$detail})" : '') . "\n";
        if ($ok) {
            $this->passed++;
        } else {
            $this->failed++;
        }
        $this->checks[] = [
            'scenario' => $scenario,
            'direction' => $direction,
            'name' => $name,
            'passed' => $ok,
            'detail' => $detail,
        ];
    }

    public function report(string $participant, string $phase): string
    {
        return (string) json_encode([
            'participant' => $participant,
            'phase' => $phase,
            'passed' => $this->passed,
            'failed' => $this->failed,
            'checks' => $this->checks,
            'artifacts' => $this->artifacts,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}

const INTEROP_PREFIX = 'guard_core_interop:';
const INTEROP_RATE_WINDOW = 120;
const INTEROP_RATE_LIMIT_LOOSE = 10000;
const INTEROP_BAN_DURATION = 900;
const INTEROP_LEGACY_DURATION = 600;
const INTEROP_CLOUD_TTL = 3600;
const INTEROP_PY_BAN_IP = '203.0.113.7';
const INTEROP_GO_BAN_IP = '192.0.2.66';
const INTEROP_PHP_BAN_IP = '192.0.2.77';
const INTEROP_LEGACY_CANONICAL = '203.0.113.9';
const INTEROP_LEGACY_MAPPED = '::ffff:203.0.113.9';
const INTEROP_NETWORK_BAN = '198.51.100.0/24';
const INTEROP_NETWORK_PROBE = '198.51.100.55';
const INTEROP_BUCKET_A = '192.0.2.10';
const INTEROP_BUCKET_B = '192.0.2.11';
const INTEROP_BUCKET_C = '192.0.2.12';
const INTEROP_EXEMPT_IP = '192.0.2.30';
const INTEROP_EXEMPT_NORMAL_IP = '192.0.2.31';
const INTEROP_EXEMPT_BLACK_IP = '192.0.2.32';
const INTEROP_EXEMPT_LIMIT = 2;

/**
 * @param array<string, mixed> $input
 */
function interopRateConfig(int $limit): RateLimitConfig
{
    return new RateLimitConfig(
        rateLimit: $limit,
        rateLimitWindow: INTEROP_RATE_WINDOW,
        enableRedis: true,
        redisFailOpen: false
    );
}

/**
 * @param array<string, mixed> $input
 */
function interopFloatCheck(InteropRunner $t, ?string $raw, string $want, string $scenario, string $direction, string $name): void
{
    $parsed = $raw !== null && $raw !== '' ? (float) $raw : null;
    $fractional = $raw !== null && str_contains($raw, '.') && substr($raw, strpos($raw, '.') + 1) !== '0';
    $t->check(
        $scenario,
        $direction,
        $name,
        $raw === $want && $parsed !== null && $parsed > microtime(true) && $fractional,
        "raw=" . var_export($raw, true)
    );
}

/**
 * @param array<string, mixed> $input
 */
function runPhpReadThenWrite(InteropRunner $t, RedisHandler $redis, array $input): void
{
    $conn = $redis->connection();
    $ban = new IpBanManager();
    $ban->initializeRedis($redis);
    $rl = new RateLimitHandler(interopRateConfig(INTEROP_RATE_LIMIT_LOOSE));
    $rl->initializeRedis($redis);
    $rlA = new RateLimitHandler(interopRateConfig(5));
    $rlA->initializeRedis($redis);
    $rlB = new RateLimitHandler(interopRateConfig(2));
    $rlB->initializeRedis($redis);

    $pyBanned = $ban->isIpBanned(INTEROP_PY_BAN_IP);
    $pyMapped = $ban->isIpBanned('::ffff:203.0.113.7');
    $t->check('exact_ban_read', 'py:php', 'php honors the python ban 203.0.113.7', $pyBanned && $pyMapped);
    $t->check('canonical_mapped_spelling', 'py:php', 'php maps ::ffff:203.0.113.7 onto the canonical ban', $pyMapped);

    $pyRaw = $redis->getKey('banned_ips', INTEROP_PY_BAN_IP);
    interopFloatCheck($t, $pyRaw, (string) ($input['py_ban_expiry_raw'] ?? ''), 'float_string_value', 'py:php', 'python ban expiry is byte-equal and parses');

    $goBanned = $ban->isIpBanned(INTEROP_GO_BAN_IP);
    $t->check('exact_ban_read', 'go:php', 'php honors the go-written ban 192.0.2.66', $goBanned);
    $goRaw = $redis->getKey('banned_ips', INTEROP_GO_BAN_IP);
    interopFloatCheck($t, $goRaw, (string) ($input['go_ban_expiry_raw'] ?? ''), 'float_string_value', 'go:php', 'go ban expiry is byte-equal and parses');

    $netRaw = $redis->getKey('banned_networks', INTEROP_NETWORK_BAN);
    $netOk = is_string($netRaw) && $netRaw !== ''
        && is_numeric($netRaw)
        && (float) $netRaw > microtime(true)
        && CanonicalIp::networkContains(INTEROP_NETWORK_BAN, INTEROP_NETWORK_PROBE) === true;
    $t->check('network_ban_wire', 'py:php', 'banned_networks key carries a float expiry and contains the probe IP', $netOk, 'raw=' . var_export($netRaw, true));
    $managerSeesNetwork = $ban->isIpBanned(INTEROP_NETWORK_PROBE);
    $t->check('network_ban_no_redis_reader', 'py:php', 'php manager does not read banned_networks from redis (normative local-only CIDR)', $managerSeesNetwork === false);

    $prefix = $redis->prefix() . 'banned_ips:';
    $keys = [];
    $cursor = '0';
    do {
        [$cursor, $batch] = $conn->scan($cursor, $prefix . '*');
        foreach ($batch as $key) {
            $keys[] = $key;
        }
    } while ($cursor !== '0');
    $allCanonical = true;
    foreach ($keys as $key) {
        $rawIp = substr($key, strlen($prefix));
        if (CanonicalIp::canonicalize($rawIp) !== $rawIp) {
            $allCanonical = false;
        }
    }
    $t->check('legacy_migration_keys', 'py:php', 'migration state holds only canonical banned_ips keys', $allCanonical, 'keys=' . json_encode($keys));

    $legacyRaw = $redis->getKey('banned_ips', INTEROP_LEGACY_CANONICAL);
    $t->check('legacy_migration_value', 'py:php', 'migrated canonical key keeps the python-written value byte-exact', $legacyRaw === ($input['legacy_value_raw'] ?? null), 'raw=' . var_export($legacyRaw, true));

    $legacyPttl = $conn->pttl($prefix . INTEROP_LEGACY_CANONICAL);
    $t->check('legacy_migration_ttl', 'py:php', 'migrated canonical ban kept a positive TTL within the legacy bound', $legacyPttl > 0 && $legacyPttl <= INTEROP_LEGACY_DURATION * 1000, "pttl_ms={$legacyPttl}");

    $legacyGone = $redis->getKey('banned_ips', INTEROP_LEGACY_MAPPED);
    $t->check('legacy_migration_keys', 'py:php', 'legacy mapped-form key is deleted after migration', $legacyGone === null);

    $legacyBanned = $ban->isIpBanned(INTEROP_LEGACY_CANONICAL);
    $legacyMapped = $ban->isIpBanned(INTEROP_LEGACY_MAPPED);
    $t->check('legacy_migration_banned', 'py:php', 'php honors the migrated ban by canonical and mapped spelling', $legacyBanned && $legacyMapped);

    $outA = $rlA->checkRateLimit(new RateLimitRequest(), INTEROP_BUCKET_A);
    $t->check('rate_continuity', 'py+go:php', 'php observes the shared bucket A count on a blocked hit',
        $outA !== null && $outA->count === (int) ($input['expected_a_blocked'] ?? 0) && $outA->inMemory === false,
        'count=' . ($outA !== null ? (string) $outA->count : 'null'));

    $outB = $rlB->checkRateLimit(new RateLimitRequest(), INTEROP_BUCKET_B);
    $t->check('rate_continuity', 'go:php', 'php observes the go-written bucket B count on a blocked hit',
        $outB !== null && $outB->count === (int) ($input['expected_b_blocked'] ?? 0) && $outB->inMemory === false,
        'count=' . ($outB !== null ? (string) $outB->count : 'null'));

    $c1 = $rl->checkRateLimitByIp(INTEROP_BUCKET_C);
    $c2 = $rl->checkRateLimitByIp(INTEROP_BUCKET_C);
    $t->check('rate_write', 'php:php', 'php records 2 hits on bucket C', $c1 === true && $c2 === true);

    $store = new RedisCloudIpStore($redis);
    $cm = new CloudManager(null, $store);

    $awsPre = $store->get('AWS');
    $t->check('cloud_aws_present', 'py:php', 'php decodes the python-written AWS cache', $awsPre !== null, 'entries=' . json_encode($awsPre));
    $gcpPre = $store->get('GCP');
    $t->check('cloud_cache_present', 'go:php', 'php decodes the go-written GCP cache', $gcpPre !== null, 'entries=' . json_encode($gcpPre));
    if ($awsPre !== null && $gcpPre !== null) {
        $cm->refreshAsync(['AWS', 'GCP'], INTEROP_CLOUD_TTL);
        $t->check('cloud_block', 'py:php', 'php blocks an AWS IP from the python payload', $cm->isCloudIp('203.0.113.200', ['AWS']));
        $carved = $cm->isCloudIp('203.0.113.5', ['AWS:!us-east-1']);
        $t->check('cloud_carveout', 'py:php', 'php honors the AWS us-east-1 carve-out', ! $carved && $cm->isCloudIp('203.0.113.5', ['AWS']));
        $t->check('cloud_block', 'go:php', 'php blocks a GCP IP from the go payload', $cm->isCloudIp('192.0.2.200', ['GCP']));

        $rawAws = $redis->getKey('cloud_ip_v2', 'AWS');
        $store->set('AWS', $awsPre, INTEROP_CLOUD_TTL);
        $rewritten = $redis->getKey('cloud_ip_v2', 'AWS');
        $t->check('cloud_payload_bytes', 'py:php', 'php re-encodes the AWS payload byte-exact in the python format', $rawAws !== null && $rewritten === $rawAws, 'raw=' . var_export($rawAws, true));
    }

    $azureEntries = ['198.51.100.0/25', '198.51.100.128/25|eastus'];
    $store->set('Azure', $azureEntries, INTEROP_CLOUD_TTL);
    $azureRaw = $redis->getKey('cloud_ip_v2', 'Azure');
    $t->check('cloud_azure_write', 'php:php', 'php writes cloud_ip_v2:Azure in the python byte format', $azureRaw === '["198.51.100.0/25", "198.51.100.128/25|eastus"]', 'raw=' . var_export($azureRaw, true));
    if (is_string($azureRaw)) {
        $t->artifacts['azure_payload_raw'] = $azureRaw;
    }
    $cm->refreshAsync(['Azure'], INTEROP_CLOUD_TTL);
    $t->check('cloud_block', 'php:php', 'php blocks Azure IPs from its own payload',
        $cm->isCloudIp('198.51.100.200', ['Azure']) && $cm->isCloudIp('198.51.100.5', ['Azure']));
    $t->check('cloud_carveout', 'php:php', 'php honors the Azure eastus carve-out', ! $cm->isCloudIp('198.51.100.200', ['Azure:!eastus']));

    $phpBanned = $ban->ban(INTEROP_PHP_BAN_IP, INTEROP_BAN_DURATION, 'interop_php');
    $t->check('exact_ban_write', 'php:php', 'php bans 192.0.2.77', $phpBanned === true);
    $phpRaw = $redis->getKey('banned_ips', INTEROP_PHP_BAN_IP);
    $phpRoundTrip = is_string($phpRaw) && IpBanManager::formatExpiry((float) $phpRaw) === $phpRaw;
    $t->check('float_string_value', 'php:php', 'php ban expiry round-trips through its own formatter and stays fractional',
        $phpRoundTrip && is_string($phpRaw) && str_contains($phpRaw, '.') && (float) $phpRaw > microtime(true), 'raw=' . var_export($phpRaw, true));
    if (is_string($phpRaw)) {
        $t->artifacts['php_ban_expiry_raw'] = $phpRaw;
    }

    $bucketPttl = $conn->pttl($redis->fullKey('rate_limit', 'rate:' . INTEROP_BUCKET_A));
    $t->check('ttl_semantics', 'py:php', 'bucket A TTL stays within 2x the window', $bucketPttl > 0 && $bucketPttl <= INTEROP_RATE_WINDOW * 2 * 1000, "pttl_ms={$bucketPttl}");
}

/**
 * @param array<string, mixed> $input
 */
function runPhpExemptReadThenWrite(InteropRunner $t, RedisHandler $redis, array $input): void
{
    $limit = (int) ($input['expected_exempt_limit'] ?? INTEROP_EXEMPT_LIMIT);
    $host = getenv('REDIS_HOST') ?: '127.0.0.1';
    $config = new SecurityConfig(
        enableRedis: true,
        redisUrl: 'redis://' . $host . ':6379',
        redisPrefix: INTEROP_PREFIX,
        enableRateLimiting: true,
        rateLimit: $limit,
        rateLimitWindow: INTEROP_RATE_WINDOW,
        enableRateLimitAutoBan: false,
        autoBanThreshold: 1000,
        blacklist: [INTEROP_EXEMPT_BLACK_IP],
        exemptIps: [INTEROP_EXEMPT_IP, INTEROP_EXEMPT_BLACK_IP]
    );
    $engine = new GuardEngine($config, $redis);
    $engine->initialize();

    $drive = function (string $ip) use ($engine): array {
        $request = new SimpleGuardRequest(urlPath: '/api', clientHost: $ip);
        $response = $engine->execute($request);

        return [$response, $request->state()];
    };

    $exemptFlag = false;
    $exemptPassed = true;
    for ($i = 0; $i < $limit + 1; $i++) {
        [$response, $state] = $drive(INTEROP_EXEMPT_IP);
        if ($response !== null) {
            $exemptPassed = false;
        }
        $exemptFlag = $state->isExempt;
    }
    $t->check('exempt_allowed', 'py+go+php:php', sprintf('php engine passes the exempt client through %d pipeline drives at limit %d', $limit + 1, $limit),
        $exemptPassed && $exemptFlag, 'isExempt=' . var_export($exemptFlag, true));

    $afterGo = (int) ($input['exempt_n_after_go'] ?? -1);
    $rlObs = new RateLimitHandler(interopRateConfig($afterGo));
    $rlObs->initializeRedis($redis);
    $out = $rlObs->checkRateLimit(new RateLimitRequest(), INTEROP_EXEMPT_NORMAL_IP);
    $t->check('rate_continuity', 'py+go:php', 'php observes the shared non-exempt bucket count on a blocked hit at the pinned crossing',
        $out !== null && $out->count === $afterGo + 1 && $out->inMemory === false,
        'count=' . ($out !== null ? (string) $out->count : 'null') . " want=" . (string) ($afterGo + 1));

    [$blackResponse, $blackState] = $drive(INTEROP_EXEMPT_BLACK_IP);
    $t->check('blacklist_precedence', 'py+go+php:php', 'php engine denies the blacklisted exempt IP 403 without the exempt flag',
        $blackResponse !== null && $blackResponse->statusCode() === 403 && $blackState->isExempt === false,
        'status=' . ($blackResponse !== null ? (string) $blackResponse->statusCode() : 'null'));

    $conn = $redis->connection();
    $exemptZcard = $conn->zCard($redis->fullKey('rate_limit', 'rate:' . INTEROP_EXEMPT_IP));
    $t->check('exempt_no_state', 'py+go+php:php', 'exempt traffic leaves the shared bucket empty after the php drives',
        $exemptZcard === 0, "zcard={$exemptZcard}");
    $blackZcard = $conn->zCard($redis->fullKey('rate_limit', 'rate:' . INTEROP_EXEMPT_BLACK_IP));
    $t->check('blacklist_no_state', 'py+go+php:php', 'the blacklisted exempt bucket stays empty',
        $blackZcard === 0, "zcard={$blackZcard}");

    if ($out !== null) {
        $t->artifacts['exempt_n_after_php'] = (string) $out->count;
    }
}

$phase = getenv('INTEROP_PHASE') ?: '';
$host = getenv('REDIS_HOST') ?: '127.0.0.1';
$inputRaw = getenv('INTEROP_INPUT') ?: '{}';
$input = json_decode($inputRaw, true);
if (! is_array($input)) {
    fwrite(STDERR, "INTEROP_INPUT is not valid JSON\n");
    exit(1);
}

putenv('REDIS_PREFIX=' . INTEROP_PREFIX);
$redis = RedisHandler::fromEnv();
try {
    $redis->initialize();
} catch (Throwable $e) {
    fwrite(STDERR, "redis unreachable at {$host}:6379: {$e->getMessage()}\n");
    exit(1);
}

$t = new InteropRunner();

switch ($phase) {
    case 'php_read_then_write':
        runPhpReadThenWrite($t, $redis, $input);
        break;
    case 'php_exempt_read_then_write':
        runPhpExemptReadThenWrite($t, $redis, $input);
        break;
    default:
        fwrite(STDERR, "php runner does not serve phase '{$phase}'\n");
        exit(1);
}

$reportFile = getenv('INTEROP_REPORT_FILE');
if ($reportFile !== false && $reportFile !== '') {
    file_put_contents($reportFile, $t->report('php', $phase));
}

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);
