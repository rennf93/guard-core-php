<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\RateLimit;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

final class RateLimitHandler
{
    public const MAX_TRACKED_RATE_LIMIT_KEYS = 10000;

    private const RATE_LIMIT_SCRIPT = "\nlocal key = KEYS[1]\nlocal now = tonumber(ARGV[1])\nlocal window = tonumber(ARGV[2])\nlocal limit = tonumber(ARGV[3])\nlocal window_start = now - window\n\nredis.call('ZADD', key, now, now)\n\nredis.call('ZREMRANGEBYSCORE', key, 0, window_start)\n\nlocal count = redis.call('ZCARD', key)\n\nredis.call('EXPIRE', key, window * 2)\n\nreturn count\n";

    private const FAIL_OPEN_WARNING = 'Redis unavailable for rate limiting; using the in-memory window (redis_fail_open=True); with several workers the effective limit is workers x rate_limit';

    private ?RedisHandler $redisHandler = null;

    private ?IpBanManager $ipBanManager = null;

    private ?string $scriptSha = null;

    private bool $failOpenWarned = false;

    /** @var \Closure(): float */
    private \Closure $clock;

    /** @var \Closure(string): void|null */
    private ?\Closure $warn = null;

    /** @var \Closure(): void|null */
    private ?\Closure $onScriptReloaded = null;

    /** @var \Closure(string): string|null */
    private ?\Closure $geoResolver = null;

    /** @var array<string, list<float>> */
    private array $pipelineTimestamps = [];

    /** @var array<string, list<float>> */
    private array $byIpTimestamps = [];

    /** @var array<string, int> */
    private array $byIpAutobanCounts = [];

    /** @var array<string, int> */
    private array $pipelineSuspiciousCounts = [];

    /**
     * @param (\Closure(): float)|null $clock
     * @param (\Closure(string): void)|null $warn
     * @param (\Closure(): void)|null $onScriptReloaded
     * @param (\Closure(string): string)|null $geoResolver
     */
    public function __construct(
        private readonly RateLimitConfig $config,
        ?\Closure $clock = null,
        ?\Closure $warn = null,
        ?\Closure $onScriptReloaded = null,
        ?\Closure $geoResolver = null
    ) {
        $this->clock = $clock ?? static fn (): float => microtime(true);
        $this->warn = $warn;
        $this->onScriptReloaded = $onScriptReloaded;
        $this->geoResolver = $geoResolver;
    }

    public function initializeRedis(?RedisHandler $redisHandler): void
    {
        $this->redisHandler = $redisHandler;

        if ($redisHandler === null || !$this->config->enableRedis) {
            return;
        }

        try {
            $this->scriptSha = $redisHandler->connection()->scriptLoad(self::RATE_LIMIT_SCRIPT);
        } catch (\Throwable) {
            $this->scriptSha = null;
        }
    }

    public function initializeIpBan(IpBanManager $ipBanManager): void
    {
        $this->ipBanManager = $ipBanManager;
    }

    public function scriptSha(): ?string
    {
        return $this->scriptSha;
    }

    public function pipelineBucketCount(): int
    {
        return count($this->pipelineTimestamps);
    }

    public function primitiveBucketCount(): int
    {
        return count($this->byIpTimestamps);
    }

    public function primitiveAutobanCount(string $ip): int
    {
        return $this->byIpAutobanCounts[$ip] ?? 0;
    }

    public function pipelineSuspiciousCount(string $ip): int
    {
        return $this->pipelineSuspiciousCounts[$ip] ?? 0;
    }

    public function checkRateLimit(RateLimitRequest $request, string $clientIp): ?RateLimitOutcome
    {
        if (!$this->config->enableRateLimiting) {
            return null;
        }

        if ($request->whitelisted || $request->bypassRateLimit) {
            return null;
        }

        $tiers = $this->resolveTiers($request, $clientIp);

        foreach ($tiers as [$limit, $window, $endpointPath, $tier]) {
            $now = ($this->clock)();
            $windowStart = $now - $window;

            $count = null;
            $inMemory = false;
            if ($this->config->enableRedis && $this->redisHandler !== null) {
                $count = $this->redisRequestCount(
                    $clientIp,
                    $now,
                    $windowStart,
                    $endpointPath,
                    $window,
                    $limit,
                    false
                );
            }

            if ($count === null) {
                $inMemory = true;
                $count = $this->inMemoryRequestCount(
                    $this->pipelineTimestamps,
                    $clientIp,
                    $windowStart,
                    $now,
                    $endpointPath
                );
            }

            if ($count > $limit || ($inMemory && $count >= $limit)) {
                $reportedCount = $inMemory ? $count + 1 : $count;
                $this->feedAutoban($clientIp, $this->pipelineSuspiciousCounts);
                if ($inMemory) {
                    return new RateLimitOutcome($reportedCount, $window, $tier, true);
                }

                return new RateLimitOutcome($count, $window, $tier, false);
            }
        }

        return null;
    }

    public function checkRateLimitByIp(string $ip, string $endpointPath = ''): bool
    {
        if (CanonicalIp::parse($ip) === null) {
            throw new \InvalidArgumentException("check_rate_limit_by_ip: invalid ip {$ip}");
        }
        if (str_contains($endpointPath, ':')) {
            throw new \InvalidArgumentException(
                "check_rate_limit_by_ip: endpoint_path must not contain ':' (got {$endpointPath})"
            );
        }

        if (!$this->config->enableRateLimiting) {
            return true;
        }

        $now = ($this->clock)();
        $window = $this->config->rateLimitWindow;
        $windowStart = $now - $window;

        $allowed = null;
        if ($this->config->enableRedis && $this->redisHandler !== null) {
            $count = $this->redisRequestCount($ip, $now, $windowStart, $endpointPath, $window, $this->config->rateLimit, true);
            if ($count !== null) {
                $allowed = $count <= $this->config->rateLimit;
            }
        }

        if ($allowed === null) {
            $requestCount = $this->inMemoryRequestCount($this->byIpTimestamps, $ip, $windowStart, $now, $endpointPath);
            $allowed = $requestCount < $this->config->rateLimit;
        }

        if (!$allowed) {
            $this->feedAutoban($ip, $this->byIpAutobanCounts);
        }

        return $allowed;
    }

    public function reset(): void
    {
        $this->pipelineTimestamps = [];

        if ($this->config->enableRedis && $this->redisHandler !== null) {
            try {
                $this->redisHandler->deletePattern('rate_limit:rate:*');
            } catch (\Throwable) {
            }
        }

        $this->redisHandler = null;
        $this->scriptSha = null;
    }

    /** @return list<array{int, int, string, string}> */
    private function resolveTiers(RateLimitRequest $request, string $clientIp): array
    {
        $tiers = [];
        $path = $request->urlPath;

        $endpoint = $this->config->endpointRateLimits[$path] ?? null;
        if ($endpoint !== null) {
            $tiers[] = [$endpoint['limit'], $endpoint['window'], $path, 'endpoint'];
        }

        if ($request->routeRateLimit !== null) {
            $tiers[] = [
                $request->routeRateLimit,
                $request->routeRateLimitWindow ?? 60,
                $path,
                'route',
            ];
        }

        if ($request->geoRateLimits !== null) {
            $entry = null;
            $country = $this->geoResolver !== null ? ($this->geoResolver)($clientIp) : null;
            if ($country !== null && $country !== '' && isset($request->geoRateLimits[$country])) {
                $entry = $request->geoRateLimits[$country];
            } elseif (isset($request->geoRateLimits['*'])) {
                $entry = $request->geoRateLimits['*'];
            }
            if ($entry !== null) {
                $tiers[] = [$entry['limit'], $entry['window'], $path, 'geo'];
            }
        }

        $tiers[] = [$this->config->rateLimit, $this->config->rateLimitWindow, '', 'global'];

        return $tiers;
    }

    private function redisRequestCount(
        string $clientIp,
        float $now,
        float $windowStart,
        string $endpointPath,
        int $window,
        int $limit,
        bool $forcePipelineFallback
    ): ?int {
        $key = $this->rateKey($clientIp, $endpointPath);

        try {
            if ($this->scriptSha !== null && !$forcePipelineFallback) {
                try {
                    $count = $this->evalSha($this->scriptSha, $key, $now, $window, $limit);
                } catch (GuardRedisException $e) {
                    if (!str_contains($e->getMessage(), 'NOSCRIPT')) {
                        throw $e;
                    }
                    $this->scriptSha = $this->redisHandler->connection()->scriptLoad(self::RATE_LIMIT_SCRIPT);
                    if ($this->onScriptReloaded !== null) {
                        ($this->onScriptReloaded)();
                    }
                    $count = $this->evalSha($this->scriptSha, $key, $now, $window, $limit);
                }

                return $count;
            }

            $pipe = $this->redisHandler->connection()->pipeline();
            $pipe->multi();
            $pipe->zAdd($key, $now, (string) $now);
            $pipe->zRemRangeByScore($key, '0', (string) $windowStart);
            $pipe->zCard($key);
            $pipe->expire($key, $window * 2);
            $results = $pipe->execute();

            return isset($results[2]) ? (int) $results[2] : 0;
        } catch (\Throwable $e) {
            if ($this->config->redisFailOpen) {
                $this->warnFailOpen();

                return null;
            }
            throw new GuardRedisException('Redis rate limiting unavailable', 503, $e);
        }
    }

    private function evalSha(string $sha, string $key, float $now, int $window, int $limit): int
    {
        $count = $this->redisHandler->connection()->evalSha(
            $sha,
            1,
            $key,
            (string) $now,
            (string) $window,
            (string) $limit
        );

        return (int) $count;
    }

    private function rateKey(string $clientIp, string $endpointPath): string
    {
        $rateKey = $endpointPath === ''
            ? "rate:{$clientIp}"
            : 'rate:' . $clientIp . ':' . hash('sha256', $endpointPath);

        return $this->redisHandler->fullKey('rate_limit', $rateKey);
    }

    /**
     * @param array<string, list<float>> $store
     */
    private function inMemoryRequestCount(
        array &$store,
        string $clientIp,
        float $windowStart,
        float $now,
        string $endpointPath
    ): int {
        $key = $endpointPath === ''
            ? $clientIp
            : $clientIp . ':' . hash('sha256', $endpointPath);

        $timestamps = $store[$key] ?? [];
        unset($store[$key]);

        while ($timestamps !== [] && $timestamps[0] <= $windowStart) {
            array_shift($timestamps);
        }

        $requestCount = count($timestamps);
        $timestamps[] = $now;
        $store[$key] = $timestamps;
        $this->evictLru($store);

        return $requestCount;
    }

    /**
     * @param array<string, list<float>> $store
     */
    private function evictLru(array &$store): void
    {
        while (count($store) > self::MAX_TRACKED_RATE_LIMIT_KEYS) {
            $oldest = array_key_first($store);
            unset($store[$oldest]);
        }
    }

    /**
     * @param array<string, int> $counts
     */
    private function feedAutoban(string $ip, array &$counts): void
    {
        if (!$this->config->enableRateLimitAutoBan || !$this->config->enableIpBanning) {
            return;
        }
        if ($this->config->passiveMode) {
            return;
        }
        if ($this->ipBanManager !== null && $this->ipBanManager->isIpBanned($ip)) {
            return;
        }

        $count = ($counts[$ip] ?? 0) + 1;
        unset($counts[$ip]);
        $counts[$ip] = $count;
        $this->evictCountLru($counts);

        $threshold = $this->config->autoBanThreshold;
        $duration = $this->config->autoBanDuration;
        $reason = 'rate_limit_exceeded';

        $entry = $this->config->threatBanConfig['rate_limit'] ?? null;
        if ($entry !== null) {
            if ($count < $entry['threshold']) {
                return;
            }
            $threshold = $entry['threshold'];
            $duration = $entry['duration'];
            $reason = 'rate_limit_exceeded:rate_limit';
        } elseif ($count < $threshold) {
            return;
        }

        if ($this->ipBanManager !== null) {
            $this->ipBanManager->ban($ip, $duration, $reason);
        }
    }

    /**
     * @param array<string, int> $counts
     */
    private function evictCountLru(array &$counts): void
    {
        while (count($counts) > self::MAX_TRACKED_RATE_LIMIT_KEYS) {
            $oldest = array_key_first($counts);
            unset($counts[$oldest]);
        }
    }

    private function warnFailOpen(): void
    {
        if ($this->failOpenWarned) {
            return;
        }
        $this->failOpenWarned = true;
        if ($this->warn !== null) {
            ($this->warn)(self::FAIL_OPEN_WARNING);
        }
    }
}
