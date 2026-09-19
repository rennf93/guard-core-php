<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\RateLimit;

final class RateLimitConfig
{
    /**
     * @param array<string, array{limit: int, window: int}> $endpointRateLimits
     * @param array<string, array{threshold: int, duration: int}> $threatBanConfig
     */
    public function __construct(
        public readonly bool $enableRateLimiting = true,
        public readonly int $rateLimit = 10,
        public readonly int $rateLimitWindow = 60,
        public readonly array $endpointRateLimits = [],
        public readonly bool $enableRateLimitAutoBan = false,
        public readonly int $autoBanThreshold = 10,
        public readonly int $autoBanDuration = 3600,
        public readonly array $threatBanConfig = [],
        public readonly bool $enableRedis = false,
        public readonly bool $redisFailOpen = false,
        public readonly bool $passiveMode = false,
        public readonly bool $enableIpBanning = false
    ) {
    }
}
