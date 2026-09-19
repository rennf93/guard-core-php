<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\RateLimit;

final class RateLimitRequest
{
    /**
     * @param array<string, array{limit: int, window: int}>|null $geoRateLimits
     */
    public function __construct(
        public readonly string $urlPath = '',
        public readonly bool $whitelisted = false,
        public readonly bool $bypassRateLimit = false,
        public readonly ?array $geoRateLimits = null,
        public readonly ?int $routeRateLimit = null,
        public readonly ?int $routeRateLimitWindow = null
    ) {
    }
}
