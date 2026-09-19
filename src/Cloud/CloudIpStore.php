<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cloud;

interface CloudIpStore
{
    /** None (null) means miss: refresh eligible. A set (even empty) means known. */
    public function get(string $provider): ?array;

    /** @param list<string> $ranges */
    public function set(string $provider, array $ranges, ?int $ttl = null): void;

    public function clear(): void;
}
