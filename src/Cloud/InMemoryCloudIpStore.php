<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cloud;

final class InMemoryCloudIpStore implements CloudIpStore
{
    /** @var array<string, list<string>> */
    private array $data = [];

    /** @var array<string, float> */
    private array $expiresAt = [];

    public function __construct(private readonly \Closure $clock = static fn (): float => microtime(true))
    {
    }

    public function get(string $provider): ?array
    {
        $expiresAt = $this->expiresAt[$provider] ?? null;
        if ($expiresAt !== null && ($this->clock)() >= $expiresAt) {
            unset($this->data[$provider], $this->expiresAt[$provider]);

            return null;
        }
        $ranges = $this->data[$provider] ?? null;
        if ($ranges === null) {
            return null;
        }

        return $ranges;
    }

    public function set(string $provider, array $ranges, ?int $ttl = null): void
    {
        $this->data[$provider] = array_values($ranges);
        if ($ttl === null) {
            unset($this->expiresAt[$provider]);
        } else {
            $this->expiresAt[$provider] = ($this->clock)() + $ttl;
        }
    }

    public function clear(): void
    {
        $this->data = [];
        $this->expiresAt = [];
    }
}
