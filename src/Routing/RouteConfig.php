<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Routing;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;

final class RouteConfig
{
    private int $revision = 0;

    /** @var list<string> */
    public readonly array $bypassedChecks;

    /**
     * @param list<string> $bypassedChecks invalid names are silently dropped
     *     (decorator-time leniency); valid names update the config
     */
    public function __construct(
        array $bypassedChecks = [],
        public readonly ?int $rateLimit = null,
        public readonly ?int $rateLimitWindow = null
    ) {
        $this->bypassedChecks = array_values(array_filter(
            $bypassedChecks,
            fn (string $name): bool => in_array($name, SecurityConfig::VALID_BYPASS_CHECKS, true)
        ));
    }

    public function revision(): int
    {
        return $this->revision;
    }

    public function with(array $values): self
    {
        $known = [
            'bypassedChecks' => $this->bypassedChecks,
            'rateLimit' => $this->rateLimit,
            'rateLimitWindow' => $this->rateLimitWindow,
        ];
        foreach ($values as $name => $value) {
            if (!array_key_exists($name, $known)) {
                throw new \InvalidArgumentException("unknown route config field '{$name}'");
            }
            $known[$name] = $value;
        }

        $copy = new self(...$known);
        $copy->revision = $this->revision + 1;

        return $copy;
    }
}
