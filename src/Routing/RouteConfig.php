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
     * @param list<string> $blockedUserAgents
     * @param array<string, string> $requiredHeaders
     * @param list<string>|null $allowedContentTypes
     * @param array<string, string>|null $timeRestrictions start/end (HH:MM),
     *     optional timezone
     * @param list<string>|null $requireReferrer
     * @param (\Closure(object, string): mixed)|null $authVerifier
     * @param (\Closure(object, string): mixed)|null $apiKeyVerifier
     */
    public function __construct(
        array $bypassedChecks = [],
        public readonly ?int $rateLimit = null,
        public readonly ?int $rateLimitWindow = null,
        public readonly bool $requireHttps = false,
        public readonly ?string $authRequired = null,
        public readonly array $blockedUserAgents = [],
        public readonly array $requiredHeaders = [],
        public readonly ?int $maxRequestSize = null,
        public readonly ?array $allowedContentTypes = null,
        public readonly ?array $timeRestrictions = null,
        public readonly ?array $requireReferrer = null,
        public readonly bool $apiKeyRequired = false,
        public readonly ?\Closure $authVerifier = null,
        public readonly ?\Closure $apiKeyVerifier = null,
        public readonly ?string $apiKeyHeader = null,
        public readonly ?string $authorizationHeaderRequired = null
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

    /** @param array<string, mixed> $values */
    public function with(array $values): self
    {
        $known = [
            'bypassedChecks' => $this->bypassedChecks,
            'rateLimit' => $this->rateLimit,
            'rateLimitWindow' => $this->rateLimitWindow,
            'requireHttps' => $this->requireHttps,
            'authRequired' => $this->authRequired,
            'blockedUserAgents' => $this->blockedUserAgents,
            'requiredHeaders' => $this->requiredHeaders,
            'maxRequestSize' => $this->maxRequestSize,
            'allowedContentTypes' => $this->allowedContentTypes,
            'timeRestrictions' => $this->timeRestrictions,
            'requireReferrer' => $this->requireReferrer,
            'apiKeyRequired' => $this->apiKeyRequired,
            'authVerifier' => $this->authVerifier,
            'apiKeyVerifier' => $this->apiKeyVerifier,
            'apiKeyHeader' => $this->apiKeyHeader,
            'authorizationHeaderRequired' => $this->authorizationHeaderRequired,
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
