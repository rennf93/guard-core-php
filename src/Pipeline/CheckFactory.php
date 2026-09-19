<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\Checks\IpSecurityCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\RateLimitCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class CheckFactory
{
    /** Slot order from spec 03 / factory.py DEFAULT_CHECK_CLASSES. */
    public const DEFAULT_CHECK_NAMES = [
        'route_config', 'emergency_mode', 'https_enforcement', 'request_logging',
        'request_size_content', 'required_headers', 'authentication', 'referrer',
        'custom_validators', 'time_window', 'cloud_ip_refresh', 'ip_security',
        'cloud_provider', 'user_agent', 'rate_limit', 'suspicious_activity',
        'custom_request',
    ];

    /**
     * Container fields whose sizes participate in staleness detection
     * (factory.py WATCHED_CONTAINER_FIELDS, first-seen order).
     */
    public const WATCHED_CONTAINER_FIELDS = ['block_cloud_providers', 'blocked_user_agents', 'endpoint_rate_limits'];

    public function __construct(
        private readonly GuardResponseFactory $responseFactory,
        private readonly RouteResolver $routeResolver = new RouteResolver(),
        private readonly ?IpBanManager $ipBanManager = null,
        private readonly ?RateLimitHandler $rateLimitHandler = null,
        private readonly ?SusPatterns $susPatterns = null
    ) {
    }

    /** @param list<RouteConfig>|null $routeConfigs @return list<SecurityCheck> */
    public function buildChecks(SecurityConfig $config, ?array $routeConfigs = null): array
    {
        $checks = [];
        foreach (self::DEFAULT_CHECK_NAMES as $name) {
            $check = $this->buildOne($name, $config);
            if ($check !== null && $check->appliesTo($config, $routeConfigs)) {
                $checks[] = $check;
            }
        }

        return $checks;
    }

    private function buildOne(string $name, SecurityConfig $config): ?SecurityCheck
    {
        return match ($name) {
            'ip_security' => new IpSecurityCheck($config, $this->responseFactory, $this->ipBanManager, $this->routeResolver),
            'rate_limit' => new RateLimitCheck($config, $this->responseFactory, $this->rateLimitHandler, $this->routeResolver),
            'suspicious_activity' => new SuspiciousActivityCheck(
                $config,
                $this->responseFactory,
                $this->susPatterns ?? new SusPatterns($config->detectionSemanticThreshold),
                $this->ipBanManager,
                $this->routeResolver
            ),
            default => new DeferredCheck($name, $config, $this->responseFactory, $this->deferredGate($name)),
        };
    }

    /**
     * Construction-time gate for a deferred slot, per the spec 03 table. The
     * enabling config fields belong to features this port does not implement;
     * a supported SecurityConfig can never turn them on (config construction
     * rejects them), so each gate resolves to false against the subset. If a
     * future port extension makes a gate return true, DeferredCheck::check()
     * fails closed with UnsupportedFeatureError.
     *
     * @return \Closure(SecurityConfig, list<RouteConfig>|null): bool
     */
    private function deferredGate(string $name): \Closure
    {
        return static fn (SecurityConfig $config, ?array $routeConfigs): bool => false;
    }
}
