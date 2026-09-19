<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Config\UnsupportedFeatureError;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

/**
 * Fail-closed sentinel for a pipeline slot whose feature this port does not
 * implement yet. Its appliesTo() gate can never pass against a supported
 * SecurityConfig (enabling the underlying feature is rejected at config
 * construction); if it ever returns true anyway, check() throws.
 */
final class DeferredCheck extends SecurityCheck
{
    /**
     * @param (\Closure(SecurityConfig, list<RouteConfig>|null): bool)|null $gate
     */
    public function __construct(
        private readonly string $name,
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly ?\Closure $gate = null
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return $this->name;
    }

    /** @param list<RouteConfig>|null $routeConfigs */
    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        if ($this->gate === null) {
            return false;
        }

        return ($this->gate)($config, $routeConfigs);
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        throw new UnsupportedFeatureError("pipeline check '{$this->name}'");
    }
}
