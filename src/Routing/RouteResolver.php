<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Routing;

use RenzoFranceschini\GuardCore\Request\GuardRequest;

final class RouteResolver
{
    /** @param array<string, RouteConfig> $routeConfigs */
    public function __construct(
        private readonly array $routeConfigs = []
    ) {
    }

    public function getRouteConfig(GuardRequest $request): ?RouteConfig
    {
        $routeId = $request->state()->guardRouteId;
        if ($routeId === null || $routeId === '') {
            return null;
        }

        return $this->routeConfigs[$routeId] ?? null;
    }

    public function shouldBypassCheck(string $checkName, ?RouteConfig $routeConfig): bool
    {
        if ($routeConfig === null) {
            return false;
        }

        return in_array($checkName, $routeConfig->bypassedChecks, true)
            || in_array('all', $routeConfig->bypassedChecks, true);
    }

    /**
     * @param list<string> $globalProviders
     * @return list<string>|null
     */
    public function getCloudProvidersToCheck(?RouteConfig $routeConfig, array $globalProviders = []): ?array
    {
        if ($routeConfig !== null && $routeConfig->blockCloudProviders !== []) {
            return $routeConfig->blockCloudProviders;
        }
        if ($globalProviders !== []) {
            return $globalProviders;
        }

        return null;
    }
}
