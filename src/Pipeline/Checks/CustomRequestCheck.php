<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;

final class CustomRequestCheck extends SecurityCheck
{
    public function checkName(): string
    {
        return 'custom_request';
    }

    /** @param list<\RenzoFranceschini\GuardCore\Routing\RouteConfig>|null $routeConfigs */
    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return $config->customRequestCheck !== null;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $customRequestCheck = $this->config->customRequestCheck;
        if ($customRequestCheck === null) {
            return null;
        }

        $customResponse = $customRequestCheck($request);
        if ($customResponse) {
            if (!$this->config->passiveMode) {
                return $this->responseFactory->applyModifier($customResponse);
            }
        }

        return null;
    }
}
