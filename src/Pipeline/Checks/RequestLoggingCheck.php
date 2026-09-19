<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\LogActivity;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;

final class RequestLoggingCheck extends SecurityCheck
{
    public function checkName(): string
    {
        return 'request_logging';
    }

    /** @param list<\RenzoFranceschini\GuardCore\Routing\RouteConfig>|null $routeConfigs */
    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return $config->logRequestLevel !== null;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        LogActivity::log(
            $request,
            $this->logger,
            $this->config,
            logType: 'request',
            level: $this->config->logRequestLevel,
            checkName: $this->checkName()
        );

        return null;
    }
}
