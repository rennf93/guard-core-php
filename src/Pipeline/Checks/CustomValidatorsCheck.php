<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\LogActivity;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

final class CustomValidatorsCheck extends SecurityCheck
{
    public function checkName(): string
    {
        return 'custom_validators';
    }

    /** @param list<RouteConfig>|null $routeConfigs */
    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return CheckFactory::routeConfigApplies(
            $routeConfigs,
            fn (RouteConfig $rc): bool => $rc->customValidators !== []
        );
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $routeConfig = $request->state()->routeConfig;
        if ($routeConfig === null || $routeConfig->customValidators === []) {
            return null;
        }

        foreach ($routeConfig->customValidators as $validator) {
            $validationResponse = $validator($request);
            if ($validationResponse) {
                LogActivity::log(
                    $request,
                    $this->logger,
                    $this->config,
                    logType: 'suspicious',
                    level: $this->config->logSuspiciousLevel,
                    reason: 'Custom validation failed',
                    passiveMode: $this->config->passiveMode,
                    checkName: $this->checkName()
                );
                if (!$this->config->passiveMode && $validationResponse instanceof GuardResponse) {
                    return $validationResponse;
                }
            }
        }

        return null;
    }
}
