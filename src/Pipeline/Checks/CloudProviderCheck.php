<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\LogActivity;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class CloudProviderCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly CloudManager $cloudManager,
        private readonly RouteResolver $routeResolver
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'cloud_provider';
    }

    public function containerFields(): array
    {
        return ['block_cloud_providers'];
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        if ($config->cloudBlockingEnabled()) {
            return true;
        }

        return CheckFactory::routeConfigApplies($routeConfigs, fn (RouteConfig $rc): bool => $rc->blockCloudProviders !== []);
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $state = $request->state();
        if ($state->isWhitelisted) {
            return null;
        }

        $clientIp = $state->clientIp;
        $routeConfig = $state->routeConfig;
        if ($clientIp === null || $clientIp === '') {
            return null;
        }

        if ($this->routeResolver->shouldBypassCheck('clouds', $routeConfig)) {
            return null;
        }

        if ($state->isExempt) {
            // An exempt match skips the route-driven cloud blocks, but the
            // global block_cloud_providers list still applies: the reference
            // enforces the global list inside the global IP stage
            // (check_ip_access), ahead of the exempt flag, so an exempt
            // match can never be set past it. This port enforces the global
            // list here, so the exempt skip resolves the global list
            // directly instead of the route-wins composition.
            if ($this->config->blockCloudProviders === []) {
                return null;
            }

            $providers = $this->config->blockCloudProviders;
        } else {
            $providers = $this->routeResolver->getCloudProvidersToCheck($routeConfig, $this->config->blockCloudProviders);
            if ($providers === null) {
                return null;
            }
        }

        if (!$this->cloudManager->isCloudIp($clientIp, $providers)) {
            return null;
        }

        LogActivity::log(
            $request,
            $this->logger,
            $this->config,
            logType: 'suspicious',
            level: $this->config->logSuspiciousLevel,
            reason: "Blocked cloud provider IP: {$clientIp}",
            passiveMode: $this->config->passiveMode,
            checkName: $this->checkName()
        );

        if (!$this->isPassiveMode()) {
            return $this->createErrorResponse(403, 'Cloud provider IP not allowed');
        }

        return null;
    }
}
