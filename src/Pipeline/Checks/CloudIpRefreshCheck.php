<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class CloudIpRefreshCheck extends SecurityCheck
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
        return 'cloud_ip_refresh';
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
        $providers = $this->routeResolver->getCloudProvidersToCheck(
            $request->state()->routeConfig,
            $this->config->blockCloudProviders
        );
        if ($providers === null) {
            return null;
        }

        if (time() - $this->cloudManager->lastCloudIpRefresh > $this->config->cloudIpRefreshInterval) {
            $previousRefresh = $this->cloudManager->lastCloudIpRefresh;
            $this->cloudManager->lastCloudIpRefresh = time();
            $scheduled = $this->cloudManager->scheduleRefresh($providers, $this->config->cloudIpRefreshInterval);
            if (!$scheduled) {
                $this->cloudManager->lastCloudIpRefresh = $previousRefresh;
            }
        }

        return null;
    }
}
