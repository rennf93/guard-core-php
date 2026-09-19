<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

abstract class SecurityCheck
{
    public function __construct(
        protected SecurityConfig $config,
        protected GuardResponseFactory $responseFactory
    ) {
    }

    abstract public function checkName(): string;

    /** @return list<string> */
    public function containerFields(): array
    {
        return [];
    }

    public function enforcedOnExcludedPaths(): bool
    {
        return false;
    }

    /** @param list<RouteConfig>|null $routeConfigs */
    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return true;
    }

    abstract public function check(GuardRequest $request): ?GuardResponse;

    public function isPassiveMode(): bool
    {
        return $this->config->passiveMode;
    }

    public function createErrorResponse(int $statusCode, string $defaultMessage): GuardResponse
    {
        return $this->responseFactory->createResponse($defaultMessage, $statusCode);
    }

    protected function stashBlock(GuardRequest $request, string $reason, string $triggerInfo): void
    {
        if ($this->isPassiveMode()) {
            return;
        }
        $request->state()->guardBlockStash = ['reason' => $reason, 'trigger_info' => $triggerInfo];
    }
}
