<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitRequest;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class RateLimitCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly ?RateLimitHandler $rateLimitHandler,
        private readonly RouteResolver $routeResolver
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'rate_limit';
    }

    public function enforcedOnExcludedPaths(): bool
    {
        return true;
    }

    public function containerFields(): array
    {
        return ['endpoint_rate_limits'];
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return $config->enableRateLimiting || $config->endpointRateLimits !== [];
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $clientIp = $request->state()->clientIp;
        if ($clientIp === null || $request->state()->isWhitelisted) {
            return null;
        }

        $routeConfig = $request->state()->routeConfig;
        $bypassed = $this->routeResolver->shouldBypassCheck('rate_limit', $routeConfig);
        if ($bypassed && $routeConfig !== null) {
            return null;
        }

        if ($this->rateLimitHandler === null) {
            return null;
        }

        $outcome = $this->rateLimitHandler->checkRateLimit(
            new RateLimitRequest(
                urlPath: $request->urlPath(),
                whitelisted: false,
                bypassRateLimit: $bypassed,
                routeRateLimit: $routeConfig?->rateLimit,
                routeRateLimitWindow: $routeConfig?->rateLimitWindow
            ),
            $clientIp
        );

        if ($outcome === null) {
            return null;
        }

        $this->stashBlock($request, "Rate limit exceeded: {$outcome->count}/{$outcome->window} ({$outcome->tier} tier)", 'rate_limit');
        if ($this->isPassiveMode()) {
            return null;
        }

        $response = $this->responseFactory->createResponse(
            $outcome::MESSAGE,
            $outcome::STATUS
        );
        foreach ($outcome->errorResponse()['headers'] as $name => $value) {
            $response->headers()->set($name, $value);
        }

        return $response;
    }
}
