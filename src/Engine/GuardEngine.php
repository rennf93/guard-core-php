<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Engine;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\BlockEvents;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheckPipeline;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Request\ClientIpResolver;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class GuardEngine
{
    public const UNRESOLVABLE_CLIENT_CHECK_NAME = 'client_address_unresolved';

    private SecurityConfig $config;

    private readonly RedisHandler $redis;

    private readonly IpBanManager $banManager;

    private readonly RateLimitHandler $rateLimitHandler;

    private readonly ?CloudManager $cloudManager;

    private readonly GuardResponseFactory $responseFactory;

    private readonly SecurityCheckPipeline $pipeline;

    /**
     * @param (\Closure(string, string, array<string, mixed>): void)|null $log
     * @param (\Closure(string): void)|null $warn
     */
    public function __construct(
        SecurityConfig $config,
        ?RedisHandler $redis = null,
        ?\Closure $log = null,
        ?\Closure $warn = null,
        ?CloudManager $cloudManager = null
    ) {
        $this->config = $config;
        $this->redis = $redis ?? new RedisHandler(
            enableRedis: $config->enableRedis,
            prefix: $config->redisPrefix,
            host: getenv('REDIS_HOST') ?: '127.0.0.1',
            port: (int) (getenv('REDIS_PORT') ?: 6379)
        );
        $this->responseFactory = new GuardResponseFactory();
        $this->banManager = new IpBanManager($config->trustedProxies, $warn);
        $this->rateLimitHandler = new RateLimitHandler(self::rateLimitConfig($config), warn: $warn);
        $this->cloudManager = $cloudManager ?? ($config->cloudBlockingEnabled() ? new CloudManager() : null);
        $checkFactory = new CheckFactory(
            $this->responseFactory,
            new RouteResolver(),
            $this->banManager,
            $this->rateLimitHandler,
            null,
            $this->cloudManager
        );
        $this->pipeline = new SecurityCheckPipeline(
            $checkFactory->buildChecks($config),
            $config,
            array_keys($config->mutedCheckLogs),
            rebuildChecks: fn (): array => $checkFactory->buildChecks($this->config),
            log: $log,
            configProvider: fn (): SecurityConfig => $this->config
        );
    }

    public static function rateLimitConfig(SecurityConfig $config): RateLimitConfig
    {
        return new RateLimitConfig(
            enableRateLimiting: $config->enableRateLimiting,
            rateLimit: $config->rateLimit,
            rateLimitWindow: $config->rateLimitWindow,
            endpointRateLimits: $config->endpointRateLimits,
            enableRateLimitAutoBan: $config->enableRateLimitAutoBan,
            autoBanThreshold: $config->autoBanThreshold,
            autoBanDuration: $config->autoBanDuration,
            threatBanConfig: $config->threatBanConfig,
            enableRedis: $config->enableRedis,
            redisFailOpen: $config->redisFailOpen,
            passiveMode: $config->passiveMode,
            enableIpBanning: $config->enableIpBanning
        );
    }

    public function config(): SecurityConfig
    {
        return $this->config;
    }

    public function redis(): RedisHandler
    {
        return $this->redis;
    }

    public function banManager(): IpBanManager
    {
        return $this->banManager;
    }

    public function rateLimitHandler(): RateLimitHandler
    {
        return $this->rateLimitHandler;
    }

    public function cloudManager(): ?CloudManager
    {
        return $this->cloudManager;
    }

    public function responseFactory(): GuardResponseFactory
    {
        return $this->responseFactory;
    }

    public function pipeline(): SecurityCheckPipeline
    {
        return $this->pipeline;
    }

    public function failClosedResponse(): GuardResponse
    {
        return $this->createErrorResponse(500, 'Security check failed');
    }

    public function initialize(): void
    {
        if (!$this->redis->isEnabled()) {
            $this->banManager->initializeRedis(null);
            $this->rateLimitHandler->initializeRedis(null);

            return;
        }

        $this->redis->initialize();
        $this->banManager->initializeRedis($this->redis);
        $this->rateLimitHandler->initializeRedis($this->redis);
        $this->rateLimitHandler->initializeIpBan($this->banManager);
        $this->cloudManager?->initializeRedis($this->redis, ttl: $this->config->cloudIpRefreshInterval);
    }

    public function execute(GuardRequest $request): ?GuardResponse
    {
        $state = $request->state();

        if ($this->isPathExcluded($request->urlPath())) {
            $state->guardExclusionScoped = true;
        } elseif ($request->clientHost() === null) {
            $clientIp = ClientIpResolver::extract($request, $this->config);
            $state->clientIp = $clientIp;
            if ($clientIp === ClientIpResolver::UNKNOWN_CLIENT_IDENTITY && $this->config->failSecure) {
                return $this->unresolvableClientResponse($request);
            }
        }

        return $this->pipeline->execute($request);
    }

    private function unresolvableClientResponse(GuardRequest $request): GuardResponse
    {
        $reason = 'Client address could not be determined';
        $response = $this->createErrorResponse(403, $reason);
        BlockEvents::fire(
            $this->config->onBlock,
            $request,
            BlockEvents::buildPayload($request, self::UNRESOLVABLE_CLIENT_CHECK_NAME, $reason, '', false, $response->statusCode())
        );

        return $response;
    }

    private function createErrorResponse(int $statusCode, string $defaultMessage): GuardResponse
    {
        $message = $this->config->customErrorResponses[$statusCode] ?? $defaultMessage;

        return $this->responseFactory->createResponse($message, $statusCode);
    }

    private function isPathExcluded(string $urlPath): bool
    {
        $normalized = SecurityConfig::normalizeUrlPath($urlPath);
        if ($normalized === null) {
            return false;
        }

        foreach ($this->config->excludePaths as $excluded) {
            if ($normalized === $excluded || str_starts_with($normalized, $excluded . '/')) {
                return true;
            }
        }

        return false;
    }
}
