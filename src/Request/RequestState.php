<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

use RenzoFranceschini\GuardCore\Routing\RouteConfig;

final class RequestState
{
    public ?string $clientIp = null;

    public ?RouteConfig $routeConfig = null;

    public bool $guardExclusionScoped = false;

    public bool $isWhitelisted = false;

    public ?bool $guardRouteUnresolved = null;

    /** @var array{reason: string, trigger_info: string}|null */
    public ?array $guardBlockStash = null;

    /** @var array<string, mixed> */
    public array $scratch = [];
}
