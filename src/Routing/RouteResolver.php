<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Routing;

final class RouteResolver
{
    public function shouldBypassCheck(string $checkName, ?RouteConfig $routeConfig): bool
    {
        if ($routeConfig === null) {
            return false;
        }

        return in_array($checkName, $routeConfig->bypassedChecks, true)
            || in_array('all', $routeConfig->bypassedChecks, true);
    }
}
