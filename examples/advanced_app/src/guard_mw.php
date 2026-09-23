<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Request\RequestState;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;

/**
 * The SAPI adapter used by the advanced example. It translates native SAPI
 * superglobals into SimpleGuardRequest, attaches route IDs, enforces the
 * admin route gate, and writes block verdicts.
 *
 * In production services prefer the official PSR-15 adapter (psr15-guard);
 * this file exists to show the complete contract in app code.
 */

/**
 * The example's route registry. guard-core-php's GuardEngine facade does not
 * expose a route registry yet (its internal RouteResolver is built with no
 * route configs), so the admin gate below reproduces the engine's
 * RequiredHeadersCheck semantics in app code: a missing header is rejected
 * with 400 and the engine's exact message, before the handler runs.
 *
 * @return array<string, list<string>> route id => guarded path prefixes
 */
function advanced_route_table(): array
{
    return [
        'admin' => ['/admin/'],
    ];
}

/** @return array<string, string> lowercase name => value */
function advanced_collect_headers(): array
{
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (str_starts_with($key, 'HTTP_')) {
            $name = strtolower(str_replace('_', '-', substr($key, 5)));
            $headers[$name] = (string) $value;
        }
    }
    if (isset($_SERVER['CONTENT_TYPE'])) {
        $headers['content-type'] = (string) $_SERVER['CONTENT_TYPE'];
    }

    return $headers;
}

/** @param array<string, string> $headers */
function advanced_route_id_for(array $routeTable, string $path): ?string
{
    foreach ($routeTable as $routeId => $prefixes) {
        foreach ($prefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return $routeId;
            }
        }
    }

    return null;
}

/**
 * Guard a request. Returns [headers, status, body] for a block verdict, or
 * null when the request may proceed to the handler.
 *
 * @param array<string, string> $headers
 *
 * @return array{array<string, string>, int, ?string}|null
 */
function advanced_guard(GuardEngine $engine, string $path, string $method, array $headers): ?array
{
    $routeTable = advanced_route_table();

    // Route registry gate (app-level stand-in for RequiredHeadersCheck on
    // the "admin" route; see advanced_route_table()).
    $routeId = advanced_route_id_for($routeTable, $path);
    if ($routeId !== null && $routeId === 'admin') {
        $token = trim($headers['x-admin-token'] ?? '');
        if ($token === '') {
            return [[], 400, "Missing required header: X-Admin-Token\n"];
        }
    }

    $body = '';
    if ($method === 'POST' || $method === 'PUT' || $method === 'PATCH') {
        $body = (string) file_get_contents('php://input');
    }

    $state = new RequestState();
    if ($routeId !== null) {
        // Attached for the engine's route_config check; harmless today
        // (the engine resolves no configs) and correct once a route
        // registry seam lands.
        $state->guardRouteId = $routeId;
    }

    $request = new SimpleGuardRequest(
        urlPath: $path,
        urlScheme: 'http',
        host: $headers['host'] ?? 'localhost',
        method: $method,
        // Resolved by the engine: with TRUSTED_PROXIES matching nginx, the
        // engine walks X-Forwarded-For to the real client IP.
        clientHost: $_SERVER['REMOTE_ADDR'] ?? null,
        headers: $headers,
        queryParams: $_GET,
        rawQuery: $_SERVER['QUERY_STRING'] ?? '',
        body: $body,
        state: $state,
    );

    $verdict = $engine->execute($request);
    if ($verdict === null) {
        return null;
    }

    return [$verdict->headers()->all(), $verdict->statusCode(), $verdict->body()];
}
