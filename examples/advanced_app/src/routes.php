<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Engine\GuardEngine;

/**
 * HTTP handlers of the advanced example, split by concern the way the
 * Python advanced example splits routers. The /admin/* handlers drive the
 * engine's ban manager directly; the engine's route gate (the admin token
 * check in guard_mw.php) has already run by the time these execute.
 */

/** @param array<string, mixed> $payload */
function advanced_json(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($payload), "\n";
}

function advanced_dispatch(GuardEngine $engine, string $path, string $method): void
{
    switch ($path) {
        case '/':
            advanced_json(200, [
                'app' => 'guard-core-php advanced example',
                'routes' => ['/health', '/ready', '/echo', '/rate/burst', '/admin/*', '/test/*'],
                'engine' => 'guard-core-php',
                'version' => '0.1.0',
            ]);

            return;
        case '/health':
            // Excluded from the pipeline (config excludePaths), so probes
            // and orchestrator health checks never trip the guard.
            advanced_json(200, ['status' => 'ok']);

            return;
        case '/ready':
            // Extend this with real dependency probes (Redis PING, cloud
            // range warmup) for your deployment.
            advanced_json(200, ['status' => 'ready']);

            return;
        case '/echo':
            if ($method !== 'POST') {
                advanced_json(405, ['error' => 'use POST']);

                return;
            }
            advanced_json(200, [
                'echo' => true,
                'method' => $method,
                'path' => $path,
            ]);

            return;
        case '/rate/burst':
            // Limited by config endpointRateLimits (5 requests per 60
            // seconds), enforced by exact request path.
            advanced_json(200, [
                'endpoint' => '/rate/burst',
                'limit' => '5 requests per 60 seconds',
            ]);

            return;
        case '/admin/banned':
            advanced_banned($engine);

            return;
        case '/admin/ban':
            advanced_ban($engine);

            return;
        case '/admin/unban':
            advanced_unban($engine);

            return;
        case '/test/xss':
        case '/test/sqli':
        case '/test/traversal':
            // Intentionally echoes a neutral verdict; the guard blocks the
            // request before the handler runs, so reaching this code means
            // detection was bypassed (defense in depth: do not log or
            // store the payload). Payloads ride in query parameters.
            advanced_json(200, ['detected' => false]);

            return;
        default:
            advanced_json(404, ['error' => 'not found']);
    }
}

function advanced_json_body(): ?array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return null;
    }

    return json_decode($raw, true);
}

function advanced_banned(GuardEngine $engine): void
{
    $ip = trim((string) ($_GET['ip'] ?? ''));
    if ($ip === '') {
        advanced_json(400, ['error' => 'query parameter "ip" is required']);

        return;
    }

    advanced_json(200, [
        'ip' => $ip,
        'banned' => $engine->banManager()->isIpBanned($ip),
    ]);
}

function advanced_ban(GuardEngine $engine): void
{
    $body = advanced_json_body();
    if ($body === null || !isset($body['ip']) || !is_string($body['ip']) || $body['ip'] === '') {
        advanced_json(400, ['error' => 'body must be {"ip": ..., "seconds": ..., "reason": ...}']);

        return;
    }
    $seconds = isset($body['seconds']) && is_int($body['seconds']) && $body['seconds'] > 0
        ? $body['seconds']
        : 300;
    $reason = isset($body['reason']) && is_string($body['reason']) && $body['reason'] !== ''
        ? $body['reason']
        : 'manual ban via admin route';

    try {
        $created = $engine->banManager()->ban($body['ip'], $seconds, $reason);
    } catch (\InvalidArgumentException) {
        advanced_json(400, ['error' => 'invalid IP address']);

        return;
    }
    if (!$created) {
        advanced_json(500, ['error' => 'ban refused (the target overlaps loopback or trusted proxy space)']);

        return;
    }
    advanced_json(200, ['ip' => $body['ip'], 'seconds' => $seconds, 'created' => true]);
}

function advanced_unban(GuardEngine $engine): void
{
    $body = advanced_json_body();
    if ($body === null || !isset($body['ip']) || !is_string($body['ip']) || $body['ip'] === '') {
        advanced_json(400, ['error' => 'body must be {"ip": ...}']);

        return;
    }

    try {
        $engine->banManager()->unban($body['ip']);
    } catch (\InvalidArgumentException) {
        advanced_json(400, ['error' => 'invalid IP address']);

        return;
    }
    advanced_json(200, ['ip' => $body['ip'], 'status' => 'unbanned']);
}
