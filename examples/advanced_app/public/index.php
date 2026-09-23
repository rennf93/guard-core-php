<?php

declare(strict_types=1);

/**
 * Front controller for the PHP built-in server:
 *
 *   php -S 0.0.0.0:8080 -t examples/advanced_app/public examples/advanced_app/public/index.php
 *
 * Assembles the advanced example: tuned engine config, the guard adapter,
 * and the route handlers, mirroring the Go example's cmd/server assembly.
 */

use RenzoFranceschini\GuardCore\Engine\GuardEngine;

require __DIR__ . '/../../../vendor/autoload.php';
require __DIR__ . '/../src/config.php';
require __DIR__ . '/../src/guard_mw.php';
require __DIR__ . '/../src/routes.php';

/**
 * Engine holder. Runtimes that keep the process alive across requests
 * (worker-mode runtimes) reuse the instance and its in-process state; the
 * PHP built-in server starts a fresh process per request, but all shared
 * state (bans, rate limits) is Redis-backed here, so the demo behaves the
 * same either way.
 */
function advanced_engine(): GuardEngine
{
    static $engine = null;
    if ($engine !== null) {
        return $engine;
    }

    $engine = new GuardEngine(advanced_config());
    // Connects Redis when enabled and initializes ban/rate-limit state.
    $engine->initialize();

    return $engine;
}

$engine = advanced_engine();

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

$verdict = advanced_guard($engine, $path, $method, advanced_collect_headers());
if ($verdict !== null) {
    [$headers, $status, $body] = $verdict;
    http_response_code($status);
    foreach ($headers as $name => $value) {
        header("{$name}: {$value}");
    }
    if ($body !== null) {
        echo $body;
    }

    return;
}

advanced_dispatch($engine, $path, $method);
