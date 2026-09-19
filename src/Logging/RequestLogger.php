<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Logging;

interface RequestLogger
{
    /** @param array<string, mixed> $context */
    public function log(string $level, string $message, array $context = []): void;
}
