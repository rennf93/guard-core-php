<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Logging;

final class SimpleRequestLogger implements RequestLogger
{
    /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
    private array $records = [];

    public function __construct(private readonly bool $emit = false)
    {
    }

    /** @return list<array{level: string, message: string, context: array<string, mixed>}> */
    public function records(): array
    {
        return $this->records;
    }

    public function reset(): void
    {
        $this->records = [];
    }

    /** @param array<string, mixed> $context */
    public function log(string $level, string $message, array $context = []): void
    {
        $this->records[] = ['level' => strtolower($level), 'message' => $message, 'context' => $context];
        if ($this->emit) {
            error_log('[guard_core] ' . $message);
        }
    }
}
