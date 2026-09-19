<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\RateLimit;

final class RateLimitOutcome
{
    public const STATUS = 429;
    public const MESSAGE = 'Too many requests';

    public function __construct(
        public readonly int $count,
        public readonly int $window,
        public readonly string $tier,
        public readonly bool $inMemory
    ) {
    }

    public function retryAfter(): string
    {
        return (string) $this->window;
    }

    /** @return array{status: int, message: string, headers: array<string, string>} */
    public function errorResponse(): array
    {
        return [
            'status' => self::STATUS,
            'message' => self::MESSAGE,
            'headers' => ['Retry-After' => $this->retryAfter()],
        ];
    }
}
