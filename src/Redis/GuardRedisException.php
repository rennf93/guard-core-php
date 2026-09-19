<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Redis;

final class GuardRedisException extends \RuntimeException
{
    public function __construct(string $message, int $code = 503, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
