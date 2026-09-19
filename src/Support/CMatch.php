<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Support;

final class CMatch
{
    public function __construct(
        public readonly string $subject,
        public readonly string $pattern,
        public readonly int $cpStart,
        public readonly int $cpEnd,
        public readonly string $text,
        public readonly array $groups,
    ) {
    }

    public function group(int $index = 0): string
    {
        return $this->groups[$index] ?? '';
    }

    public function hasGroup(int $index): bool
    {
        return array_key_exists($index, $this->groups);
    }
}
