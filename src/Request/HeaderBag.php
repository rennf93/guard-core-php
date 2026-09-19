<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

final class HeaderBag
{
    /** @var array<string, string> canonical lowercase name => value */
    private array $headers = [];

    /** @param array<string, string> $headers */
    public function __construct(array $headers = [])
    {
        foreach ($headers as $name => $value) {
            $this->headers[strtolower($name)] = $value;
        }
    }

    public function get(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function has(string $name): bool
    {
        return isset($this->headers[strtolower($name)]);
    }

    public function set(string $name, string $value): void
    {
        $this->headers[strtolower($name)] = $value;
    }

    public function remove(string $name): void
    {
        unset($this->headers[strtolower($name)]);
    }

    /** @return array<string, string> */
    public function all(): array
    {
        return $this->headers;
    }
}
