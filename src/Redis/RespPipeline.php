<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Redis;

final class RespPipeline
{
    /** @var list<list<string>> */
    private array $commands = [];
    private bool $multi = false;

    public function __construct(private RespConnection $connection)
    {
    }

    public function multi(): self
    {
        $this->multi = true;

        return $this;
    }

    public function queue(string ...$args): self
    {
        $this->commands[] = $args;

        return $this;
    }

    /** @return list<mixed> */
    public function execute(): array
    {
        $commands = $this->commands;
        $this->commands = [];
        if ($commands === []) {
            return [];
        }
        if ($this->multi) {
            $wire = [['MULTI'], ...$commands, ['EXEC']];
            $this->connection->writeCommands($wire);
            $replies = $this->connection->readReplies(count($wire));
            array_shift($replies);
            foreach ($replies as $reply) {
                if (is_object($reply) || (is_string($reply) && str_starts_with($reply, 'ERR'))) {
                    throw new GuardRedisException('Redis EXEC aborted: ' . var_export($reply, true));
                }
            }

            return $replies;
        }
        $this->connection->writeCommands($commands);

        return $this->connection->readReplies(count($commands));
    }

    public function get(string $key): self
    {
        return $this->queue('GET', $key);
    }

    public function set(string $key, string $value, ?int $ex = null, ?int $px = null): self
    {
        $args = ['SET', $key, $value];
        if ($ex !== null) {
            array_push($args, 'EX', (string) $ex);
        } elseif ($px !== null) {
            array_push($args, 'PX', (string) $px);
        }

        return $this->queue(...$args);
    }

    public function pttl(string $key): self
    {
        return $this->queue('PTTL', $key);
    }

    public function del(string ...$keys): self
    {
        return $this->queue('DEL', ...$keys);
    }

    public function expire(string $key, int $seconds): self
    {
        return $this->queue('EXPIRE', $key, (string) $seconds);
    }

    public function incr(string $key): self
    {
        return $this->queue('INCR', $key);
    }

    public function zAdd(string $key, float $score, string $member): self
    {
        return $this->queue('ZADD', $key, (string) $score, $member);
    }

    public function zRemRangeByScore(string $key, string $min, string $max): self
    {
        return $this->queue('ZREMRANGEBYSCORE', $key, $min, $max);
    }

    public function zCard(string $key): self
    {
        return $this->queue('ZCARD', $key);
    }
}
