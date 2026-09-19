<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Redis;

class RespConnection
{
    /** @var resource|null */
    protected $stream = null;
    private string $host;
    private int $port;
    private float $connectTimeout;
    private float $timeout;

    public function __construct(
        string $host = '127.0.0.1',
        int $port = 6379,
        float $connectTimeout = 2.0,
        float $timeout = 2.0
    ) {
        $this->host = $host;
        $this->port = $port;
        $this->connectTimeout = $connectTimeout;
        $this->timeout = $timeout;
    }

    public function close(): void
    {
        if (is_resource($this->stream)) {
            fclose($this->stream);
        }
        $this->stream = null;
    }

    public function command(string ...$args): mixed
    {
        $this->writeCommands([$args]);

        return $this->readReplies(1)[0];
    }

    public function pipeline(): RespPipeline
    {
        return new RespPipeline($this);
    }

    public function ping(): void
    {
        $this->command('PING');
    }

    public function get(string $key): ?string
    {
        return $this->command('GET', $key);
    }

    public function set(string $key, string $value, ?int $ex = null, ?int $px = null): bool
    {
        $args = ['SET', $key, $value];
        if ($ex !== null) {
            $args[] = 'EX';
            $args[] = (string) $ex;
        } elseif ($px !== null) {
            $args[] = 'PX';
            $args[] = (string) $px;
        }

        return $this->command(...$args) === true;
    }

    public function del(string ...$keys): int
    {
        return (int) $this->command('DEL', ...$keys);
    }

    public function exists(string $key): bool
    {
        return (int) $this->command('EXISTS', $key) > 0;
    }

    /** @return list<string> */
    public function keys(string $pattern): array
    {
        $reply = $this->command('KEYS', $pattern);
        if (!is_array($reply)) {
            return [];
        }

        return array_map('strval', $reply);
    }

    /** @return array{0: string, 1: list<string>} */
    public function scan(string $cursor, string $pattern): array
    {
        $reply = $this->command('SCAN', $cursor, 'MATCH', $pattern);
        $keys = [];
        if (isset($reply[1]) && is_array($reply[1])) {
            $keys = array_map('strval', $reply[1]);
        }

        return [strval($reply[0] ?? '0'), $keys];
    }

    public function pttl(string $key): int
    {
        return (int) $this->command('PTTL', $key);
    }

    public function expire(string $key, int $seconds): bool
    {
        return (int) $this->command('EXPIRE', $key, (string) $seconds) === 1;
    }

    public function expireTime(string $key): int
    {
        return (int) $this->command('EXPIRETIME', $key);
    }

    public function incr(string $key): int
    {
        return (int) $this->command('INCR', $key);
    }

    public function zAdd(string $key, float $score, string $member): int
    {
        return (int) $this->command('ZADD', $key, $this->formatScore($score), $member);
    }

    public function zCard(string $key): int
    {
        return (int) $this->command('ZCARD', $key);
    }

    public function zRemRangeByScore(string $key, string $min, string $max): int
    {
        return (int) $this->command('ZREMRANGEBYSCORE', $key, $min, $max);
    }

    /** @return list<string> */
    public function zRangeByScore(string $key, string $min, string $max): array
    {
        $reply = $this->command('ZRANGEBYSCORE', $key, $min, $max);
        if (!is_array($reply)) {
            return [];
        }

        return array_map('strval', $reply);
    }

    public function evalSha(string $sha, int $numKeys, string ...$keysAndArgs): mixed
    {
        return $this->command('EVALSHA', $sha, (string) $numKeys, ...$keysAndArgs);
    }

    public function scriptLoad(string $script): string
    {
        return strval($this->command('SCRIPT', 'LOAD', $script));
    }

    protected function formatScore(float $score): string
    {
        $r = (string) $score;

        return $r;
    }

    protected function connect(): void
    {
        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client(
            sprintf('tcp://%s:%d', $this->host, $this->port),
            $errno,
            $errstr,
            $this->connectTimeout
        );
        if ($stream === false) {
            throw new GuardRedisException("Redis connection failed: {$errstr}");
        }
        if ($this->timeout > 0) {
            stream_set_timeout($stream, (int) $this->timeout, (int) (($this->timeout - (int) $this->timeout) * 1e6));
        }
        $this->stream = $stream;
    }

    /** @param list<list<string>> $commands */
    public function writeCommands(array $commands): void
    {
        if (!is_resource($this->stream)) {
            $this->connect();
        }
        $payload = '';
        foreach ($commands as $args) {
            $payload .= '*' . count($args) . "\r\n";
            foreach ($args as $arg) {
                $arg = (string) $arg;
                $payload .= '$' . strlen($arg) . "\r\n" . $arg . "\r\n";
            }
        }
        $total = strlen($payload);
        $written = 0;
        while ($written < $total) {
            $n = @fwrite($this->stream, substr($payload, $written));
            if ($n === false || $n === 0) {
                $meta = is_resource($this->stream) ? stream_get_meta_data($this->stream) : [];
                $this->close();
                $reason = ($meta['timed_out'] ?? false) ? 'socket timeout' : 'broken pipe';
                throw new GuardRedisException("Redis write failed: {$reason}");
            }
            $written += $n;
        }
    }

    /** @return list<mixed> */
    public function readReplies(int $count): array
    {
        $replies = [];
        for ($i = 0; $i < $count; $i++) {
            $replies[] = $this->readReply();
        }

        return $replies;
    }

    private function readReply(): mixed
    {
        $line = $this->readLine();
        if ($line === false || $line === '') {
            $this->close();
            throw new GuardRedisException('Redis read failed: empty reply (timeout or closed socket)');
        }
        $type = $line[0];
        $body = substr($line, 1, -2);
        switch ($type) {
            case '+':
                return $body;
            case '-':
                throw new GuardRedisException("Redis error reply: {$body}");
            case ':':
                return (int) $body;
            case '$':
                $len = (int) $body;
                if ($len === -1) {
                    return null;
                }
                return substr($this->readBytes($len + 2), 0, $len);
            case '*':
                $count = (int) $body;
                if ($count === -1) {
                    return null;
                }
                $items = [];
                for ($i = 0; $i < $count; $i++) {
                    $items[] = $this->readReply();
                }
                return $items;
            default:
                $this->close();
                throw new GuardRedisException("Redis protocol error: unknown reply type '{$type}'");
        }
    }

    private function readLine(): string|false
    {
        $line = fgets($this->stream);
        if ($line === false) {
            $meta = stream_get_meta_data($this->stream);
            if ($meta['timed_out'] ?? false) {
                throw new GuardRedisException('Redis read failed: socket timeout');
            }
        }

        return $line;
    }

    private function readBytes(int $n): string
    {
        $data = '';
        $remaining = $n;
        while ($remaining > 0) {
            $chunk = fread($this->stream, $remaining);
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($this->stream);
                $this->close();
                $reason = ($meta['timed_out'] ?? false) ? 'socket timeout' : 'stream closed';
                throw new GuardRedisException("Redis read failed: {$reason}");
            }
            $data .= $chunk;
            $remaining -= strlen($chunk);
        }
        return $data;
    }
}
