<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

final class Pickle
{
    private const WORK_BUDGET = 4096;

    private const MARK = "\0MARK";

    private string $data;
    private int $pos = 0;
    private array $stack = [];
    private array $metastack = [];

    private function __construct(string $data)
    {
        $this->data = $data;
    }

    private function read(int $size): string
    {
        if ($this->pos + $size > strlen($this->data)) {
            throw new \RuntimeException('short');
        }
        $out = substr($this->data, $this->pos, $size);
        $this->pos += $size;

        return $out;
    }

    private function readline(): string
    {
        $idx = strpos($this->data, "\n", $this->pos);
        if ($idx === false) {
            throw new \RuntimeException('short');
        }
        $line = substr($this->data, $this->pos, $idx - $this->pos + 1);
        $this->pos = $idx + 1;

        return $line;
    }

    private function popMark(): array
    {
        $k = count($this->stack) - 1;
        while ($k >= 0) {
            if ($this->stack[$k] === self::MARK) {
                $items = array_slice($this->stack, $k + 1);
                array_splice($this->stack, $k);

                return $items;
            }
            $k--;
        }
        throw new \RuntimeException('nomark');
    }

    private function step(): ?bool
    {
        $key = $this->read(1);
        $op = $key[0];
        switch ($op) {
            case '.':
                return true;
            case '(':
                $this->stack[] = self::MARK;
                break;
            case 'N':
                $this->stack[] = null;
                break;
            case 'S':
            case 'V':
            case 'T':
                $this->readline();
                $this->stack[] = 'obj';
                break;
            case 'U':
            case 'C':
            case "\x8c":
            case 'X':
            case "\x8a":
            case "\x8d":
            case 'G':
            case 'F':
            case 'I':
            case 'L':
            case "\x8e":
                $this->readArgForObj($op);
                $this->stack[] = 'obj';
                break;
            case 'K':
                $this->read(1);
                $this->stack[] = 'obj';
                break;
            case 'M':
                $this->read(2);
                $this->stack[] = 'obj';
                break;
            case 'J':
                $this->read(4);
                $this->stack[] = 'obj';
                break;
            case 'c':
                throw new \RuntimeException('blocked');
            case 'R':
                array_pop($this->stack);
                array_pop($this->stack);
                $this->stack[] = 'obj';
                break;
            case 'b':
                array_pop($this->stack);
                array_pop($this->stack);
                $this->stack[] = 'obj';
                break;
            case 'o':
            case "\x01":
                $this->popMark();
                $this->stack[] = 'obj';
                break;
            case 't':
            case 'l':
            case 'd':
            case ')':
            case ']':
            case '}':
            case "\x93":
                if (in_array($op, ['t', 'l', 'd', "\x93"], true)) {
                    $this->popMark();
                }
                $this->stack[] = 'obj';
                break;
            case 'e':
            case 'u':
                $this->popMark();
                break;
            case 'a':
            case 's':
                array_pop($this->stack);
                array_pop($this->stack);
                $this->stack[] = 'obj';
                break;
            case 'p':
            case 'q':
                $this->read(1);
                break;
            case 'r':
            case 'Q':
                $this->read(4);
                break;
            case 'g':
                $this->read(1);
                $this->stack[] = 'obj';
                break;
            case 'h':
                $this->read(1);
                $this->stack[] = 'obj';
                break;
            case 'j':
                $this->read(4);
                $this->stack[] = 'obj';
                break;
            case "\x80":
            case "\x95":
                $frame = $this->read($op === "\x80" ? 1 : 8);
                if ($op === "\x95") {
                    $this->pos += 0;
                }
                break;
            case "\x85":
                $this->read(1);
                $this->stack[] = 'obj';
                break;
            case "\x81":
            case "\x82":
            case "\x83":
            case "\x84":
            case "\x86":
            case "\x87":
            case "\x88":
            case "\x89":
            case "\x8f":
            case "\x90":
            case "\x91":
            case "\x92":
            case "\x94":
            case "\x96":
            case "\x97":
                if ($op === "\x8a") {
                    $this->read(1);
                }
                $this->stack[] = 'obj';
                break;
            default:
                return false;
        }

        return null;
    }

    private function readArgForObj(string $op): void
    {
        switch ($op) {
            case 'U':
            case 'C':
            case "\x8c":
                $this->read(ord($this->read(1)));
                break;
            case 'X':
            case "\x8a":
                $this->read(unpack('V', $this->read(4))[1]);
                break;
            case "\x8d":
                $this->read(unpack('P', $this->read(8))[1]);
                break;
            case 'G':
                $this->read(8);
                break;
            case 'F':
            case 'I':
            case 'L':
                $this->readline();
                break;
            case "\x8e":
                $this->read(1);
                break;
        }
    }

    private static function windowFromChars(string $text): ?string
    {
        $out = '';
        $n = Text::len($text);
        for ($i = 0; $i < $n; $i++) {
            $cp = Text::ordAt($text, $i);
            if ($cp <= 0xff) {
                $out .= chr($cp);
            } elseif ($cp >= 0xdc80 && $cp <= 0xdcff) {
                $out .= chr($cp - 0xdc80 + 0x80);
            } else {
                return null;
            }
        }

        return $out;
    }

    private static function walk(string $window, bool $complete, bool $suffixMode, bool $seedStack): bool|null
    {
        $vm = new self($window);
        if ($seedStack) {
            $vm->stack[] = 'obj';
        }
        $reachedReduceOrBuild = false;
        try {
            while ($vm->pos < strlen($vm->data)) {
                $peek = ord($vm->data[$vm->pos]);
                if ($suffixMode && ($peek === 0x52 || $peek === 0x62)) {
                    $reachedReduceOrBuild = true;
                    break;
                }
                if ($peek === 0x85) {
                    $vm->read(9);
                    continue;
                }
                if ($peek === 0x95) {
                    $vm->read(9);
                    continue;
                }
                $result = $vm->step();
                if ($result !== null) {
                    break;
                }
            }
        } catch (\RuntimeException $e) {
            return str_starts_with($e->getMessage(), 'blocked') || $e->getMessage() === 'nomark' ? false : ($complete ? false : null);
        }
        if ($suffixMode) {
            if ($reachedReduceOrBuild) {
                return true;
            }

            return $complete ? false : null;
        }

        return $complete ? true : null;
    }

    public static function globalPrefixIsOpcodeStream(string $prefix): bool
    {
        if ($prefix === '' || str_ends_with($prefix, "\n")) {
            return true;
        }
        $complete = Text::len($prefix) <= self::WORK_BUDGET;
        $slice = $complete ? $prefix : mb_strcut($prefix, 0, self::WORK_BUDGET, 'UTF-8');
        $window = self::windowFromChars($slice);
        if ($window === null) {
            return false;
        }

        return self::walk($window, $complete, false, false) !== false;
    }

    public static function globalSuffixReachesReduceOrBuild(string $suffix): bool
    {
        $complete = Text::len($suffix) <= self::WORK_BUDGET;
        $slice = $complete ? $suffix : mb_strcut($suffix, 0, self::WORK_BUDGET, 'UTF-8');
        $window = self::windowFromChars($slice);
        if ($window === null) {
            return false;
        }

        return self::walk($window, $complete, true, true) !== false;
    }

    public static function globalCandidateIsInjection(string $text, array $match): bool
    {
        $prefix = substr($text, 0, $match['start']);
        if (!self::globalPrefixIsOpcodeStream($prefix)) {
            return false;
        }

        return self::globalSuffixReachesReduceOrBuild(substr($text, $match['groups'][1]['end']));
    }
}
