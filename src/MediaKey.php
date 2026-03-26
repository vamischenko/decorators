<?php

declare(strict_types=1);

namespace Vamischenko\Decorators;

use Vamischenko\Decorators\Exception\InvalidMediaKeyException;

final class MediaKey
{
    private const LENGTH = 32;

    private function __construct(private readonly string $bytes)
    {
    }

    public static function fromBinary(string $bytes): self
    {
        if (strlen($bytes) !== self::LENGTH) {
            throw new InvalidMediaKeyException(
                sprintf('MediaKey must be exactly %d bytes, %d given', self::LENGTH, strlen($bytes))
            );
        }

        return new self($bytes);
    }

    public static function generate(): self
    {
        return new self(random_bytes(self::LENGTH));
    }

    public function bytes(): string
    {
        return $this->bytes;
    }
}
