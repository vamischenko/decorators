<?php

declare(strict_types=1);

namespace Vamischenko\Decorators;

use Vamischenko\Decorators\Exception\InvalidMediaKeyException;

/**
 * Immutable value object representing a 32-byte WhatsApp media encryption key.
 */
final class MediaKey
{
    private const LENGTH = 32;

    private function __construct(private readonly string $bytes)
    {
    }

    /**
     * Creates a MediaKey from a raw binary string.
     *
     * @param string $bytes Exactly 32 raw bytes.
     * @throws InvalidMediaKeyException if the byte string is not exactly 32 bytes.
     */
    public static function fromBinary(string $bytes): self
    {
        if (strlen($bytes) !== self::LENGTH) {
            throw new InvalidMediaKeyException(
                sprintf('MediaKey must be exactly %d bytes, %d given', self::LENGTH, strlen($bytes))
            );
        }

        return new self($bytes);
    }

    /** Generates a cryptographically secure random 32-byte media key. */
    public static function generate(): self
    {
        return new self(random_bytes(self::LENGTH));
    }

    /** Returns the raw binary key bytes. */
    public function bytes(): string
    {
        return $this->bytes;
    }
}
