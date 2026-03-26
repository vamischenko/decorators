<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Encryption;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

/**
 * PSR-7 stream decorator that computes an HMAC over all bytes as they are read.
 * Adapted from jeskew/php-encrypted-streams (Apache 2.0).
 */
final class HashingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    /** @var StreamInterface */
    private StreamInterface $stream;

    private ?string $hash = null;
    private \HashContext $hashContext;

    /** @var callable|null */
    private $onComplete;

    /**
     * @param StreamInterface $stream     The underlying stream to read from and hash.
     * @param string|null     $key        HMAC key; if null, a plain hash (no HMAC) is computed.
     * @param callable|null   $onComplete Invoked with the raw binary hash once the stream reaches EOF.
     * @param string          $algorithm  Hash algorithm name accepted by hash_init() (default: 'sha256').
     */
    public function __construct(
        StreamInterface $stream,
        private readonly ?string $key = null,
        ?callable $onComplete = null,
        private readonly string $algorithm = 'sha256',
    ) {
        $this->stream = $stream;
        $this->onComplete = $onComplete;
        $this->initHash();
    }

    /** Returns the raw binary hash once the stream has been fully read, null otherwise. */
    public function getHash(): ?string
    {
        return $this->hash;
    }

    /**
     * Reads up to $length bytes, updating the running hash with each chunk.
     * Finalizes the hash and invokes the onComplete callback when EOF is reached.
     *
     * @param int $length Maximum number of bytes to return.
     * @return string The bytes read from the underlying stream.
     */
    public function read(int $length): string
    {
        $data = $this->stream->read($length);

        if (strlen($data) > 0) {
            hash_update($this->hashContext, $data);
        }

        if ($this->stream->eof()) {
            $this->hash = hash_final($this->hashContext, true);
            // Explicitly unset to prevent accidental reuse of an invalidated context
            unset($this->hashContext);
            if ($this->onComplete !== null) {
                ($this->onComplete)($this->hash);
            }
        }

        return $data;
    }

    /**
     * Rewinds the stream and resets the hash state (rewind only; arbitrary seeking is not supported).
     *
     * @throws \LogicException if offset is non-zero or whence is not SEEK_SET.
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->stream->seek($offset, $whence);
            $this->initHash();
        } else {
            throw new \LogicException('HashingStream only supports rewind, not arbitrary seeking.');
        }
    }

    private function initHash(): void
    {
        $this->hash = null;
        $this->hashContext = hash_init(
            $this->algorithm,
            $this->key !== null ? HASH_HMAC : 0,
            (string) $this->key,
        );
    }
}
