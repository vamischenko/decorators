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

    public function read(int $length): string
    {
        $data = $this->stream->read($length);

        if (strlen($data) > 0) {
            hash_update($this->hashContext, $data);
        }

        if ($this->stream->eof()) {
            $this->hash = hash_final($this->hashContext, true);
            if ($this->onComplete !== null) {
                ($this->onComplete)($this->hash);
            }
        }

        return $data;
    }

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
