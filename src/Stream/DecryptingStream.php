<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Stream;

use GuzzleHttp\Psr7\AppendStream;
use GuzzleHttp\Psr7\LimitStream;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;
use Vamischenko\Decorators\Encryption\AesDecryptingStream;
use Vamischenko\Decorators\Encryption\HashingStream;
use Vamischenko\Decorators\ExpandedKey;
use Vamischenko\Decorators\Exception\MacVerificationException;

/**
 * PSR-7 stream decorator that decrypts a WhatsApp-encrypted stream.
 *
 * Input format: [ciphertext] [hmac-sha256 truncated to 10 bytes]
 * (The IV is not part of the stream — it comes from the expanded key.)
 *
 * MAC is verified before any plaintext bytes are returned (integrity-first).
 * Uses constant-time hash_equals() comparison to prevent timing attacks.
 *
 * Streaming behaviour:
 *   - Seekable streams (e.g. file handles): MAC is read from the tail via seek,
 *     then the ciphertext is decrypted incrementally through AesDecryptingStream.
 *     Memory usage is O(block size), not O(file size).
 *   - Non-seekable streams (e.g. HTTP response bodies): the entire ciphertext
 *     must be buffered first (MAC sits at the tail — verification requires it).
 *     After MAC verification the buffered ciphertext is wrapped in a stream and
 *     decrypted incrementally; no second full copy is made.
 *     For memory-constrained environments, wrap the source in a temp-file stream
 *     before passing it to DecryptingStream.
 *
 * The stream is forward-only (seeking is not supported).
 */
final class DecryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const MAC_LENGTH = 10;

    /** @var StreamInterface */
    private StreamInterface $stream;

    private bool $initialized = false;

    /**
     * @param StreamInterface $source Encrypted source stream (format: ciphertext + 10-byte MAC).
     * @param ExpandedKey     $key    Expanded key material used for MAC verification and decryption.
     */
    public function __construct(
        StreamInterface $source,
        private readonly ExpandedKey $key,
    ) {
        // Placeholder until initialize() builds the real decryption stream.
        $this->stream = $source;
    }

    /** This stream is forward-only; seeking is not supported. */
    public function isSeekable(): bool
    {
        return false;
    }

    /**
     * Plaintext size cannot be determined without decrypting (PKCS7 padding is 1–16 bytes).
     */
    public function getSize(): ?int
    {
        return null;
    }

    /**
     * Reads up to $length plaintext bytes.
     * Triggers MAC verification and sets up the decryption pipeline on the first call.
     *
     * @param int $length Maximum number of bytes to return.
     * @return string Decrypted plaintext bytes.
     * @throws MacVerificationException if the MAC does not match.
     * @throws \RuntimeException if OpenSSL decryption fails.
     */
    public function read(int $length): string
    {
        if (!$this->initialized) {
            $this->initialize();
        }

        return $this->stream->read($length);
    }

    /** Returns true once the decryption stream is exhausted. */
    public function eof(): bool
    {
        return $this->initialized && $this->stream->eof();
    }

    private function initialize(): void
    {
        if ($this->stream->isSeekable() && $this->stream->getSize() !== null) {
            $this->initializeFromSeekable();
        } else {
            $this->initializeFromBuffer();
        }

        $this->initialized = true;
    }

    /**
     * Seekable path: reads the MAC from the tail via seek, verifies it by
     * streaming iv + ciphertext through HMAC-SHA256, then rewinds and builds
     * an AesDecryptingStream over the ciphertext — true streaming decryption.
     */
    private function initializeFromSeekable(): void
    {
        $size           = $this->stream->getSize();
        $ciphertextSize = $size - self::MAC_LENGTH;

        // Read MAC from the tail
        $this->stream->seek($ciphertextSize);
        $mac = $this->readExact($this->stream, self::MAC_LENGTH);

        // Verify MAC by streaming iv + ciphertext through HMAC (no extra copy)
        $this->stream->rewind();
        $ciphertextStream = new LimitStream($this->stream, $ciphertextSize);

        // Build iv + ciphertext stream for HMAC
        $ivStream   = Utils::streamFor($this->key->iv);
        $hmacInput  = new AppendStream([$ivStream, $ciphertextStream]);
        $computedMac = '';
        $hashing = new HashingStream(
            $hmacInput,
            $this->key->macKey,
            function (string $hash) use (&$computedMac): void {
                $computedMac = \substr($hash, 0, self::MAC_LENGTH);
            },
        );
        while (!$hashing->eof()) {
            $hashing->read(8192);
        }

        if (!hash_equals($computedMac, $mac)) {
            throw new MacVerificationException('MAC verification failed: encrypted media is corrupt or tampered');
        }

        // Rewind and build incremental decryption stream over the ciphertext
        $this->stream->rewind();
        $ciphertextOnly = new LimitStream($this->stream, $ciphertextSize);

        $this->stream = new AesDecryptingStream($ciphertextOnly, $this->key->cipherKey, $this->key->iv);
    }

    /**
     * Non-seekable path: buffers the entire ciphertext (MAC is at the tail),
     * verifies the MAC, then wraps the buffer in AesDecryptingStream for
     * incremental plaintext delivery — no second full copy is made.
     */
    private function initializeFromBuffer(): void
    {
        $encrypted = '';
        while (!$this->stream->eof()) {
            $encrypted .= $this->stream->read(8192);
        }

        $mac        = \substr($encrypted, -self::MAC_LENGTH);
        $ciphertext = \substr($encrypted, 0, -self::MAC_LENGTH);
        unset($encrypted); // release the combined buffer

        $expected = \substr(
            hash_hmac('sha256', $this->key->iv . $ciphertext, $this->key->macKey, true),
            0,
            self::MAC_LENGTH,
        );

        if (!hash_equals($expected, $mac)) {
            throw new MacVerificationException('MAC verification failed: encrypted media is corrupt or tampered');
        }

        $this->stream = new AesDecryptingStream(
            Utils::streamFor($ciphertext),
            $this->key->cipherKey,
            $this->key->iv,
        );
    }

    /**
     * Reads exactly $length bytes from a stream (or fewer at EOF).
     */
    private function readExact(StreamInterface $stream, int $length): string
    {
        $data = '';
        while (\strlen($data) < $length && !$stream->eof()) {
            $data .= $stream->read($length - \strlen($data));
        }
        return $data;
    }
}
