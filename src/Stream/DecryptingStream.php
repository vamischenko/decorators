<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Stream;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Vamischenko\Decorators\ExpandedKey;
use Vamischenko\Decorators\Exception\MacVerificationException;

/**
 * PSR-7 stream decorator that decrypts a WhatsApp-encrypted stream.
 *
 * Input format: [ciphertext] [hmac-sha256 truncated to 10 bytes]
 * (The iv is not part of the stream — it comes from the expanded key.)
 *
 * MAC is verified before any decrypted bytes are returned (integrity-first).
 * For seekable streams with a known size the MAC is read from the tail without
 * buffering the entire ciphertext. For non-seekable streams the full content is
 * buffered (unavoidable when MAC is at the end).
 */
final class DecryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const MAC_LENGTH = 10;

    /** @var StreamInterface */
    private StreamInterface $stream;

    private bool $initialized  = false;
    private string $outputBuffer = '';
    private bool $done          = false;

    public function __construct(
        StreamInterface $stream,
        private readonly ExpandedKey $key,
    ) {
        $this->stream = $stream;
    }

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

    public function read(int $length): string
    {
        if (!$this->initialized) {
            $this->initialize();
        }

        $out = substr($this->outputBuffer, 0, $length);
        $this->outputBuffer = substr($this->outputBuffer, $length);

        return $out;
    }

    public function eof(): bool
    {
        return $this->initialized && $this->done && $this->outputBuffer === '';
    }

    private function initialize(): void
    {
        if ($this->stream->isSeekable() && $this->stream->getSize() !== null) {
            $this->initializeFromSeekable();
        } else {
            $this->initializeFromBuffer();
        }

        $this->initialized = true;
        $this->done = true;
    }

    /**
     * Optimized path for seekable streams: seeks to the tail to read the MAC,
     * then rewinds and reads the ciphertext for verification, avoiding a second
     * full read for decryption.
     */
    private function initializeFromSeekable(): void
    {
        $size = $this->stream->getSize();
        $ciphertextSize = $size - self::MAC_LENGTH;

        // Read MAC from the tail
        $this->stream->seek($ciphertextSize);
        $mac = $this->stream->read(self::MAC_LENGTH);
        $this->stream->rewind();

        // Read ciphertext for HMAC verification
        $ciphertext = $this->stream->read($ciphertextSize);

        $this->verifyMac($ciphertext, $mac);

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-cbc', $this->key->cipherKey, OPENSSL_RAW_DATA, $this->key->iv);
        if ($plaintext === false) {
            throw new \RuntimeException('OpenSSL decryption failed: ' . openssl_error_string());
        }

        $this->outputBuffer = $plaintext;
    }

    /**
     * Fallback path for non-seekable streams: buffers the entire encrypted content,
     * then verifies the MAC and decrypts.
     */
    private function initializeFromBuffer(): void
    {
        $encrypted = '';
        while (!$this->stream->eof()) {
            $encrypted .= $this->stream->read(8192);
        }

        $mac        = substr($encrypted, -self::MAC_LENGTH);
        $ciphertext = substr($encrypted, 0, -self::MAC_LENGTH);

        $this->verifyMac($ciphertext, $mac);

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-cbc', $this->key->cipherKey, OPENSSL_RAW_DATA, $this->key->iv);
        if ($plaintext === false) {
            throw new \RuntimeException('OpenSSL decryption failed: ' . openssl_error_string());
        }

        $this->outputBuffer = $plaintext;
    }

    /**
     * @throws MacVerificationException when the HMAC does not match (tampered or corrupt data)
     */
    private function verifyMac(string $ciphertext, string $mac): void
    {
        $expected = substr(hash_hmac('sha256', $this->key->iv . $ciphertext, $this->key->macKey, true), 0, self::MAC_LENGTH);

        // hash_equals provides constant-time comparison to prevent timing attacks
        if (!hash_equals($expected, $mac)) {
            throw new MacVerificationException('MAC verification failed: encrypted media is corrupt or tampered');
        }
    }
}
