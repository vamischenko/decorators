<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Encryption;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

/**
 * PSR-7 stream decorator that decrypts AES-256-CBC ciphertext block by block.
 *
 * Reads ciphertext from the underlying stream and returns plaintext
 * incrementally. PKCS7 padding is stripped from the final block automatically.
 *
 * The stream is forward-only (seeking is not supported).
 */
final class AesDecryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const BLOCK_SIZE = 16;

    /** @var StreamInterface */
    private StreamInterface $stream;

    /** Decrypted plaintext waiting to be returned via read(). */
    private string $plainBuffer = '';

    /** Ciphertext read ahead but not yet decrypted. Always 0 or BLOCK_SIZE bytes. */
    private string $cipherBuffer = '';

    private string $currentIv;
    private bool $finished = false;

    /**
     * @param StreamInterface $cipherText Source stream containing raw ciphertext bytes.
     * @param string          $key        Raw binary AES key (32 bytes for AES-256).
     * @param string          $iv         Initialization vector (16 bytes).
     */
    public function __construct(
        StreamInterface $cipherText,
        private readonly string $key,
        string $iv,
    ) {
        $this->stream    = $cipherText;
        $this->currentIv = $iv;
    }

    /** This stream is read-only; writes are not supported. */
    public function isWritable(): bool
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
     * Returns true only when all ciphertext has been decrypted and the plaintext
     * buffer has been fully consumed.
     */
    public function eof(): bool
    {
        return $this->finished && $this->plainBuffer === '';
    }

    /**
     * Reads up to $length plaintext bytes, decrypting ciphertext blocks as needed.
     *
     * @param int $length Maximum number of bytes to return.
     * @return string Decrypted plaintext bytes (may be shorter than $length near EOF).
     * @throws \RuntimeException if OpenSSL decryption fails.
     */
    public function read(int $length): string
    {
        while (\strlen($this->plainBuffer) < $length && !$this->finished) {
            $this->fillPlainBuffer();
        }

        $out             = \substr($this->plainBuffer, 0, $length);
        $this->plainBuffer = \substr($this->plainBuffer, $length);

        return $out !== false ? $out : '';
    }

    /**
     * Reads the next ciphertext block, decrypts it, and appends plaintext to $plainBuffer.
     *
     * Strategy: always keep one block buffered in $cipherBuffer. When we read another
     * block and the source is EOF, the buffered block is the last — decrypt it with
     * PKCS7 unpadding. Otherwise decrypt the buffered block without unpadding and
     * replace it with the newly read block.
     */
    private function fillPlainBuffer(): void
    {
        // Fill cipherBuffer to BLOCK_SIZE if empty
        if ($this->cipherBuffer === '') {
            $this->cipherBuffer = $this->readExact(self::BLOCK_SIZE);
            if ($this->cipherBuffer === '') {
                $this->finished = true;
                return;
            }
        }

        // Read the next block
        $next = $this->readExact(self::BLOCK_SIZE);

        if ($next === '' || $this->stream->eof() && \strlen($next) < self::BLOCK_SIZE) {
            // $cipherBuffer is the last block (or $next completes the tail together with cipherBuffer)
            $toDecrypt = $this->cipherBuffer . $next;
            $options   = OPENSSL_RAW_DATA; // enables PKCS7 unpadding
            $this->cipherBuffer = '';
            $this->finished     = true;
        } else {
            // More data follows — decrypt $cipherBuffer without removing padding
            $toDecrypt          = $this->cipherBuffer;
            $options            = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
            $this->cipherBuffer = $next;
        }

        $nextIv    = \substr($toDecrypt, -self::BLOCK_SIZE);
        $plaintext = openssl_decrypt($toDecrypt, 'aes-256-cbc', $this->key, $options, $this->currentIv);

        if ($plaintext === false) {
            throw new \RuntimeException('OpenSSL decryption failed: ' . openssl_error_string());
        }

        $this->currentIv    = $nextIv;
        $this->plainBuffer .= $plaintext;
    }

    /**
     * Reads exactly $length bytes from the underlying stream (or fewer at EOF).
     */
    private function readExact(int $length): string
    {
        $data = '';
        while (\strlen($data) < $length && !$this->stream->eof()) {
            $data .= $this->stream->read($length - \strlen($data));
        }
        return $data;
    }
}
