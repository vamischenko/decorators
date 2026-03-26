<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Encryption;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

/**
 * PSR-7 stream decorator that encrypts using AES with a given cipher method.
 * Adapted from jeskew/php-encrypted-streams (Apache 2.0).
 */
final class AesEncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const BLOCK_SIZE = 16;

    /** @var StreamInterface */
    private StreamInterface $stream;

    private string $buffer = '';
    private CipherMethod $cipherMethod;

    /**
     * @param StreamInterface $plainText    Source stream containing data to encrypt.
     * @param string          $key          Raw binary cipher key (length must match the chosen cipher).
     * @param CipherMethod    $cipherMethod Cipher configuration; cloned so the caller's instance is unaffected.
     */
    public function __construct(
        StreamInterface $plainText,
        private readonly string $key,
        CipherMethod $cipherMethod,
    ) {
        $this->stream = $plainText;
        $this->cipherMethod = clone $cipherMethod;
    }

    /**
     * Returns the encrypted output size, accounting for PKCS7 padding when the cipher requires it.
     *
     * @return int|null null if the plaintext size is unknown.
     */
    public function getSize(): ?int
    {
        $plainTextSize = $this->stream->getSize();

        if ($this->cipherMethod->requiresPadding() && $plainTextSize !== null) {
            $padding = self::BLOCK_SIZE - $plainTextSize % self::BLOCK_SIZE;
            return $plainTextSize + $padding;
        }

        return $plainTextSize;
    }

    /** This stream is read-only; writes are not supported. */
    public function isWritable(): bool
    {
        return false;
    }

    /**
     * Returns true only when the plaintext source is exhausted AND the internal
     * ciphertext buffer has been fully consumed. StreamDecoratorTrait delegates
     * eof() to the underlying stream, which reports true as soon as plaintext is
     * read — even if encrypted bytes are still buffered.
     */
    public function eof(): bool
    {
        return $this->stream->eof() && $this->buffer === '';
    }

    /**
     * Reads up to $length encrypted bytes, filling the internal buffer by encrypting plaintext blocks as needed.
     *
     * @param int $length Maximum number of bytes to return.
     * @return string Raw encrypted bytes (may be shorter than $length near EOF).
     */
    public function read(int $length): string
    {
        if ($length > strlen($this->buffer)) {
            $this->buffer .= $this->encryptBlock(
                self::BLOCK_SIZE * (int) ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
            );
        }

        $data = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);

        return $data !== false ? $data : '';
    }

    /**
     * Seeks to the given offset within the encrypted stream.
     *
     * @param int $offset Byte offset to seek to.
     * @param int $whence SEEK_SET or SEEK_CUR; SEEK_END is not supported.
     * @throws \LogicException if an unsupported whence value is provided.
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        if ($whence === SEEK_CUR) {
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }

        if ($whence === SEEK_SET) {
            $this->buffer = '';
            $wholeBlockOffset = (int) ($offset / self::BLOCK_SIZE) * self::BLOCK_SIZE;
            $this->stream->seek($wholeBlockOffset);
            $this->cipherMethod->seek($wholeBlockOffset);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new \LogicException('Unrecognized whence.');
        }
    }

    private function encryptBlock(int $length): string
    {
        if ($this->stream->eof()) {
            return '';
        }

        $plainText = '';
        do {
            $plainText .= $this->stream->read($length - strlen($plainText));
        } while (strlen($plainText) < $length && !$this->stream->eof());

        $options = OPENSSL_RAW_DATA;
        if (!$this->stream->eof()) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        $cipherText = openssl_encrypt(
            $plainText,
            $this->cipherMethod->getOpenSslName(),
            $this->key,
            $options,
            $this->cipherMethod->getCurrentIv(),
        );

        if ($cipherText === false) {
            throw new \RuntimeException('OpenSSL encryption failed: ' . openssl_error_string());
        }

        $this->cipherMethod->update($cipherText);

        return $cipherText;
    }
}
