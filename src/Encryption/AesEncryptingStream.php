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

    public function __construct(
        StreamInterface $plainText,
        private readonly string $key,
        CipherMethod $cipherMethod,
    ) {
        $this->stream = $plainText;
        $this->cipherMethod = clone $cipherMethod;
    }

    public function getSize(): ?int
    {
        $plainTextSize = $this->stream->getSize();

        if ($this->cipherMethod->requiresPadding() && $plainTextSize !== null) {
            $padding = self::BLOCK_SIZE - $plainTextSize % self::BLOCK_SIZE;
            return $plainTextSize + $padding;
        }

        return $plainTextSize;
    }

    public function isWritable(): bool
    {
        return false;
    }

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
