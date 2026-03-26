<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Encryption;

/**
 * AES-CBC cipher method with IV chaining.
 * Adapted from jeskew/php-encrypted-streams (Apache 2.0).
 */
final class Cbc implements CipherMethod
{
    private const BLOCK_SIZE = 16;

    private string $baseIv;
    private string $iv;

    public function __construct(string $iv, private readonly int $keySize = 256)
    {
        if (strlen($iv) !== openssl_cipher_iv_length("aes-{$keySize}-cbc")) {
            throw new \InvalidArgumentException('Invalid initialization vector length');
        }

        $this->baseIv = $this->iv = $iv;
    }

    public function getOpenSslName(): string
    {
        return "aes-{$this->keySize}-cbc";
    }

    public function getCurrentIv(): string
    {
        return $this->iv;
    }

    public function requiresPadding(): bool
    {
        return true;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->iv = $this->baseIv;
        } else {
            throw new \LogicException('CBC only supports rewind, not arbitrary seeking.');
        }
    }

    /** Updates the IV to the last block of ciphertext for CBC chaining. */
    public function update(string $cipherTextBlock): void
    {
        $this->iv = substr($cipherTextBlock, self::BLOCK_SIZE * -1);
    }
}
