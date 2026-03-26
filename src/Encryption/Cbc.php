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

    /**
     * @param string $iv      Initialization vector; length must match the OpenSSL requirement for the chosen key size.
     * @param int    $keySize AES key size in bits (128, 192, or 256).
     * @throws \InvalidArgumentException if the IV length does not match the cipher's requirement.
     */
    public function __construct(string $iv, private readonly int $keySize = 256)
    {
        if (strlen($iv) !== openssl_cipher_iv_length("aes-{$keySize}-cbc")) {
            throw new \InvalidArgumentException('Invalid initialization vector length');
        }

        $this->baseIv = $this->iv = $iv;
    }

    /** Returns the OpenSSL cipher name, e.g. "aes-256-cbc". */
    public function getOpenSslName(): string
    {
        return "aes-{$this->keySize}-cbc";
    }

    /** Returns the current IV, updated after each encrypted block. */
    public function getCurrentIv(): string
    {
        return $this->iv;
    }

    /** CBC mode always requires PKCS7 padding on the final block. */
    public function requiresPadding(): bool
    {
        return true;
    }

    /**
     * Resets the IV to the initial value (rewind only; arbitrary seeking is not supported).
     *
     * @throws \LogicException if offset is non-zero or whence is not SEEK_SET.
     */
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
