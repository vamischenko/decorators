<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Encryption;

/**
 * Abstraction over a symmetric block cipher mode used by AesEncryptingStream.
 * Adapted from jeskew/php-encrypted-streams (Apache 2.0).
 */
interface CipherMethod
{
    /** Returns the OpenSSL cipher name (e.g. "aes-256-cbc"). */
    public function getOpenSslName(): string;

    /** Returns the current IV to be passed to the next openssl_encrypt call. */
    public function getCurrentIv(): string;

    /** Returns true if the cipher mode requires PKCS7 padding on the final block. */
    public function requiresPadding(): bool;

    /**
     * Seeks the cipher state to the given stream offset.
     *
     * @param int $offset Byte offset within the ciphertext stream.
     * @param int $whence One of SEEK_SET, SEEK_CUR, or SEEK_END.
     */
    public function seek(int $offset, int $whence = SEEK_SET): void;

    /**
     * Advances internal cipher state after a block has been encrypted.
     *
     * @param string $cipherTextBlock The most recently produced ciphertext block.
     */
    public function update(string $cipherTextBlock): void;
}
