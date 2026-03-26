<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Encryption;

/**
 * Adapted from jeskew/php-encrypted-streams (Apache 2.0).
 */
interface CipherMethod
{
    public function getOpenSslName(): string;

    public function getCurrentIv(): string;

    public function requiresPadding(): bool;

    public function seek(int $offset, int $whence = SEEK_SET): void;

    public function update(string $cipherTextBlock): void;
}
