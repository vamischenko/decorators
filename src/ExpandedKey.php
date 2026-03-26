<?php

declare(strict_types=1);

namespace Vamischenko\Decorators;

final class ExpandedKey
{
    public function __construct(
        /** @var string 16 bytes — initialization vector for AES-CBC */
        public readonly string $iv,
        /** @var string 32 bytes — AES-256-CBC cipher key */
        public readonly string $cipherKey,
        /** @var string 32 bytes — HMAC-SHA256 signing key */
        public readonly string $macKey,
        /** @var string 32 bytes — reference key (unused per spec) */
        public readonly string $refKey,
    ) {
    }
}
