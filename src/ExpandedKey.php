<?php

declare(strict_types=1);

namespace Vamischenko\Decorators;

/**
 * Holds the 112-byte HKDF-expanded key material split into its four named segments.
 */
final class ExpandedKey
{
    /**
     * @param string $iv        16 bytes — initialization vector for AES-CBC.
     * @param string $cipherKey 32 bytes — AES-256-CBC cipher key.
     * @param string $macKey    32 bytes — HMAC-SHA256 signing key.
     * @param string $refKey    32 bytes — reference key (unused per spec).
     */
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
