<?php

declare(strict_types=1);

namespace Vamischenko\Decorators;

/**
 * Derives the four-part expanded key from a MediaKey using HKDF-SHA-256.
 */
final class KeyExpander
{
    private const EXPANDED_LENGTH = 112;

    /**
     * Expands a 32-byte mediaKey to 112 bytes using HKDF with SHA-256.
     * Empty-string salt follows RFC 5869: treat as HashLen zero bytes.
     *
     * @param MediaKey  $mediaKey  The 32-byte media encryption key.
     * @param MediaType $mediaType Provides the HKDF info string (context label).
     * @return ExpandedKey The derived key material split into iv, cipherKey, macKey, and refKey.
     */
    public function expand(MediaKey $mediaKey, MediaType $mediaType): ExpandedKey
    {
        $expanded = hash_hkdf('sha256', $mediaKey->bytes(), self::EXPANDED_LENGTH, $mediaType->value, '');

        return new ExpandedKey(
            iv:        substr($expanded,  0, 16),
            cipherKey: substr($expanded, 16, 32),
            macKey:    substr($expanded, 48, 32),
            refKey:    substr($expanded, 80, 32),
        );
    }
}
