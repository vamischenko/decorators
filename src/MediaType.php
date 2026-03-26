<?php

declare(strict_types=1);

namespace Vamischenko\Decorators;

/**
 * Represents the WhatsApp media type, providing the HKDF info string used during key expansion.
 */
enum MediaType: string
{
    case IMAGE    = 'WhatsApp Image Keys';
    case VIDEO    = 'WhatsApp Video Keys';
    case AUDIO    = 'WhatsApp Audio Keys';
    case DOCUMENT = 'WhatsApp Document Keys';

    /** Returns true for media types that require a sidecar file (VIDEO and AUDIO). */
    public function supportsSidecar(): bool
    {
        return match ($this) {
            self::VIDEO, self::AUDIO => true,
            default                  => false,
        };
    }
}
