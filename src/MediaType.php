<?php

declare(strict_types=1);

namespace Vamischenko\Decorators;

enum MediaType: string
{
    case IMAGE    = 'WhatsApp Image Keys';
    case VIDEO    = 'WhatsApp Video Keys';
    case AUDIO    = 'WhatsApp Audio Keys';
    case DOCUMENT = 'WhatsApp Document Keys';

    public function supportsSidecar(): bool
    {
        return match ($this) {
            self::VIDEO, self::AUDIO => true,
            default                  => false,
        };
    }
}
