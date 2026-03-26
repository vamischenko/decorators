<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Exception;

/** Thrown when the HMAC-SHA256 tag of an encrypted media stream fails verification. */
class MacVerificationException extends \RuntimeException
{
}
