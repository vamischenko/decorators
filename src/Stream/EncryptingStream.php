<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Stream;

use GuzzleHttp\Psr7\AppendStream;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;
use Vamischenko\Decorators\Encryption\AesEncryptingStream;
use Vamischenko\Decorators\Encryption\Cbc;
use Vamischenko\Decorators\Encryption\HashingStream;
use Vamischenko\Decorators\ExpandedKey;
use Vamischenko\Decorators\Sidecar\SidecarContext;

/**
 * PSR-7 stream decorator that encrypts the underlying stream using WhatsApp's
 * AES-256-CBC algorithm.
 *
 * Output format: [ciphertext] [hmac-sha256 truncated to 10 bytes]
 *
 * Pipeline:
 *   source
 *   → AesEncryptingStream   (AES-256-CBC, cipherKey, iv)
 *   → AppendStream([iv, ciphertext])  — iv prepended so HMAC-SHA256 covers it
 *   → HashingStream         (HMAC-SHA256, macKey)
 *
 * The iv bytes are drained internally after HMAC computation but before
 * emitting bytes to callers. Callers only receive ciphertext + 10-byte MAC.
 * The stream is forward-only (not seekable).
 */
final class EncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const MAC_LENGTH = 10;

    /** @var StreamInterface */
    private StreamInterface $stream;

    private string $mac            = '';
    private bool $macEmitted       = false;
    private bool $sidecarFinalized = false;

    /** Output buffer: ciphertext bytes ready to be returned to callers */
    private string $outputBuffer = '';

    /** Number of iv bytes still to drain from the HashingStream output */
    private int $ivBytesToSkip;

    public function __construct(
        StreamInterface $source,
        private readonly ExpandedKey $key,
        private readonly ?SidecarContext $sidecar = null,
    ) {
        $this->ivBytesToSkip = \strlen($key->iv);

        // AES-256-CBC encryption
        $aesStream = new AesEncryptingStream($source, $key->cipherKey, new Cbc($key->iv));

        // Prepend iv so HMAC-SHA256 covers iv + ciphertext
        $combined = new AppendStream([
            Utils::streamFor($key->iv),
            $aesStream,
        ]);

        // HMAC-SHA256 over the combined stream; captures hash on EOF
        $this->stream = new HashingStream(
            $combined,
            $key->macKey,
            function (string $fullHash): void {
                $this->mac = \substr($fullHash, 0, self::MAC_LENGTH);
            },
        );

        // Sidecar's logical combined buffer starts with iv
        $this->sidecar?->feed($key->iv);
    }

    public function isSeekable(): bool
    {
        return false;
    }

    /**
     * Output size = ciphertext + 10-byte MAC.
     * HashingStream size = iv + ciphertext, so subtract iv length.
     */
    public function getSize(): ?int
    {
        $combinedSize = $this->stream->getSize();
        if ($combinedSize === null) {
            return null;
        }

        return $combinedSize - \strlen($this->key->iv) + self::MAC_LENGTH;
    }

    public function read(int $length): string
    {
        // Lazily populate the output buffer on first read by draining the full
        // pipeline. AesEncryptingStream reports eof() as soon as the plaintext
        // source is exhausted, even though its internal block buffer may still
        // hold bytes — so we must drain it in one shot rather than looping on eof().
        if (!$this->macEmitted && $this->outputBuffer === '') {
            $combined = Utils::copyToString($this->stream);

            // Strip the iv prefix (hashed but not emitted)
            $ciphertext = \substr($combined, \strlen($this->key->iv));

            $this->outputBuffer = $ciphertext . $this->mac;
            $this->macEmitted = true;

            $this->sidecar?->feed($ciphertext);
            $this->sidecar?->feed($this->mac);

            if (!$this->sidecarFinalized) {
                $this->sidecarFinalized = true;
                $this->sidecar?->finalize();
            }
        }

        $out = \substr($this->outputBuffer, 0, $length);
        $this->outputBuffer = \substr($this->outputBuffer, $length);

        return $out;
    }

    public function eof(): bool
    {
        return $this->stream->eof() && $this->macEmitted && $this->outputBuffer === '';
    }
}
