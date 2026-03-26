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
 * The iv bytes pass through HashingStream (counted in MAC) but are skipped in
 * read() output — callers receive only ciphertext + 10-byte MAC.
 *
 * Data is streamed incrementally: no more than one internal read-buffer is held
 * in memory at a time. The 10-byte MAC is buffered only after the last block.
 *
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

    /**
     * Small carry-buffer for leftovers between read() calls.
     * At most (MAC_LENGTH - 1) bytes at any time.
     */
    private string $carryBuffer = '';

    /** Number of iv bytes still to drain from the start of the HashingStream output */
    private int $ivBytesToSkip;

    /**
     * @param StreamInterface     $source  Plaintext source stream.
     * @param ExpandedKey         $key     Expanded key material (iv, cipherKey, macKey).
     * @param SidecarContext|null $sidecar Optional sidecar accumulator for VIDEO/AUDIO seek support.
     */
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

        // HMAC-SHA256 over the combined stream; captures the hash when EOF is reached
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

    /** This stream is forward-only; seeking is not supported. */
    public function isSeekable(): bool
    {
        return false;
    }

    /**
     * Output size = ciphertext + 10-byte MAC.
     * HashingStream wraps iv + ciphertext, so subtract the iv length.
     */
    public function getSize(): ?int
    {
        $combinedSize = $this->stream->getSize();
        if ($combinedSize === null) {
            return null;
        }

        return $combinedSize - \strlen($this->key->iv) + self::MAC_LENGTH;
    }

    /**
     * Reads up to $length bytes of encrypted output (ciphertext, then 10-byte MAC).
     *
     * @param int $length Maximum number of bytes to return.
     * @return string Encrypted bytes; empty string when the stream is exhausted.
     */
    public function read(int $length): string
    {
        $out = $this->carryBuffer;
        $this->carryBuffer = '';

        // Read ciphertext from the pipeline until we have enough or source is done
        while (\strlen($out) < $length && !$this->stream->eof()) {
            $data = $this->stream->read($length - \strlen($out) + $this->ivBytesToSkip);

            // Discard iv bytes that appear at the front of the HashingStream output
            if ($this->ivBytesToSkip > 0) {
                $skip = \min($this->ivBytesToSkip, \strlen($data));
                $data = \substr($data, $skip);
                $this->ivBytesToSkip -= $skip;
            }

            $out .= $data;
            $this->sidecar?->feed($data);
        }

        // After ciphertext is exhausted, append the 10-byte truncated MAC
        if ($this->stream->eof() && !$this->macEmitted) {
            $out .= $this->mac;
            $this->macEmitted = true;

            $this->sidecar?->feed($this->mac);

            if (!$this->sidecarFinalized) {
                $this->sidecarFinalized = true;
                $this->sidecar?->finalize();
            }
        }

        // If we produced more bytes than requested (e.g. iv skip returned extras),
        // save the overflow for the next read() call
        if (\strlen($out) > $length) {
            $this->carryBuffer = \substr($out, $length);
            $out = \substr($out, 0, $length);
        }

        return $out;
    }

    /** Returns true only after the ciphertext, the 10-byte MAC, and any carry buffer have all been consumed. */
    public function eof(): bool
    {
        return $this->stream->eof() && $this->macEmitted && $this->carryBuffer === '';
    }
}
