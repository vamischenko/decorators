<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Stream;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Vamischenko\Decorators\ExpandedKey;
use Vamischenko\Decorators\Sidecar\SidecarContext;

/**
 * PSR-7 stream decorator that encrypts the underlying stream using WhatsApp's
 * AES-256-CBC algorithm.
 *
 * Output format: [ciphertext] [hmac-sha256 truncated to 10 bytes]
 *
 * The iv is NOT included in the output stream — it is derived from the mediaKey
 * via HKDF and must be kept alongside the key for decryption.
 *
 * The MAC is computed over (iv + ciphertext), so it covers the iv even though
 * the iv is not emitted.
 *
 * The sidecar (if provided) receives all bytes of the logical combined buffer
 * (iv + ciphertext + mac) to match the WhatsApp sidecar specification.
 *
 * The stream is forward-only (not seekable) because AES-CBC requires processing
 * from the beginning to maintain the cipher chain.
 */
final class EncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const AES_BLOCK_SIZE = 16;
    private const MAC_LENGTH     = 10;

    /** @var StreamInterface */
    private StreamInterface $stream;

    private string $outputBuffer   = '';
    private string $inputBuffer   = '';
    private bool $encryptionDone  = false;
    private bool $macEmitted      = false;
    private bool $sidecarFinalized = false;

    /** Current CBC chaining vector — starts as iv, updated after each block group */
    private string $lastCipherBlock;

    private \HashContext $macContext;

    public function __construct(
        StreamInterface $stream,
        private readonly ExpandedKey $key,
        private readonly ?SidecarContext $sidecar = null,
    ) {
        $this->stream = $stream;
        $this->lastCipherBlock = $key->iv;

        // MAC is computed over iv + ciphertext
        $this->macContext = hash_init('sha256', HASH_HMAC, $key->macKey);
        hash_update($this->macContext, $key->iv);

        // Sidecar's combined buffer starts with iv
        $this->sidecar?->feed($key->iv);
    }

    public function isSeekable(): bool
    {
        return false;
    }

    /**
     * Returns the exact encrypted output size if the source stream reports its size.
     * Formula: ceil(plainSize/16)*16 (PKCS7-padded ciphertext) + 10 (mac)
     */
    public function getSize(): ?int
    {
        $plainSize = $this->stream->getSize();
        if ($plainSize === null) {
            return null;
        }

        $ciphertextSize = (intdiv($plainSize, self::AES_BLOCK_SIZE) + 1) * self::AES_BLOCK_SIZE;

        return $ciphertextSize + self::MAC_LENGTH;
    }

    public function read(int $length): string
    {
        while (strlen($this->outputBuffer) < $length && !$this->macEmitted) {
            $this->produce();
        }

        $out = substr($this->outputBuffer, 0, $length);
        $this->outputBuffer = substr($this->outputBuffer, $length);

        $this->sidecar?->feed($out);

        // Finalize sidecar only after all bytes (including mac) have been fed
        if ($this->macEmitted && $this->outputBuffer === '' && !$this->sidecarFinalized) {
            $this->sidecarFinalized = true;
            $this->sidecar?->finalize();
        }

        return $out;
    }

    public function eof(): bool
    {
        return $this->macEmitted && $this->outputBuffer === '';
    }

    /**
     * Advances the internal state machine, appending bytes to the output buffer.
     *
     * State order: encrypt blocks → emit final padded block → emit mac
     */
    private function produce(): void
    {
        if (!$this->encryptionDone) {
            $this->encryptChunk();
            return;
        }

        // Finalize: append the 10-byte truncated HMAC
        $mac = substr(hash_final($this->macContext, true), 0, self::MAC_LENGTH);
        $this->outputBuffer .= $mac;
        $this->macEmitted = true;
        // Sidecar finalize() is called from read() after all bytes including mac are fed
    }

    private function encryptChunk(): void
    {
        $chunk = $this->stream->read(8192);
        $this->inputBuffer .= $chunk;

        if ($chunk === '' && $this->stream->eof()) {
            // Encrypt remaining bytes with PKCS7 padding (openssl adds it automatically)
            $ciphertext = openssl_encrypt(
                $this->inputBuffer,
                'aes-256-cbc',
                $this->key->cipherKey,
                OPENSSL_RAW_DATA,
                $this->lastCipherBlock,
            );

            if ($ciphertext === false) {
                throw new \RuntimeException('OpenSSL encryption failed: ' . openssl_error_string());
            }

            hash_update($this->macContext, $ciphertext);
            $this->outputBuffer .= $ciphertext;
            $this->inputBuffer = '';
            $this->encryptionDone = true;
            return;
        }

        // Process only complete 16-byte blocks; hold the remainder for the final padded block
        $completeBytes = intdiv(strlen($this->inputBuffer), self::AES_BLOCK_SIZE) * self::AES_BLOCK_SIZE;
        if ($completeBytes === 0) {
            return;
        }

        $toEncrypt = substr($this->inputBuffer, 0, $completeBytes);
        $this->inputBuffer = substr($this->inputBuffer, $completeBytes);

        // OPENSSL_ZERO_PADDING suppresses automatic PKCS7 padding for intermediate blocks
        $ciphertext = openssl_encrypt(
            $toEncrypt,
            'aes-256-cbc',
            $this->key->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->lastCipherBlock,
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('OpenSSL encryption failed: ' . openssl_error_string());
        }

        // Update the CBC chaining vector to the last produced ciphertext block
        $this->lastCipherBlock = substr($ciphertext, -self::AES_BLOCK_SIZE);

        hash_update($this->macContext, $ciphertext);
        $this->outputBuffer .= $ciphertext;
    }
}
