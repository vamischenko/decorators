<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Sidecar;

/**
 * Generates sidecar data for streamable WhatsApp media (VIDEO and AUDIO).
 *
 * The sidecar enables random-offset decryption (seeking) without downloading
 * the full file. It is built by signing every [n*64K, (n+1)*64K+16] byte slice
 * of the combined stream (iv + ciphertext + mac) with HMAC-SHA256 and truncating
 * each signature to 10 bytes.
 *
 * Chunks overlap: chunk n covers [n*64K, (n+1)*64K+16], so the last 16 bytes
 * of chunk n are the first 16 bytes of chunk n+1. This is tracked via
 * $overlapBuffer which carries those bytes across the chunk boundary.
 *
 * Usage: pass an instance to EncryptingStream; after all data is read from the
 * stream, call getSidecar() to retrieve the accumulated sidecar bytes.
 * No additional reads from the source stream are required.
 */
final class SidecarContext
{
    private const CHUNK_SIZE = 65536; // 64 KiB
    private const OVERLAP    = 16;    // one AES block — allows CBC decryption at chunk boundaries
    private const MAC_BYTES  = 10;

    private string $sidecar      = '';
    private int $chunkIndex      = 0;
    private int $bytesInChunk    = 0; // bytes fed into current chunk's HMAC so far
    private ?\HashContext $hmac  = null;
    private bool $finalized      = false;

    /** Last OVERLAP bytes of the previous chunk, re-fed into the next chunk's HMAC */
    private string $overlapBuffer = '';

    /** Rolling buffer of last OVERLAP bytes of all data fed so far */
    private string $tailBuffer = '';

    /**
     * @param string $macKey 32-byte HMAC-SHA256 key used to sign each chunk.
     */
    public function __construct(private readonly string $macKey)
    {
    }

    /**
     * Feed bytes from the combined buffer (iv + ciphertext + mac, in order).
     * Called automatically by EncryptingStream.
     */
    public function feed(string $data): void
    {
        $pos = 0;
        $len = strlen($data);

        while ($pos < $len) {
            if ($this->hmac === null) {
                $this->hmac = hash_init('sha256', HASH_HMAC, $this->macKey);
                // Re-feed the overlap bytes carried over from the previous chunk
                if ($this->overlapBuffer !== '') {
                    hash_update($this->hmac, $this->overlapBuffer);
                    $this->bytesInChunk = strlen($this->overlapBuffer);
                }
            }

            $chunkCapacity = self::CHUNK_SIZE + self::OVERLAP - $this->bytesInChunk;
            $available     = $len - $pos;
            $feed          = min($available, $chunkCapacity);

            hash_update($this->hmac, substr($data, $pos, $feed));
            $this->bytesInChunk += $feed;
            $pos                += $feed;

            if ($this->bytesInChunk >= self::CHUNK_SIZE + self::OVERLAP) {
                // The last OVERLAP bytes of this chunk become the start of the next chunk.
                // Update tailBuffer first so it reflects the bytes up to $pos.
                $this->tailBuffer    = substr($this->tailBuffer . substr($data, 0, $pos), -(self::OVERLAP));
                $this->overlapBuffer = $this->tailBuffer;
                $this->finalizeChunk();
            }
        }

        // Keep a rolling buffer of the last OVERLAP bytes of all data seen so far
        $this->tailBuffer = substr($this->tailBuffer . $data, -(self::OVERLAP));
    }

    /**
     * Finalizes the last (possibly partial) chunk.
     * EncryptingStream calls this automatically after all data has been fed.
     */
    public function finalize(): void
    {
        if ($this->finalized) {
            return;
        }
        $this->finalized = true;
        if ($this->hmac !== null) {
            $this->finalizeChunk();
        }
    }

    /**
     * Returns the accumulated sidecar bytes (concatenated 10-byte chunk MACs).
     * Call only after finalize() has been invoked.
     */
    public function getSidecar(): string
    {
        return $this->sidecar;
    }

    private function finalizeChunk(): void
    {
        $this->sidecar .= substr(hash_final($this->hmac, true), 0, self::MAC_BYTES);
        $this->hmac         = null;
        $this->bytesInChunk = 0;
        $this->chunkIndex++;
    }
}
