<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Vamischenko\Decorators\Encryption\Cbc;
use Vamischenko\Decorators\KeyExpander;
use Vamischenko\Decorators\MediaKey;
use Vamischenko\Decorators\MediaType;
use Vamischenko\Decorators\Sidecar\SidecarContext;
use Vamischenko\Decorators\Stream\DecryptingStream;
use Vamischenko\Decorators\Stream\EncryptingStream;

/**
 * Tests covering streaming correctness, edge cases, and auxiliary classes.
 */
class StreamingTest extends TestCase
{
    private KeyExpander $expander;
    private string $samplesDir;

    protected function setUp(): void
    {
        $this->expander   = new KeyExpander();
        $this->samplesDir = dirname(__DIR__) . '/samples';
    }

    // -------------------------------------------------------------------------
    // EncryptingStream — small chunk reads
    // -------------------------------------------------------------------------

    /**
     * @dataProvider smallChunkProvider
     */
    public function testEncryptImageWithSmallChunks(int $chunkSize): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        $source = Utils::streamFor(file_get_contents($this->samplesDir . '/IMAGE.original'));
        $stream = new EncryptingStream($source, $expanded);

        $result = '';
        while (!$stream->eof()) {
            $result .= $stream->read($chunkSize);
        }

        self::assertSame(file_get_contents($this->samplesDir . '/IMAGE.encrypted'), $result);
    }

    /**
     * @dataProvider smallChunkProvider
     */
    public function testVideoSidecarWithSmallChunks(int $chunkSize): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/VIDEO.key'));
        $expanded = $this->expander->expand($key, MediaType::VIDEO);

        $source  = Utils::streamFor(file_get_contents($this->samplesDir . '/VIDEO.original'));
        $sidecar = new SidecarContext($expanded->macKey);
        $stream  = new EncryptingStream($source, $expanded, $sidecar);

        while (!$stream->eof()) {
            $stream->read($chunkSize);
        }

        self::assertSame(
            file_get_contents($this->samplesDir . '/VIDEO.sidecar'),
            $sidecar->getSidecar(),
        );
    }

    public static function smallChunkProvider(): array
    {
        return [
            '1 byte'   => [1],
            '7 bytes'  => [7],
            '13 bytes' => [13],
            '17 bytes' => [17],
        ];
    }

    // -------------------------------------------------------------------------
    // EncryptingStream — memory: no full-file buffering
    // -------------------------------------------------------------------------

    public function testEncryptingStreamDoesNotBufferFullFile(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/VIDEO.key'));
        $expanded = $this->expander->expand($key, MediaType::VIDEO);

        $source = Utils::streamFor(file_get_contents($this->samplesDir . '/VIDEO.original'));
        $stream = new EncryptingStream($source, $expanded);

        $memBefore = memory_get_usage();
        $stream->read(16); // single small read — must NOT load the whole file
        $memAfter = memory_get_usage();

        // Allow up to 512 KB overhead — full VIDEO file is ~380 KB so if it were
        // buffered the delta would exceed this threshold significantly.
        self::assertLessThan(512 * 1024, $memAfter - $memBefore);
    }

    // -------------------------------------------------------------------------
    // SidecarContext — finalize() idempotency
    // -------------------------------------------------------------------------

    public function testSidecarFinalizeIsIdempotent(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/VIDEO.key'));
        $expanded = $this->expander->expand($key, MediaType::VIDEO);

        $source  = Utils::streamFor(file_get_contents($this->samplesDir . '/VIDEO.original'));
        $sidecar = new SidecarContext($expanded->macKey);
        $stream  = new EncryptingStream($source, $expanded, $sidecar);

        Utils::copyToString($stream);

        $result1 = $sidecar->getSidecar();

        // Second call must be a no-op
        $sidecar->finalize();
        $result2 = $sidecar->getSidecar();

        self::assertSame($result1, $result2);
    }

    // -------------------------------------------------------------------------
    // Cbc — seek() error cases
    // -------------------------------------------------------------------------

    public function testCbcSeekThrowsOnNonZeroOffset(): void
    {
        $cbc = new Cbc(str_repeat("\x00", 16));

        $this->expectException(\LogicException::class);
        $cbc->seek(16);
    }

    public function testCbcSeekThrowsOnSeekEnd(): void
    {
        $cbc = new Cbc(str_repeat("\x00", 16));

        $this->expectException(\LogicException::class);
        $cbc->seek(0, SEEK_END);
    }

    public function testCbcSeekRewindRestoresIv(): void
    {
        $iv  = str_repeat("\xab", 16);
        $cbc = new Cbc($iv);

        // Simulate IV update after encrypting a block
        $cbc->update(str_repeat("\xff", 16));
        self::assertNotSame($iv, $cbc->getCurrentIv());

        // Rewind must restore original IV
        $cbc->seek(0, SEEK_SET);
        self::assertSame($iv, $cbc->getCurrentIv());
    }

    // -------------------------------------------------------------------------
    // DecryptingStream — round-trip with small chunk reads
    // -------------------------------------------------------------------------

    public function testDecryptWithSmallChunks(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        $encrypted = file_get_contents($this->samplesDir . '/IMAGE.encrypted');
        $source    = Utils::streamFor($encrypted);
        $stream    = new DecryptingStream($source, $expanded);

        $result = '';
        while (!$stream->eof()) {
            $result .= $stream->read(7);
        }

        self::assertSame(file_get_contents($this->samplesDir . '/IMAGE.original'), $result);
    }
}
