<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Vamischenko\Decorators\KeyExpander;
use Vamischenko\Decorators\MediaKey;
use Vamischenko\Decorators\MediaType;
use Vamischenko\Decorators\Sidecar\SidecarContext;
use Vamischenko\Decorators\Stream\EncryptingStream;

class SidecarTest extends TestCase
{
    private KeyExpander $expander;
    private string $samplesDir;

    protected function setUp(): void
    {
        $this->expander   = new KeyExpander();
        $this->samplesDir = dirname(__DIR__) . '/samples';
    }

    public function testVideoSidecarMatchesReference(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/VIDEO.key'));
        $expanded = $this->expander->expand($key, MediaType::VIDEO);

        $plaintext = file_get_contents($this->samplesDir . '/VIDEO.original');
        $source    = Utils::streamFor($plaintext);
        $sidecar   = new SidecarContext($expanded->macKey);
        $stream    = new EncryptingStream($source, $expanded, $sidecar);

        // Consume the stream — sidecar is built as bytes are read
        Utils::copyToString($stream);

        $reference = file_get_contents($this->samplesDir . '/VIDEO.sidecar');
        self::assertSame($reference, $sidecar->getSidecar());
    }

    public function testSidecarIsEmptyBeforeStreamIsRead(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/VIDEO.key'));
        $expanded = $this->expander->expand($key, MediaType::VIDEO);

        $sidecar = new SidecarContext($expanded->macKey);
        self::assertSame('', $sidecar->getSidecar());
    }

    public function testSidecarLengthIsMultipleOfTenBytes(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/VIDEO.key'));
        $expanded = $this->expander->expand($key, MediaType::VIDEO);

        $plaintext = file_get_contents($this->samplesDir . '/VIDEO.original');
        $source    = Utils::streamFor($plaintext);
        $sidecar   = new SidecarContext($expanded->macKey);
        $stream    = new EncryptingStream($source, $expanded, $sidecar);

        Utils::copyToString($stream);

        self::assertSame(0, strlen($sidecar->getSidecar()) % 10);
    }

    public function testEncryptingStreamWithoutSidecarStillWorks(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        $plaintext = file_get_contents($this->samplesDir . '/IMAGE.original');
        $source    = Utils::streamFor($plaintext);
        $stream    = new EncryptingStream($source, $expanded); // no sidecar

        $result    = Utils::copyToString($stream);
        $reference = file_get_contents($this->samplesDir . '/IMAGE.encrypted');

        self::assertSame($reference, $result);
    }
}
