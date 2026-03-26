<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Vamischenko\Decorators\ExpandedKey;
use Vamischenko\Decorators\KeyExpander;
use Vamischenko\Decorators\MediaKey;
use Vamischenko\Decorators\MediaType;
use Vamischenko\Decorators\Stream\EncryptingStream;

class EncryptingStreamTest extends TestCase
{
    private KeyExpander $expander;
    private string $samplesDir;

    protected function setUp(): void
    {
        $this->expander   = new KeyExpander();
        $this->samplesDir = dirname(__DIR__) . '/samples';
    }

    public function testEncryptImageMatchesReference(): void
    {
        $this->assertEncryptedMatchesReference('IMAGE', MediaType::IMAGE);
    }

    public function testEncryptVideoMatchesReference(): void
    {
        $this->assertEncryptedMatchesReference('VIDEO', MediaType::VIDEO);
    }

    public function testEncryptAudioMatchesReference(): void
    {
        $this->assertEncryptedMatchesReference('AUDIO', MediaType::AUDIO);
    }

    public function testGetSizeReturnsCorrectValue(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        $plaintext = file_get_contents($this->samplesDir . '/IMAGE.original');
        $source    = Utils::streamFor($plaintext);
        $stream    = new EncryptingStream($source, $expanded);

        $expected = strlen(file_get_contents($this->samplesDir . '/IMAGE.encrypted'));
        self::assertSame($expected, $stream->getSize());
    }

    public function testIsNotSeekable(): void
    {
        $expanded = $this->makeExpandedKey('IMAGE', MediaType::IMAGE);
        $stream   = new EncryptingStream(Utils::streamFor(''), $expanded);

        self::assertFalse($stream->isSeekable());
    }

    public function testReadInSmallChunks(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        $plaintext = file_get_contents($this->samplesDir . '/IMAGE.original');
        $source    = Utils::streamFor($plaintext);
        $stream    = new EncryptingStream($source, $expanded);

        $result = '';
        while (!$stream->eof()) {
            $result .= $stream->read(100);
        }

        self::assertSame(file_get_contents($this->samplesDir . '/IMAGE.encrypted'), $result);
    }

    private function assertEncryptedMatchesReference(string $name, MediaType $type): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . "/{$name}.key"));
        $expanded = $this->expander->expand($key, $type);

        $plaintext = file_get_contents($this->samplesDir . "/{$name}.original");
        $source    = Utils::streamFor($plaintext);
        $stream    = new EncryptingStream($source, $expanded);

        $result    = Utils::copyToString($stream);
        $reference = file_get_contents($this->samplesDir . "/{$name}.encrypted");

        self::assertSame($reference, $result);
    }

    private function makeExpandedKey(string $name, MediaType $type): ExpandedKey
    {
        $key = MediaKey::fromBinary(file_get_contents($this->samplesDir . "/{$name}.key"));
        return $this->expander->expand($key, $type);
    }
}
