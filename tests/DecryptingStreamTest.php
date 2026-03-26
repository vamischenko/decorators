<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Vamischenko\Decorators\Exception\MacVerificationException;
use Vamischenko\Decorators\KeyExpander;
use Vamischenko\Decorators\MediaKey;
use Vamischenko\Decorators\MediaType;
use Vamischenko\Decorators\Stream\DecryptingStream;

class DecryptingStreamTest extends TestCase
{
    private KeyExpander $expander;
    private string $samplesDir;

    protected function setUp(): void
    {
        $this->expander   = new KeyExpander();
        $this->samplesDir = dirname(__DIR__) . '/samples';
    }

    public function testDecryptImageMatchesOriginal(): void
    {
        $this->assertDecryptedMatchesOriginal('IMAGE', MediaType::IMAGE);
    }

    public function testDecryptVideoMatchesOriginal(): void
    {
        $this->assertDecryptedMatchesOriginal('VIDEO', MediaType::VIDEO);
    }

    public function testDecryptAudioMatchesOriginal(): void
    {
        $this->assertDecryptedMatchesOriginal('AUDIO', MediaType::AUDIO);
    }

    public function testTamperedMacThrowsMacVerificationException(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        $encrypted = file_get_contents($this->samplesDir . '/IMAGE.encrypted');
        // Flip one byte in the MAC (last 10 bytes)
        $tampered  = substr($encrypted, 0, -10) . chr(ord($encrypted[-1]) ^ 0xff) . substr($encrypted, -9);

        $source = Utils::streamFor($tampered);
        $stream = new DecryptingStream($source, $expanded);

        $this->expectException(MacVerificationException::class);
        $stream->read(1);
    }

    public function testTamperedCiphertextThrowsMacVerificationException(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        $encrypted = file_get_contents($this->samplesDir . '/IMAGE.encrypted');
        // Flip one byte in the middle of the ciphertext
        $tampered  = substr($encrypted, 0, 100) . chr(ord($encrypted[100]) ^ 0x01) . substr($encrypted, 101);

        $source = Utils::streamFor($tampered);
        $stream = new DecryptingStream($source, $expanded);

        $this->expectException(MacVerificationException::class);
        $stream->read(1);
    }

    public function testIsNotSeekable(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);
        $stream   = new DecryptingStream(Utils::streamFor(''), $expanded);

        self::assertFalse($stream->isSeekable());
    }

    public function testGetSizeReturnsNull(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);
        $stream   = new DecryptingStream(Utils::streamFor(''), $expanded);

        self::assertNull($stream->getSize());
    }

    private function assertDecryptedMatchesOriginal(string $name, MediaType $type): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . "/{$name}.key"));
        $expanded = $this->expander->expand($key, $type);

        $encrypted = file_get_contents($this->samplesDir . "/{$name}.encrypted");
        $source    = Utils::streamFor($encrypted);
        $stream    = new DecryptingStream($source, $expanded);

        $result   = Utils::copyToString($stream);
        $original = file_get_contents($this->samplesDir . "/{$name}.original");

        self::assertSame($original, $result);
    }
}
