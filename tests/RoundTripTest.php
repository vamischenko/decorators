<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Vamischenko\Decorators\KeyExpander;
use Vamischenko\Decorators\MediaKey;
use Vamischenko\Decorators\MediaType;
use Vamischenko\Decorators\Stream\DecryptingStream;
use Vamischenko\Decorators\Stream\EncryptingStream;

class RoundTripTest extends TestCase
{
    private KeyExpander $expander;

    protected function setUp(): void
    {
        $this->expander = new KeyExpander();
    }

    /**
     * @dataProvider mediaTypeProvider
     */
    public function testEncryptThenDecryptReturnsOriginal(MediaType $type): void
    {
        $original = 'Hello, WhatsApp! ' . str_repeat('x', 1000);
        $key      = MediaKey::generate();
        $expanded = $this->expander->expand($key, $type);

        $encryptedStream = new EncryptingStream(Utils::streamFor($original), $expanded);
        $encryptedBytes  = Utils::copyToString($encryptedStream);

        $decryptedStream = new DecryptingStream(Utils::streamFor($encryptedBytes), $expanded);
        $decrypted       = Utils::copyToString($decryptedStream);

        self::assertSame($original, $decrypted);
    }

    public function testEncryptThenDecryptEmptyStream(): void
    {
        $key      = MediaKey::generate();
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        $encryptedStream = new EncryptingStream(Utils::streamFor(''), $expanded);
        $encryptedBytes  = Utils::copyToString($encryptedStream);

        $decryptedStream = new DecryptingStream(Utils::streamFor($encryptedBytes), $expanded);
        $decrypted       = Utils::copyToString($decryptedStream);

        self::assertSame('', $decrypted);
    }

    public function testEncryptThenDecryptSingleByte(): void
    {
        $key      = MediaKey::generate();
        $expanded = $this->expander->expand($key, MediaType::AUDIO);

        $encryptedStream = new EncryptingStream(Utils::streamFor('X'), $expanded);
        $encryptedBytes  = Utils::copyToString($encryptedStream);

        $decryptedStream = new DecryptingStream(Utils::streamFor($encryptedBytes), $expanded);
        $decrypted       = Utils::copyToString($decryptedStream);

        self::assertSame('X', $decrypted);
    }

    public function testEncryptThenDecryptExactBlockBoundary(): void
    {
        // 16 bytes = exactly one AES block, triggers a full padding block
        $original = str_repeat('A', 16);
        $key      = MediaKey::generate();
        $expanded = $this->expander->expand($key, MediaType::DOCUMENT);

        $encryptedStream = new EncryptingStream(Utils::streamFor($original), $expanded);
        $encryptedBytes  = Utils::copyToString($encryptedStream);

        $decryptedStream = new DecryptingStream(Utils::streamFor($encryptedBytes), $expanded);
        $decrypted       = Utils::copyToString($decryptedStream);

        self::assertSame($original, $decrypted);
    }

    public static function mediaTypeProvider(): array
    {
        return [
            'IMAGE'    => [MediaType::IMAGE],
            'VIDEO'    => [MediaType::VIDEO],
            'AUDIO'    => [MediaType::AUDIO],
            'DOCUMENT' => [MediaType::DOCUMENT],
        ];
    }
}
