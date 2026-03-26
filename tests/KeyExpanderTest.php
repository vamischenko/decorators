<?php

declare(strict_types=1);

namespace Vamischenko\Decorators\Tests;

use PHPUnit\Framework\TestCase;
use Vamischenko\Decorators\KeyExpander;
use Vamischenko\Decorators\MediaKey;
use Vamischenko\Decorators\MediaType;

class KeyExpanderTest extends TestCase
{
    private KeyExpander $expander;
    private string $samplesDir;

    protected function setUp(): void
    {
        $this->expander   = new KeyExpander();
        $this->samplesDir = dirname(__DIR__) . '/samples';
    }

    public function testExpandImageKey(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/IMAGE.key'));
        $expanded = $this->expander->expand($key, MediaType::IMAGE);

        self::assertSame(16, strlen($expanded->iv));
        self::assertSame(32, strlen($expanded->cipherKey));
        self::assertSame(32, strlen($expanded->macKey));
        self::assertSame(32, strlen($expanded->refKey));

        // Verify correctness: encrypt with derived key and compare to reference
        $plaintext  = file_get_contents($this->samplesDir . '/IMAGE.original');
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $expanded->cipherKey, OPENSSL_RAW_DATA, $expanded->iv);
        $mac        = substr(hash_hmac('sha256', $expanded->iv . $ciphertext, $expanded->macKey, true), 0, 10);
        $encrypted  = $ciphertext . $mac;

        self::assertSame(file_get_contents($this->samplesDir . '/IMAGE.encrypted'), $encrypted);
    }

    public function testExpandVideoKey(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/VIDEO.key'));
        $expanded = $this->expander->expand($key, MediaType::VIDEO);

        $plaintext  = file_get_contents($this->samplesDir . '/VIDEO.original');
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $expanded->cipherKey, OPENSSL_RAW_DATA, $expanded->iv);
        $mac        = substr(hash_hmac('sha256', $expanded->iv . $ciphertext, $expanded->macKey, true), 0, 10);
        $encrypted  = $ciphertext . $mac;

        self::assertSame(file_get_contents($this->samplesDir . '/VIDEO.encrypted'), $encrypted);
    }

    public function testExpandAudioKey(): void
    {
        $key      = MediaKey::fromBinary(file_get_contents($this->samplesDir . '/AUDIO.key'));
        $expanded = $this->expander->expand($key, MediaType::AUDIO);

        $plaintext  = file_get_contents($this->samplesDir . '/AUDIO.original');
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $expanded->cipherKey, OPENSSL_RAW_DATA, $expanded->iv);
        $mac        = substr(hash_hmac('sha256', $expanded->iv . $ciphertext, $expanded->macKey, true), 0, 10);
        $encrypted  = $ciphertext . $mac;

        self::assertSame(file_get_contents($this->samplesDir . '/AUDIO.encrypted'), $encrypted);
    }

    public function testMediaKeyRejectsWrongLength(): void
    {
        $this->expectException(\Vamischenko\Decorators\Exception\InvalidMediaKeyException::class);
        MediaKey::fromBinary('tooshort');
    }

    public function testMediaKeyGenerateIsThirtyTwoBytes(): void
    {
        $key = MediaKey::generate();
        self::assertSame(32, strlen($key->bytes()));
    }

    public function testMediaTypeSupportsSidecar(): void
    {
        self::assertTrue(MediaType::VIDEO->supportsSidecar());
        self::assertTrue(MediaType::AUDIO->supportsSidecar());
        self::assertFalse(MediaType::IMAGE->supportsSidecar());
        self::assertFalse(MediaType::DOCUMENT->supportsSidecar());
    }
}
