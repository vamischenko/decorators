# vamischenko/decorators

PSR-7 stream decorators for encrypting and decrypting WhatsApp media files using the WhatsApp AES-256-CBC algorithm.

## Requirements

- PHP 8.1+
- ext-openssl
- ext-hash
- guzzlehttp/psr7 ^2.0

## Installation

```bash
composer require vamischenko/decorators
```

## Architecture

The encryption pipeline is built from composable PSR-7 stream decorators, inspired by [jeskew/php-encrypted-streams](https://github.com/jeskew/php-encrypted-streams) (Apache 2.0). Since that package requires `guzzlehttp/psr7 ~1.0` and is no longer maintained, its core classes were adapted and included directly.

```text
source
  → AesEncryptingStream   (AES-256-CBC, cipherKey, iv)
  → AppendStream([iv, ciphertext])   ← iv prepended so HMAC covers it
  → HashingStream                    (HMAC-SHA256, macKey)
```

Encryption is **true streaming** — no full-file buffering. Data is processed block by block as the stream is read.

## Algorithm

1. Expand the 32-byte `mediaKey` to 112 bytes using HKDF with SHA-256 (RFC 5869)
2. Split into `iv` (16 bytes), `cipherKey` (32), `macKey` (32), `refKey` (32)
3. Encrypt with AES-256-CBC + PKCS7 padding
4. Compute HMAC-SHA256 over `iv + ciphertext`, truncate to 10 bytes
5. Output: `[ciphertext][mac]`

Media-type-specific HKDF info strings:

| Type     | Info string              |
|----------|--------------------------|
| IMAGE    | `WhatsApp Image Keys`    |
| VIDEO    | `WhatsApp Video Keys`    |
| AUDIO    | `WhatsApp Audio Keys`    |
| DOCUMENT | `WhatsApp Document Keys` |

## Usage

### Encryption

```php
use GuzzleHttp\Psr7\Utils;
use Vamischenko\Decorators\KeyExpander;
use Vamischenko\Decorators\MediaKey;
use Vamischenko\Decorators\MediaType;
use Vamischenko\Decorators\Sidecar\SidecarContext;
use Vamischenko\Decorators\Stream\EncryptingStream;

$mediaKey = MediaKey::generate(); // or MediaKey::fromBinary($existingKey)
$expanded = (new KeyExpander())->expand($mediaKey, MediaType::IMAGE);

$source  = Utils::streamFor(fopen('photo.jpg', 'rb'));
$sidecar = new SidecarContext($expanded->macKey); // optional, for VIDEO/AUDIO
$stream  = new EncryptingStream($source, $expanded, $sidecar);

// Read the encrypted stream — data is processed incrementally, not buffered
file_put_contents('photo.jpg.enc', (string) $stream);

// For streamable media, retrieve the sidecar after reading the full stream
$sidecarBytes = $sidecar->getSidecar();
```

### Decryption

```php
use GuzzleHttp\Psr7\Utils;
use Vamischenko\Decorators\KeyExpander;
use Vamischenko\Decorators\MediaKey;
use Vamischenko\Decorators\MediaType;
use Vamischenko\Decorators\Stream\DecryptingStream;

$mediaKey = MediaKey::fromBinary($keyBytes);
$expanded = (new KeyExpander())->expand($mediaKey, MediaType::IMAGE);

$source = Utils::streamFor(fopen('photo.jpg.enc', 'rb'));
$stream = new DecryptingStream($source, $expanded);

// MAC is verified before any bytes are returned
$plaintext = (string) $stream;
```

### Exceptions

- `InvalidMediaKeyException` — thrown when the key is not exactly 32 bytes
- `MacVerificationException` — thrown when the HMAC does not match (corrupt or tampered data)

## Security

- MAC verification uses **constant-time** `hash_equals()` to prevent timing attacks
- Integrity is verified **before** any plaintext is returned
- Key derivation follows RFC 5869 (HKDF) with WhatsApp-specific info strings

## Memory behaviour

| Stream type         | Encryption                    | Decryption                                                                                      |
|---------------------|-------------------------------|-------------------------------------------------------------------------------------------------|
| Seekable (file)     | Incremental — O(block) memory | Full plaintext buffered after decryption                                                        |
| Non-seekable (HTTP) | Incremental — O(block) memory | **Full ciphertext buffered** (MAC is at the tail, verification is mandatory before decryption)  |

For large non-seekable streams wrap the response body in a temporary file before decrypting.

## Sidecar

The sidecar enables random-offset decryption for VIDEO and AUDIO streams, allowing players to seek without downloading the full file.

It is generated during encryption with **no additional reads** from the source stream. Each 10-byte entry is the HMAC-SHA256 of the `[n*64K, (n+1)*64K+16]` slice of the logical combined buffer `iv + ciphertext + mac`, truncated to 10 bytes.

## Running tests

```bash
composer install
vendor/bin/phpunit
```
