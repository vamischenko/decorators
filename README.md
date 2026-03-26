# WhatsApp Media Crypto

PSR-7 stream decorators for encrypting and decrypting WhatsApp media files using the WhatsApp AES-256-CBC algorithm.

## Requirements

- PHP 8.1+
- ext-openssl
- ext-hash

## Installation

```bash
composer require vamischenko/decorators
```

## Algorithm

Encryption uses:
1. HKDF with SHA-256 to expand the 32-byte `mediaKey` to 112 bytes
2. Split into `iv` (16), `cipherKey` (32), `macKey` (32), `refKey` (32)
3. AES-256-CBC encryption with PKCS7 padding
4. HMAC-SHA256 over `iv + ciphertext`, truncated to 10 bytes, appended to output

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

// Read the encrypted stream and upload it
file_put_contents('photo.jpg.enc', (string) $stream);

// For streamable media, get the sidecar after reading the full stream
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

## Running tests

```bash
composer install
vendor/bin/phpunit
```

## Sidecar

The sidecar enables random-offset decryption for VIDEO and AUDIO streams (seeking without full download). It is generated automatically during encryption — no additional reads from the source stream are performed.

Each 10-byte sidecar entry is the HMAC-SHA256 of the `[n*64K, (n+1)*64K+16]` slice of the combined `iv + ciphertext + mac` buffer, truncated to 10 bytes.
