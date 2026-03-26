# Changelog

## [1.1.2] — 2026-03-26

- add CI unit tests

## [1.1.1] — 2026-03-26

- some fixes

## [1.1.0] — 2026-03-26

### Documentation

- PHPDoc комментарии ко всем классам: описания классов, `@param`, `@return`, `@throws` для публичных методов

### Added
- `EncryptingStream` — PSR-7 stream decorator for WhatsApp AES-256-CBC encryption
- `DecryptingStream` — PSR-7 stream decorator for WhatsApp AES-256-CBC decryption
- `SidecarContext` — sidecar generation for seekable VIDEO/AUDIO streaming
- `MediaType` — enum with HKDF info strings for IMAGE, VIDEO, AUDIO, DOCUMENT
- `MediaKey` — value object enforcing 32-byte key constraint
- `KeyExpander` — HKDF SHA-256 key expansion (RFC 5869)
- `AesEncryptingStream`, `HashingStream`, `Cbc` — low-level stream primitives adapted from jeskew/php-encrypted-streams (Apache 2.0)

### Security
- HMAC-SHA256 with constant-time `hash_equals()` comparison to prevent timing attacks
- MAC is verified before any plaintext bytes are returned (integrity-first decryption)
- HKDF key expansion follows RFC 5869 with empty salt (= HashLen zero bytes)
