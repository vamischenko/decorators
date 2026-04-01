# Changelog

## [1.2.0] — 2026-04-01

### Added

- `AesDecryptingStream` — потоковая дешифровка AES-256-CBC блок за блоком (без буферизации всего plaintext)

### Changed

- `DecryptingStream` переписан для истинного потокового декодирования:
  - Seekable-источник: MAC читается через seek, ciphertext верифицируется через `HashingStream`, затем инкрементальная дешифровка через `AesDecryptingStream` — O(блок) памяти
  - Non-seekable источник: ciphertext буферизуется (MAC в хвосте — иначе никак), но после верификации plaintext раздаётся потоково через `AesDecryptingStream` без второй полной копии

## [1.1.2] — 2026-03-26

### Added

- GitHub Actions CI: запуск тестов на PHP 8.1, 8.2, 8.3 при push/pull request в `main`

## [1.1.1] — 2026-03-26

### Documentation

- PHPDoc комментарии ко всем классам: описания классов, `@param`, `@return`, `@throws` для публичных методов

## [1.1.0] — 2026-03-26

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
